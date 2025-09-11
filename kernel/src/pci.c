#include "pci.h"
#include "console.h"
#include "libc.h"
#include <stdint.h>

// I/O port access functions
static inline void outl(uint16_t port, uint32_t value) {
  asm volatile("outl %0, %1" : : "a"(value), "Nd"(port));
}

static inline uint32_t inl(uint16_t port) {
  uint32_t value;
  asm volatile("inl %1, %0" : "=a"(value) : "Nd"(port));
  return value;
}

static inline void outb(uint16_t port, uint8_t value) {
  asm volatile("outb %0, %1" : : "a"(value), "Nd"(port));
}

static inline uint8_t inb(uint16_t port) {
  uint8_t value;
  asm volatile("inb %1, %0" : "=a"(value) : "Nd"(port));
  return value;
}

// Store discovered PCI devices
static pci_device_t pci_devices[MAX_PCI_DEVICES];
static int pci_device_count = 0;

// PCI configuration space access
uint32_t pci_config_read_dword(uint8_t bus, uint8_t device, uint8_t function,
                               uint8_t offset) {
  uint32_t address = PCI_CONFIG_ENABLE | ((uint32_t)bus << 16) |
                     ((uint32_t)device << 11) | ((uint32_t)function << 8) |
                     (offset & 0xFC);

  outl(PCI_CONFIG_ADDRESS, address);
  return inl(PCI_CONFIG_DATA);
}

uint16_t pci_config_read_word(uint8_t bus, uint8_t device, uint8_t function,
                              uint8_t offset) {
  uint32_t dword = pci_config_read_dword(bus, device, function, offset & ~0x3);
  return (uint16_t)((dword >> ((offset & 0x2) * 8)) & 0xFFFF);
}

uint8_t pci_config_read_byte(uint8_t bus, uint8_t device, uint8_t function,
                             uint8_t offset) {
  uint32_t dword = pci_config_read_dword(bus, device, function, offset & ~0x3);
  return (uint8_t)((dword >> ((offset & 0x3) * 8)) & 0xFF);
}

void pci_config_write_dword(uint8_t bus, uint8_t device, uint8_t function,
                            uint8_t offset, uint32_t value) {
  uint32_t address = PCI_CONFIG_ENABLE | ((uint32_t)bus << 16) |
                     ((uint32_t)device << 11) | ((uint32_t)function << 8) |
                     (offset & 0xFC);

  outl(PCI_CONFIG_ADDRESS, address);
  outl(PCI_CONFIG_DATA, value);
}

void pci_config_write_word(uint8_t bus, uint8_t device, uint8_t function,
                           uint8_t offset, uint16_t value) {
  uint32_t dword = pci_config_read_dword(bus, device, function, offset & ~0x3);
  uint32_t shift = (offset & 0x2) * 8;
  dword = (dword & ~(0xFFFF << shift)) | ((uint32_t)value << shift);
  pci_config_write_dword(bus, device, function, offset & ~0x3, dword);
}

void pci_config_write_byte(uint8_t bus, uint8_t device, uint8_t function,
                           uint8_t offset, uint8_t value) {
  uint32_t dword = pci_config_read_dword(bus, device, function, offset & ~0x3);
  uint32_t shift = (offset & 0x3) * 8;
  dword = (dword & ~(0xFF << shift)) | ((uint32_t)value << shift);
  pci_config_write_dword(bus, device, function, offset & ~0x3, dword);
}

// Check if a device exists
static int pci_device_exists(uint8_t bus, uint8_t device, uint8_t function) {
  uint16_t vendor_id = pci_config_read_word(bus, device, function, 0x00);
  return vendor_id != 0xFFFF;
}

// Scan a specific device
static void pci_scan_device(uint8_t bus, uint8_t device) {
  uint8_t function = 0;

  if (!pci_device_exists(bus, device, 0)) {
    return;
  }

  // Check if this is a multifunction device
  uint8_t header_type = pci_config_read_byte(bus, device, 0, PCI_HEADER_TYPE);
  uint8_t num_functions = (header_type & PCI_MULTIFUNCTION) ? 8 : 1;

  for (function = 0; function < num_functions; function++) {
    if (!pci_device_exists(bus, device, function)) {
      continue;
    }

    if (pci_device_count >= MAX_PCI_DEVICES) {
      kprint("PCI: Maximum device limit reached\n");
      return;
    }

    // Read device information
    pci_device_t *dev = &pci_devices[pci_device_count];
    dev->bus = bus;
    dev->device = device;
    dev->function = function;

    // Read vendor and device IDs
    uint32_t id = pci_config_read_dword(bus, device, function, 0x00);
    dev->vendor_id = id & 0xFFFF;
    dev->device_id = (id >> 16) & 0xFFFF;

    // Read class information
    uint32_t class_info = pci_config_read_dword(bus, device, function, 0x08);
    dev->revision_id = class_info & 0xFF;
    dev->prog_if = (class_info >> 8) & 0xFF;
    dev->subclass_code = (class_info >> 16) & 0xFF;
    dev->class_code = (class_info >> 24) & 0xFF;

    // Read header type
    dev->header_type =
        pci_config_read_byte(bus, device, function, PCI_HEADER_TYPE) & 0x7F;

    // Read BARs (Base Address Registers) for standard devices
    if (dev->header_type == 0x00) {
      for (int bar = 0; bar < 6; bar++) {
        dev->bar[bar] =
            pci_config_read_dword(bus, device, function, 0x10 + bar * 4);
      }

      // Read interrupt information
      dev->interrupt_line = pci_config_read_byte(bus, device, function, 0x3C);
      dev->interrupt_pin = pci_config_read_byte(bus, device, function, 0x3D);
    }

    pci_device_count++;
  }
}

// Scan all PCI buses
void pci_scan_bus(void) {
  pci_device_count = 0;

  kprint("PCI: Starting bus scan...\n");

  // Scan all buses (0-255), devices (0-31)
  for (uint16_t bus = 0; bus < 256; bus++) {
    for (uint8_t device = 0; device < 32; device++) {
      pci_scan_device(bus, device);
    }
  }

  kprint("PCI: Found ");
  kprint_dec(pci_device_count);
  kprint(" devices\n");
}

// Get class name string
const char *pci_get_class_name(uint8_t class_code) {
  switch (class_code) {
  case PCI_CLASS_UNCLASSIFIED:
    return "Unclassified";
  case PCI_CLASS_MASS_STORAGE:
    return "Mass Storage";
  case PCI_CLASS_NETWORK:
    return "Network";
  case PCI_CLASS_DISPLAY:
    return "Display";
  case PCI_CLASS_MULTIMEDIA:
    return "Multimedia";
  case PCI_CLASS_MEMORY:
    return "Memory";
  case PCI_CLASS_BRIDGE:
    return "Bridge";
  case PCI_CLASS_SIMPLE_COMM:
    return "Simple Comm";
  case PCI_CLASS_BASE_SYSTEM:
    return "Base System";
  case PCI_CLASS_INPUT_DEVICE:
    return "Input Device";
  case PCI_CLASS_DOCKING_STATION:
    return "Docking Station";
  case PCI_CLASS_PROCESSOR:
    return "Processor";
  case PCI_CLASS_SERIAL_BUS:
    return "Serial Bus";
  case PCI_CLASS_WIRELESS:
    return "Wireless";
  case PCI_CLASS_INTELLIGENT:
    return "Intelligent I/O";
  case PCI_CLASS_SATELLITE:
    return "Satellite";
  case PCI_CLASS_ENCRYPTION:
    return "Encryption";
  case PCI_CLASS_SIGNAL_PROCESSING:
    return "Signal Processing";
  case PCI_CLASS_ACCELERATOR:
    return "Accelerator";
  case PCI_CLASS_NON_ESSENTIAL:
    return "Non-Essential";
  case PCI_CLASS_COPROCESSOR:
    return "Coprocessor";
  default:
    return "Unknown";
  }
}

// Get vendor name string (common vendors)
const char *pci_get_vendor_name(uint16_t vendor_id) {
  switch (vendor_id) {
  case 0x8086:
    return "Intel";
  case 0x1022:
    return "AMD";
  case 0x10DE:
    return "NVIDIA";
  case 0x1002:
    return "ATI/AMD";
  case 0x10EC:
    return "Realtek";
  case 0x14E4:
    return "Broadcom";
  case 0x1234:
    return "QEMU/Bochs";
  case 0x80EE:
    return "VirtualBox";
  case 0x15AD:
    return "VMware";
  case 0x1AF4:
    return "Red Hat/Virtio";
  case 0x1AB8:
    return "Parallels";
  case 0x1414:
    return "Microsoft";
  case 0x168C:
    return "Atheros";
  case 0x11AB:
    return "Marvell";
  case 0x10B7:
    return "3Com";
  case 0x1106:
    return "VIA";
  case 0x1039:
    return "SiS";
  case 0x10B9:
    return "ALi";
  case 0x1013:
    return "Cirrus Logic";
  default:
    return "Unknown";
  }
}

// List all discovered PCI devices
void pci_list_devices(void) {
  if (pci_device_count == 0) {
    kprint("No PCI devices found. Run scan first.\n");
    return;
  }

  kprint("PCI Devices:\n");
  kprint("Bus:Dev.Func  Vendor  Device  Class              Vendor Name\n");
  kprint("-------------------------------------------------------------\n");

  for (int i = 0; i < pci_device_count; i++) {
    pci_device_t *dev = &pci_devices[i];

    // Bus:Dev.Func
    if (dev->bus < 16)
      kprint("0");
    kprint_hex8(dev->bus);
    kprint(":");
    if (dev->device < 16)
      kprint("0");
    kprint_hex8(dev->device);
    kprint(".");
    kprint_hex8(dev->function);
    kprint("     ");

    // Vendor ID
    kprint_hex16(dev->vendor_id);
    kprint("   ");

    // Device ID
    kprint_hex16(dev->device_id);
    kprint("   ");

    // Class name
    const char *class_name = pci_get_class_name(dev->class_code);
    kprint(class_name);

    // Pad class name to align vendor name
    int class_len = strlen(class_name);
    for (int j = class_len; j < 18; j++) {
      kprint(" ");
    }

    // Vendor name
    kprint(pci_get_vendor_name(dev->vendor_id));

    kprint("\n");
  }
}

// Get pointer to device array
pci_device_t *pci_get_devices(int *count) {
  if (count) {
    *count = pci_device_count;
  }
  return pci_devices;
}

// Initialize PCI subsystem
void pci_init(void) {
  kprint("PCI: Initializing...\n");
  pci_scan_bus();
}