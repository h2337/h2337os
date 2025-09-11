#ifndef PCI_H
#define PCI_H

#include <stdint.h>

// PCI Configuration Space Ports
#define PCI_CONFIG_ADDRESS 0xCF8
#define PCI_CONFIG_DATA 0xCFC

// PCI Config Address Register bits
#define PCI_CONFIG_ENABLE (1 << 31)

// PCI Header Type Register
#define PCI_HEADER_TYPE 0x0E
#define PCI_MULTIFUNCTION 0x80

// PCI Device Classes
#define PCI_CLASS_UNCLASSIFIED 0x00
#define PCI_CLASS_MASS_STORAGE 0x01
#define PCI_CLASS_NETWORK 0x02
#define PCI_CLASS_DISPLAY 0x03
#define PCI_CLASS_MULTIMEDIA 0x04
#define PCI_CLASS_MEMORY 0x05
#define PCI_CLASS_BRIDGE 0x06
#define PCI_CLASS_SIMPLE_COMM 0x07
#define PCI_CLASS_BASE_SYSTEM 0x08
#define PCI_CLASS_INPUT_DEVICE 0x09
#define PCI_CLASS_DOCKING_STATION 0x0A
#define PCI_CLASS_PROCESSOR 0x0B
#define PCI_CLASS_SERIAL_BUS 0x0C
#define PCI_CLASS_WIRELESS 0x0D
#define PCI_CLASS_INTELLIGENT 0x0E
#define PCI_CLASS_SATELLITE 0x0F
#define PCI_CLASS_ENCRYPTION 0x10
#define PCI_CLASS_SIGNAL_PROCESSING 0x11
#define PCI_CLASS_ACCELERATOR 0x12
#define PCI_CLASS_NON_ESSENTIAL 0x13
#define PCI_CLASS_COPROCESSOR 0x40
#define PCI_CLASS_UNASSIGNED 0xFF

// Maximum PCI devices we'll track
#define MAX_PCI_DEVICES 256

typedef struct {
  uint16_t vendor_id;
  uint16_t device_id;
  uint8_t bus;
  uint8_t device;
  uint8_t function;
  uint8_t class_code;
  uint8_t subclass_code;
  uint8_t prog_if;
  uint8_t revision_id;
  uint8_t header_type;
  uint32_t bar[6]; // Base Address Registers
  uint8_t interrupt_line;
  uint8_t interrupt_pin;
} pci_device_t;

// PCI Functions
void pci_init(void);
uint32_t pci_config_read_dword(uint8_t bus, uint8_t device, uint8_t function,
                               uint8_t offset);
uint16_t pci_config_read_word(uint8_t bus, uint8_t device, uint8_t function,
                              uint8_t offset);
uint8_t pci_config_read_byte(uint8_t bus, uint8_t device, uint8_t function,
                             uint8_t offset);
void pci_config_write_dword(uint8_t bus, uint8_t device, uint8_t function,
                            uint8_t offset, uint32_t value);
void pci_config_write_word(uint8_t bus, uint8_t device, uint8_t function,
                           uint8_t offset, uint16_t value);
void pci_config_write_byte(uint8_t bus, uint8_t device, uint8_t function,
                           uint8_t offset, uint8_t value);
void pci_scan_bus(void);
void pci_list_devices(void);
const char *pci_get_class_name(uint8_t class_code);
const char *pci_get_vendor_name(uint16_t vendor_id);
pci_device_t *pci_get_devices(int *count);

#endif