#include "block.h"
#include "console.h"
#include "heap.h"
#include "libc.h"
#include "sync.h"
#include <stdbool.h>

#define BLOCK_CACHE_ENTRIES 128
#define BLOCK_CACHE_BLOCK_SIZE 512

typedef struct {
  block_device_t *device;
  uint64_t lba;
  uint8_t data[BLOCK_CACHE_BLOCK_SIZE];
  uint64_t stamp;
  bool valid;
  bool loading;
} block_cache_entry_t;

static block_device_t *block_devices = NULL;
static size_t block_devices_count = 0;
static block_cache_entry_t block_cache[BLOCK_CACHE_ENTRIES];
static uint64_t cache_tick = 0;
static spinlock_t cache_lock = SPINLOCK_INIT("block_cache");
static spinlock_t list_lock = SPINLOCK_INIT("block_list");

static int block_device_partition_read(block_device_t *device, uint64_t lba,
                                       uint32_t count, void *buffer);
static int block_device_partition_write(block_device_t *device, uint64_t lba,
                                        uint32_t count, const void *buffer);
static int block_device_partition_flush(block_device_t *device);

static inline void cpu_relax(void) { asm volatile("pause"); }

static block_cache_entry_t *block_cache_select_victim(void) {
  block_cache_entry_t *victim = NULL;

  for (size_t i = 0; i < BLOCK_CACHE_ENTRIES; i++) {
    block_cache_entry_t *entry = &block_cache[i];
    if (entry->loading) {
      continue;
    }

    if (!entry->valid) {
      return entry;
    }

    if (!victim || !victim->valid || entry->stamp < victim->stamp) {
      victim = entry;
    }
  }

  return victim;
}

static void block_cache_store(block_device_t *device, uint64_t lba,
                              const void *data) {
  if (!device || device->block_size > BLOCK_CACHE_BLOCK_SIZE) {
    return;
  }

  spin_lock(&cache_lock);

  for (size_t i = 0; i < BLOCK_CACHE_ENTRIES; i++) {
    block_cache_entry_t *entry = &block_cache[i];
    if (entry->valid && !entry->loading && entry->device == device &&
        entry->lba == lba) {
      memcpy(entry->data, data, device->block_size);
      entry->stamp = ++cache_tick;
      spin_unlock(&cache_lock);
      return;
    }
  }

  block_cache_entry_t *victim = block_cache_select_victim();
  if (!victim) {
    spin_unlock(&cache_lock);
    return;
  }

  victim->device = device;
  victim->lba = lba;
  victim->valid = true;
  victim->loading = false;
  memcpy(victim->data, data, device->block_size);
  victim->stamp = ++cache_tick;

  spin_unlock(&cache_lock);
}

static int block_cache_fetch(block_device_t *device, uint64_t lba,
                             void *buffer) {
  if (!device || device->block_size > BLOCK_CACHE_BLOCK_SIZE) {
    return block_device_driver_read(device, lba, 1, buffer);
  }

  for (;;) {
    spin_lock(&cache_lock);

    for (size_t i = 0; i < BLOCK_CACHE_ENTRIES; i++) {
      block_cache_entry_t *entry = &block_cache[i];
      if (entry->valid && !entry->loading && entry->device == device &&
          entry->lba == lba) {
        memcpy(buffer, entry->data, device->block_size);
        entry->stamp = ++cache_tick;
        spin_unlock(&cache_lock);
        return 0;
      }

      if (entry->loading && entry->device == device && entry->lba == lba) {
        spin_unlock(&cache_lock);
        cpu_relax();
        goto fetch_retry;
      }
    }

    block_cache_entry_t *victim = block_cache_select_victim();
    if (!victim) {
      spin_unlock(&cache_lock);
      cpu_relax();
      goto fetch_retry;
    }

    victim->loading = true;
    victim->valid = false;
    victim->device = device;
    victim->lba = lba;
    spin_unlock(&cache_lock);

    int res = block_device_driver_read(device, lba, 1, victim->data);

    spin_lock(&cache_lock);
    victim->loading = false;
    if (res == 0) {
      victim->valid = true;
      victim->stamp = ++cache_tick;
      memcpy(buffer, victim->data, device->block_size);
    }
    spin_unlock(&cache_lock);
    return res;

  fetch_retry:
    continue;
  }
}

static void append_number(char *dest, size_t value) {
  char tmp[16];
  size_t index = 0;
  if (value == 0) {
    tmp[index++] = '0';
  } else {
    while (value > 0 && index < sizeof(tmp)) {
      tmp[index++] = '0' + (value % 10);
      value /= 10;
    }
  }
  for (size_t i = 0; i < index; i++) {
    dest[i] = tmp[index - i - 1];
  }
  dest[index] = '\0';
}

void block_init(void) {
  spin_lock(&list_lock);
  block_devices = NULL;
  block_devices_count = 0;
  spin_unlock(&list_lock);

  spin_lock(&cache_lock);
  memset(block_cache, 0, sizeof(block_cache));
  cache_tick = 0;
  spin_unlock(&cache_lock);
}

block_device_t *block_device_register(const char *name,
                                      block_device_type_t type,
                                      uint32_t block_size, uint64_t block_count,
                                      block_read_fn read, block_write_fn write,
                                      block_flush_fn flush, void *driver_data) {
  if (!name || block_size == 0 || block_count == 0) {
    return NULL;
  }

  block_device_t *device = kmalloc(sizeof(block_device_t));
  if (!device) {
    return NULL;
  }

  memset(device, 0, sizeof(block_device_t));
  strncpy(device->name, name, sizeof(device->name) - 1);
  device->type = type;
  device->block_size = block_size;
  device->block_count = block_count;
  device->driver_read = read;
  device->driver_write = write;
  device->driver_flush = flush;
  device->driver_data = driver_data;
  device->parent = NULL;
  device->lba_offset = 0;
  device->next = NULL;

  spin_lock(&list_lock);
  device->next = block_devices;
  block_devices = device;
  block_devices_count++;
  spin_unlock(&list_lock);

  kprint("Block: registered device \"");
  kprint(device->name);
  kprint("\" size=0x");
  kprint_hex((uint64_t)block_size * block_count);
  kprint(" bytes\n");

  return device;
}

block_device_t *block_device_register_partition(block_device_t *parent,
                                                const char *name,
                                                uint64_t first_lba,
                                                uint64_t sector_count) {
  if (!parent || sector_count == 0) {
    return NULL;
  }

  block_read_fn read = parent->driver_read ? block_device_partition_read : NULL;
  block_write_fn write =
      parent->driver_write ? block_device_partition_write : NULL;
  block_flush_fn flush =
      parent->driver_flush ? block_device_partition_flush : NULL;

  block_device_t *device = block_device_register(
      name ? name : "partition", BLOCK_DEVICE_PARTITION, parent->block_size,
      sector_count, read, write, flush, parent);

  if (!device) {
    return NULL;
  }

  device->parent = parent;
  device->lba_offset = first_lba;

  return device;
}

block_device_t *block_device_find(const char *name) {
  if (!name) {
    return NULL;
  }

  spin_lock(&list_lock);
  block_device_t *device = block_devices;
  while (device) {
    if (strcmp(device->name, name) == 0) {
      spin_unlock(&list_lock);
      return device;
    }
    device = device->next;
  }
  spin_unlock(&list_lock);
  return NULL;
}

block_device_t *block_device_get(size_t index) {
  spin_lock(&list_lock);
  block_device_t *device = block_devices;
  while (device && index > 0) {
    device = device->next;
    index--;
  }
  spin_unlock(&list_lock);
  return device;
}

size_t block_device_count(void) { return block_devices_count; }

int block_device_driver_read(block_device_t *device, uint64_t lba,
                             uint32_t count, void *buffer) {
  if (!device || !device->driver_read || !buffer || count == 0) {
    return -1;
  }
  return device->driver_read(device, lba, count, buffer);
}

int block_device_driver_write(block_device_t *device, uint64_t lba,
                              uint32_t count, const void *buffer) {
  if (!device || !device->driver_write || !buffer || count == 0) {
    return -1;
  }
  return device->driver_write(device, lba, count, buffer);
}

static int block_device_partition_read(block_device_t *device, uint64_t lba,
                                       uint32_t count, void *buffer) {
  if (!device || !device->parent) {
    return -1;
  }
  return block_device_driver_read(device->parent, lba + device->lba_offset,
                                  count, buffer);
}

static int block_device_partition_write(block_device_t *device, uint64_t lba,
                                        uint32_t count, const void *buffer) {
  if (!device || !device->parent) {
    return -1;
  }
  return block_device_driver_write(device->parent, lba + device->lba_offset,
                                   count, buffer);
}

static int block_device_partition_flush(block_device_t *device) {
  if (!device || !device->parent || !device->parent->driver_flush) {
    return 0;
  }
  return device->parent->driver_flush(device->parent);
}

int block_device_read(block_device_t *device, uint64_t lba, uint32_t count,
                      void *buffer) {
  if (!device || !buffer || count == 0) {
    return -1;
  }

  if (device->driver_read == NULL) {
    return -1;
  }

  uint8_t *dst = (uint8_t *)buffer;
  uint32_t block_size = device->block_size;

  if (device->block_size > BLOCK_CACHE_BLOCK_SIZE) {
    return block_device_driver_read(device, lba, count, buffer);
  }

  for (uint32_t i = 0; i < count; i++) {
    int res =
        block_cache_fetch(device, lba + i, dst + (uint64_t)i * block_size);
    if (res != 0) {
      return res;
    }
  }

  return 0;
}

int block_device_write(block_device_t *device, uint64_t lba, uint32_t count,
                       const void *buffer) {
  if (!device || !buffer || count == 0) {
    return -1;
  }

  if (device->driver_write == NULL) {
    return -1;
  }

  int res = block_device_driver_write(device, lba, count, buffer);
  if (res != 0) {
    return res;
  }

  if (device->block_size > BLOCK_CACHE_BLOCK_SIZE) {
    return 0;
  }

  const uint8_t *src = (const uint8_t *)buffer;
  uint32_t block_size = device->block_size;

  for (uint32_t i = 0; i < count; i++) {
    block_cache_store(device, lba + i, src + (uint64_t)i * block_size);
  }

  return 0;
}

int block_device_flush(block_device_t *device) {
  if (!device) {
    return -1;
  }

  if (device->driver_flush) {
    return device->driver_flush(device);
  }

  return 0;
}

#pragma pack(push, 1)
typedef struct {
  uint8_t status;
  uint8_t chs_first[3];
  uint8_t type;
  uint8_t chs_last[3];
  uint32_t lba_first;
  uint32_t sectors;
} mbr_partition_entry_t;

typedef struct {
  uint64_t signature;
  uint32_t revision;
  uint32_t header_size;
  uint32_t crc32;
  uint32_t reserved;
  uint64_t current_lba;
  uint64_t backup_lba;
  uint64_t first_usable_lba;
  uint64_t last_usable_lba;
  uint8_t disk_guid[16];
  uint64_t partition_entry_lba;
  uint32_t num_partition_entries;
  uint32_t partition_entry_size;
  uint32_t partition_entries_crc32;
  uint8_t reserved2[420];
} gpt_header_t;

typedef struct {
  uint8_t type_guid[16];
  uint8_t unique_guid[16];
  uint64_t first_lba;
  uint64_t last_lba;
  uint64_t attributes;
  uint16_t name[36];
} gpt_entry_t;
#pragma pack(pop)

static bool guid_is_zero(const uint8_t *guid) {
  for (int i = 0; i < 16; i++) {
    if (guid[i] != 0) {
      return false;
    }
  }
  return true;
}

static void partition_name(char *out, size_t out_size, const char *disk_name,
                           size_t index) {
  if (!out || out_size == 0) {
    return;
  }
  strncpy(out, disk_name, out_size - 1);
  out[out_size - 1] = '\0';
  size_t len = strlen(out);
  if (len < out_size - 2) {
    out[len++] = 'p';
    out[len] = '\0';
  }
  if (len < out_size - 1) {
    append_number(out + len, index);
  }
}

static void block_scan_gpt(block_device_t *device, const uint8_t *sector) {
  const gpt_header_t *header = (const gpt_header_t *)sector;
  if (header->signature != 0x5452415020494645ULL) { // "EFI PART"
    return;
  }

  uint32_t entry_size = header->partition_entry_size;
  if (entry_size == 0 || entry_size > device->block_size) {
    return;
  }

  uint32_t entries_per_sector = device->block_size / entry_size;
  if (entries_per_sector == 0) {
    return;
  }

  uint8_t *entry_sector = kmalloc(device->block_size);
  if (!entry_sector) {
    return;
  }

  size_t part_index = 1;
  for (uint32_t i = 0; i < header->num_partition_entries; i++) {
    uint64_t lba = header->partition_entry_lba + (i / entries_per_sector);
    uint32_t offset = (i % entries_per_sector) * entry_size;

    if (offset == 0) {
      if (block_device_driver_read(device, lba, 1, entry_sector) != 0) {
        break;
      }
    }

    gpt_entry_t *entry = (gpt_entry_t *)(entry_sector + offset);
    if (guid_is_zero(entry->type_guid) || entry->first_lba == 0 ||
        entry->last_lba < entry->first_lba) {
      continue;
    }

    char name[32];
    partition_name(name, sizeof(name), device->name, part_index++);
    block_device_t *part = block_device_register_partition(
        device, name, entry->first_lba, entry->last_lba - entry->first_lba + 1);
    (void)part;
  }

  kfree(entry_sector);
}

void block_scan_partitions(block_device_t *device) {
  if (!device || device->block_size < 512) {
    return;
  }

  uint8_t *sector = kmalloc(device->block_size);
  if (!sector) {
    return;
  }

  if (block_device_driver_read(device, 0, 1, sector) != 0) {
    kfree(sector);
    return;
  }

  if (sector[510] != 0x55 || sector[511] != 0xAA) {
    kfree(sector);
    return;
  }

  mbr_partition_entry_t *parts = (mbr_partition_entry_t *)(sector + 446);
  bool is_gpt = false;
  for (int i = 0; i < 4; i++) {
    if (parts[i].type == 0xEE) {
      is_gpt = true;
      break;
    }
  }

  if (is_gpt) {
    if (block_device_driver_read(device, 1, 1, sector) == 0) {
      block_scan_gpt(device, sector);
    }
    kfree(sector);
    return;
  }

  size_t part_index = 1;
  for (int i = 0; i < 4; i++) {
    if (parts[i].type == 0 || parts[i].sectors == 0) {
      continue;
    }

    char name[32];
    partition_name(name, sizeof(name), device->name, part_index++);
    block_device_t *part = block_device_register_partition(
        device, name, parts[i].lba_first, parts[i].sectors);
    (void)part;
  }

  kfree(sector);
}
