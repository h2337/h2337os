#ifndef BLOCK_H
#define BLOCK_H

#include <stddef.h>
#include <stdint.h>

typedef struct block_device block_device_t;

typedef enum {
  BLOCK_DEVICE_DISK = 0,
  BLOCK_DEVICE_PARTITION = 1,
  BLOCK_DEVICE_RAMDISK = 2,
} block_device_type_t;

typedef int (*block_read_fn)(block_device_t *device, uint64_t lba,
                             uint32_t count, void *buffer);
typedef int (*block_write_fn)(block_device_t *device, uint64_t lba,
                              uint32_t count, const void *buffer);
typedef int (*block_flush_fn)(block_device_t *device);

struct block_device {
  char name[32];
  block_device_type_t type;
  uint32_t block_size;
  uint64_t block_count;
  uint64_t lba_offset;
  block_device_t *parent;
  block_read_fn driver_read;
  block_write_fn driver_write;
  block_flush_fn driver_flush;
  void *driver_data;
  struct block_device *next;
};

void block_init(void);
block_device_t *block_device_register(const char *name,
                                      block_device_type_t type,
                                      uint32_t block_size, uint64_t block_count,
                                      block_read_fn read, block_write_fn write,
                                      block_flush_fn flush, void *driver_data);
block_device_t *block_device_register_partition(block_device_t *parent,
                                                const char *name,
                                                uint64_t first_lba,
                                                uint64_t sector_count);
block_device_t *block_device_find(const char *name);
block_device_t *block_device_get(size_t index);
size_t block_device_count(void);
int block_device_read(block_device_t *device, uint64_t lba, uint32_t count,
                      void *buffer);
int block_device_write(block_device_t *device, uint64_t lba, uint32_t count,
                       const void *buffer);
int block_device_flush(block_device_t *device);
int block_device_driver_read(block_device_t *device, uint64_t lba,
                             uint32_t count, void *buffer);
int block_device_driver_write(block_device_t *device, uint64_t lba,
                              uint32_t count, const void *buffer);
void block_scan_partitions(block_device_t *device);

#endif
