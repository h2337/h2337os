#include "ramdisk.h"
#include "block.h"
#include "console.h"
#include "fat32.h"
#include "libc.h"
#include "limine_requests.h"
#include "vfs.h"
#include <limine.h>

static uint8_t *ramdisk_data = NULL;
static uint64_t ramdisk_size = 0;

void ramdisk_init(void) {
  kprint("Initializing storage...\n");

  size_t devices = block_device_count();
  if (devices > 0) {
    // First try partitions so we avoid mounting raw disks with partition tables
    for (size_t i = 0; i < devices; i++) {
      block_device_t *dev = block_device_get(i);
      if (!dev || dev->type != BLOCK_DEVICE_PARTITION) {
        continue;
      }

      vfs_node_t *root = fat32_mount_block_device(dev, 0);
      if (root) {
        vfs_set_root(root);
        kprint("Mounted block device \"");
        kprint(dev->name);
        kprint("\" as root filesystem\n");
        return;
      }
    }

    // Fall back to scanning whole disks (for super-floppy style images)
    for (size_t i = 0; i < devices; i++) {
      block_device_t *dev = block_device_get(i);
      if (!dev || dev->type != BLOCK_DEVICE_DISK) {
        continue;
      }

      vfs_node_t *root = fat32_mount_block_device(dev, 0);
      if (root) {
        vfs_set_root(root);
        kprint("Mounted block device \"");
        kprint(dev->name);
        kprint("\" as root filesystem\n");
        return;
      }
    }
  }

  kprint("No suitable block device found, falling back to ramdisk...\n");

  if (module_request.response == NULL ||
      module_request.response->module_count == 0) {
    kprint("No modules loaded\n");
    return;
  }

  struct limine_file *rootfs_module = module_request.response->modules[0];
  ramdisk_data = (uint8_t *)rootfs_module->address;
  ramdisk_size = rootfs_module->size;

  kprint("Found ramdisk module (");
  char size_str[32];
  uint64_t kb = ramdisk_size / 1024;
  int i = 0;
  if (kb == 0) {
    size_str[i++] = '0';
  } else {
    char tmp[32];
    int j = 0;
    while (kb > 0) {
      tmp[j++] = '0' + (kb % 10);
      kb /= 10;
    }
    while (j > 0) {
      size_str[i++] = tmp[--j];
    }
  }
  size_str[i] = '\0';
  kprint(size_str);
  kprint(" KB)\n");

  vfs_node_t *root = fat32_mount_ramdisk(ramdisk_data, ramdisk_size);
  if (root) {
    vfs_set_root(root);
    kprint("Ramdisk mounted as root filesystem\n");
  } else {
    kprint("Failed to mount ramdisk\n");
  }
}

uint8_t *ramdisk_get_data(void) { return ramdisk_data; }

uint64_t ramdisk_get_size(void) { return ramdisk_size; }
