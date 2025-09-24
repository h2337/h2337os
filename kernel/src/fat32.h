#ifndef FAT32_H
#define FAT32_H

#include "block.h"
#include "vfs.h"
#include <stdint.h>

#define FAT32_SECTOR_SIZE 512
#define FAT32_MAX_FILENAME 255
#define FAT32_EOC 0x0FFFFFF8
#define FAT32_BAD_CLUSTER 0x0FFFFFF7
#define FAT32_FREE_CLUSTER 0x00000000

typedef struct __attribute__((packed)) {
  uint8_t jmp[3];
  char oem[8];
  uint16_t bytes_per_sector;
  uint8_t sectors_per_cluster;
  uint16_t reserved_sectors;
  uint8_t number_of_fats;
  uint16_t root_dir_entries;
  uint16_t total_sectors_16;
  uint8_t media_type;
  uint16_t fat_size_16;
  uint16_t sectors_per_track;
  uint16_t number_of_heads;
  uint32_t hidden_sectors;
  uint32_t total_sectors_32;

  uint32_t fat_size_32;
  uint16_t ext_flags;
  uint16_t fs_version;
  uint32_t root_cluster;
  uint16_t fs_info;
  uint16_t backup_boot_sector;
  uint8_t reserved[12];
  uint8_t drive_number;
  uint8_t reserved1;
  uint8_t boot_signature;
  uint32_t volume_id;
  char volume_label[11];
  char fs_type[8];
} fat32_bpb_t;

typedef struct __attribute__((packed)) {
  char name[11];
  uint8_t attr;
  uint8_t ntres;
  uint8_t crttime_tenth;
  uint16_t crttime;
  uint16_t crtdate;
  uint16_t lstaccdate;
  uint16_t first_cluster_hi;
  uint16_t wrttime;
  uint16_t wrtdate;
  uint16_t first_cluster_lo;
  uint32_t size;
} fat32_dir_entry_t;

typedef struct __attribute__((packed)) {
  uint8_t order;
  uint16_t name1[5];
  uint8_t attr;
  uint8_t type;
  uint8_t checksum;
  uint16_t name2[6];
  uint16_t first_cluster_lo;
  uint16_t name3[2];
} fat32_lfn_entry_t;

#define FAT32_ATTR_READ_ONLY 0x01
#define FAT32_ATTR_HIDDEN 0x02
#define FAT32_ATTR_SYSTEM 0x04
#define FAT32_ATTR_VOLUME_ID 0x08
#define FAT32_ATTR_DIRECTORY 0x10
#define FAT32_ATTR_ARCHIVE 0x20
#define FAT32_ATTR_LFN 0x0F

typedef struct fat32_fs {
  fat32_bpb_t bpb;
  uint64_t fat_start_lba;
  uint64_t data_start_lba;
  uint32_t sectors_per_cluster;
  uint32_t bytes_per_cluster;
  uint32_t total_clusters;
  uint32_t fat_sectors;
  uint32_t *fat_buffer;
  uint8_t *cluster_buffer;
  uint8_t *data_region; // RAM-based storage for clusters
  block_device_t *block;
  uint64_t partition_lba;
  uint8_t fat_count;
} fat32_fs_t;

typedef struct fat32_node {
  vfs_node_t base;
  fat32_fs_t *fs;
  uint32_t first_cluster;
  uint32_t current_cluster;
  uint32_t parent_cluster;
  uint32_t dir_entry_index;
  fat32_dir_entry_t dir_entry;
  uint8_t modified;
} fat32_node_t;

void fat32_init(void);
vfs_filesystem_t *fat32_get_filesystem(void);
vfs_node_t *fat32_mount(const char *device, const char *mountpoint);
vfs_node_t *fat32_mount_ramdisk(uint8_t *data, uint64_t size);
vfs_node_t *fat32_mount_block_device(block_device_t *device,
                                     uint64_t lba_offset);
void fat32_unmount(vfs_node_t *node);

uint32_t fat32_read(vfs_node_t *node, uint32_t offset, uint32_t size,
                    uint8_t *buffer);
uint32_t fat32_write(vfs_node_t *node, uint32_t offset, uint32_t size,
                     uint8_t *buffer);
void fat32_open(vfs_node_t *node, uint32_t flags);
void fat32_close(vfs_node_t *node);
vfs_node_t *fat32_readdir(vfs_node_t *node, uint32_t index);
vfs_node_t *fat32_finddir(vfs_node_t *node, const char *name);
int fat32_create(vfs_node_t *parent, const char *name, uint32_t type,
                 mode_t mode);
int fat32_unlink(vfs_node_t *parent, const char *name);

#endif
