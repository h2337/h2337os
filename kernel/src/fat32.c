#include "fat32.h"
#include "console.h"
#include "heap.h"
#include "libc.h"
#include "vfs.h"
#include <stdbool.h>
#include <stddef.h>

// Forward declarations
static fat32_node_t *fat32_create_node_with_parent(fat32_fs_t *fs,
                                                   fat32_dir_entry_t *entry,
                                                   const char *name,
                                                   uint32_t parent_cluster,
                                                   uint32_t dir_entry_index);

static mode_t fat32_mode_from_attr(uint8_t attr, bool is_dir) {
  mode_t mode;

  if (is_dir) {
    mode = S_IFDIR | S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH |
           S_IXOTH;
  } else {
    mode = S_IFREG | S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
  }

  if (attr & FAT32_ATTR_READ_ONLY) {
    mode &= ~(S_IWUSR | S_IWGRP | S_IWOTH);
  } else if (!is_dir) {
    mode |= S_IWGRP | S_IWOTH;
  }

  return mode;
}

static vfs_filesystem_t fat32_filesystem = {.name = "fat32",
                                            .mount = fat32_mount,
                                            .unmount = fat32_unmount,
                                            .next = NULL};

static uint64_t fat32_cluster_to_lba(fat32_fs_t *fs, uint32_t cluster) {
  return fs->data_start_lba + (uint64_t)(cluster - 2) * fs->sectors_per_cluster;
}

static uint32_t fat32_get_fat_entry(fat32_fs_t *fs, uint32_t cluster) {
  if (!fs->fat_buffer) {
    return 0;
  }
  return fs->fat_buffer[cluster] & 0x0FFFFFFF;
}

static int fat32_flush_fat_entry(fat32_fs_t *fs, uint32_t cluster) {
  if (!fs->block) {
    return 0;
  }

  uint32_t bytes_per_sector = fs->bpb.bytes_per_sector;
  uint32_t fat_offset = cluster * 4;
  uint32_t sector_index = fat_offset / bytes_per_sector;
  uint32_t sector_offset = fat_offset % bytes_per_sector;
  uint32_t value = fs->fat_buffer[cluster] & 0x0FFFFFFF;
  uint8_t stack_sector[FAT32_SECTOR_SIZE];
  uint8_t *sector = stack_sector;
  bool allocated = false;

  if (bytes_per_sector > FAT32_SECTOR_SIZE) {
    sector = kmalloc(bytes_per_sector);
    if (!sector) {
      return -1;
    }
    allocated = true;
  }

  for (uint8_t copy = 0; copy < fs->fat_count; copy++) {
    uint64_t lba =
        fs->fat_start_lba + (uint64_t)copy * fs->fat_sectors + sector_index;
    if (block_device_read(fs->block, lba, 1, sector) != 0) {
      if (allocated) {
        kfree(sector);
      }
      return -1;
    }

    uint32_t *entry_ptr = (uint32_t *)(sector + sector_offset);
    *entry_ptr = (*entry_ptr & 0xF0000000) | value;

    if (block_device_write(fs->block, lba, 1, sector) != 0) {
      if (allocated) {
        kfree(sector);
      }
      return -1;
    }
  }

  if (allocated) {
    kfree(sector);
  }

  return 0;
}

static void fat32_set_fat_entry(fat32_fs_t *fs, uint32_t cluster,
                                uint32_t value) {
  if (!fs->fat_buffer) {
    return;
  }
  fs->fat_buffer[cluster] = value & 0x0FFFFFFF;
  if (fs->block) {
    if (fat32_flush_fat_entry(fs, cluster) != 0) {
      kprint("FAT32: failed to flush FAT entry\n");
    }
  }
}

static uint32_t fat32_find_free_cluster(fat32_fs_t *fs) {
  for (uint32_t i = 2; i < fs->total_clusters; i++) {
    if (fat32_get_fat_entry(fs, i) == FAT32_FREE_CLUSTER) {
      return i;
    }
  }
  return 0;
}

static int fat32_read_cluster(fat32_fs_t *fs, uint32_t cluster,
                              uint8_t *buffer) {
  if (cluster < 2 || cluster >= FAT32_EOC || cluster >= fs->total_clusters) {
    return -1;
  }

  if (fs->block) {
    uint64_t lba = fat32_cluster_to_lba(fs, cluster);
    if (block_device_read(fs->block, lba, fs->sectors_per_cluster, buffer) !=
        0) {
      return -1;
    }
    return 0;
  }

  // Copy from RAM storage
  uint32_t offset = (cluster - 2) * fs->bytes_per_cluster;
  if (fs->data_region) {
    memcpy(buffer, fs->data_region + offset, fs->bytes_per_cluster);
  } else {
    memset(buffer, 0, fs->bytes_per_cluster);
  }

  return 0;
}

static int fat32_write_cluster(fat32_fs_t *fs, uint32_t cluster,
                               uint8_t *buffer) {
  if (cluster < 2 || cluster >= FAT32_EOC || cluster >= fs->total_clusters) {
    return -1;
  }

  if (fs->block) {
    uint64_t lba = fat32_cluster_to_lba(fs, cluster);
    if (block_device_write(fs->block, lba, fs->sectors_per_cluster, buffer) !=
        0) {
      return -1;
    }
    return 0;
  }

  // Copy to RAM storage
  uint32_t offset = (cluster - 2) * fs->bytes_per_cluster;
  if (fs->data_region) {
    memcpy(fs->data_region + offset, buffer, fs->bytes_per_cluster);
  }

  return 0;
}

static void fat32_parse_filename(const char *fat_name, char *output) {
  int i, j;

  for (i = 0, j = 0; i < 8 && fat_name[i] != ' '; i++, j++) {
    output[j] = fat_name[i];
  }

  if (fat_name[8] != ' ') {
    output[j++] = '.';
    for (i = 8; i < 11 && fat_name[i] != ' '; i++, j++) {
      output[j] = fat_name[i];
    }
  }

  output[j] = '\0';

  for (i = 0; output[i]; i++) {
    if (output[i] >= 'A' && output[i] <= 'Z') {
      output[i] = output[i] - 'A' + 'a';
    }
  }
}

static void fat32_create_short_name(const char *long_name, char *short_name) {
  memset(short_name, ' ', 11);

  int i = 0, j = 0;
  int has_ext = 0;

  for (i = 0; long_name[i] && j < 8; i++) {
    if (long_name[i] == '.') {
      has_ext = 1;
      break;
    }
    if (long_name[i] != ' ') {
      short_name[j] = (long_name[i] >= 'a' && long_name[i] <= 'z')
                          ? long_name[i] - 'a' + 'A'
                          : long_name[i];
      j++;
    }
  }

  if (has_ext) {
    i++;
    j = 8;
    for (; long_name[i] && j < 11; i++) {
      if (long_name[i] != ' ') {
        short_name[j] = (long_name[i] >= 'a' && long_name[i] <= 'z')
                            ? long_name[i] - 'a' + 'A'
                            : long_name[i];
        j++;
      }
    }
  }
}

static fat32_node_t *fat32_create_node(fat32_fs_t *fs, fat32_dir_entry_t *entry,
                                       const char *name) {
  return fat32_create_node_with_parent(fs, entry, name, 0, 0);
}

static fat32_node_t *fat32_create_node_with_parent(fat32_fs_t *fs,
                                                   fat32_dir_entry_t *entry,
                                                   const char *name,
                                                   uint32_t parent_cluster,
                                                   uint32_t dir_entry_index) {
  fat32_node_t *node = kmalloc(sizeof(fat32_node_t));
  if (!node) {
    return NULL;
  }

  memset(node, 0, sizeof(fat32_node_t));

  if (name) {
    strcpy(node->base.name, name);
  } else {
    fat32_parse_filename(entry->name, node->base.name);
  }

  bool is_dir = (entry->attr & FAT32_ATTR_DIRECTORY) != 0;
  bool is_read_only = (entry->attr & FAT32_ATTR_READ_ONLY) != 0;

  node->base.type = is_dir ? VFS_DIRECTORY : VFS_FILE;
  node->base.size = entry->size;
  node->base.flags = VFS_READ;
  if (!is_read_only) {
    node->base.flags |= VFS_WRITE;
  }
  node->base.mode = fat32_mode_from_attr(entry->attr, is_dir);
  node->base.uid = 0;
  node->base.gid = 0;

  node->base.read = fat32_read;
  node->base.write = fat32_write;
  node->base.open = fat32_open;
  node->base.close = fat32_close;
  node->base.readdir = fat32_readdir;
  node->base.finddir = fat32_finddir;
  node->base.create = fat32_create;
  node->base.unlink = fat32_unlink;

  node->fs = fs;
  node->first_cluster =
      ((uint32_t)entry->first_cluster_hi << 16) | entry->first_cluster_lo;
  node->base.inode = node->first_cluster;
  node->current_cluster = node->first_cluster;
  node->parent_cluster = parent_cluster;
  node->dir_entry_index = dir_entry_index;
  node->modified = 0;
  memcpy(&node->dir_entry, entry, sizeof(fat32_dir_entry_t));

  return node;
}

uint32_t fat32_read(vfs_node_t *node, uint32_t offset, uint32_t size,
                    uint8_t *buffer) {
  fat32_node_t *fat_node = (fat32_node_t *)node;
  fat32_fs_t *fs = fat_node->fs;

  if (!fs || !buffer) {
    return 0;
  }

  if (offset >= node->size) {
    return 0;
  }

  if (offset + size > node->size) {
    size = node->size - offset;
  }

  uint32_t cluster = fat_node->first_cluster;
  uint32_t cluster_offset = offset / fs->bytes_per_cluster;
  uint32_t byte_offset = offset % fs->bytes_per_cluster;
  uint32_t bytes_read = 0;

  for (uint32_t i = 0; i < cluster_offset && cluster < FAT32_EOC; i++) {
    cluster = fat32_get_fat_entry(fs, cluster);
  }

  while (size > 0 && cluster < FAT32_EOC) {
    if (fat32_read_cluster(fs, cluster, fs->cluster_buffer) < 0) {
      break;
    }

    uint32_t to_read = fs->bytes_per_cluster - byte_offset;
    if (to_read > size) {
      to_read = size;
    }

    memcpy(buffer + bytes_read, fs->cluster_buffer + byte_offset, to_read);

    bytes_read += to_read;
    size -= to_read;
    byte_offset = 0;

    cluster = fat32_get_fat_entry(fs, cluster);
  }

  return bytes_read;
}

uint32_t fat32_write(vfs_node_t *node, uint32_t offset, uint32_t size,
                     uint8_t *buffer) {
  fat32_node_t *fat_node = (fat32_node_t *)node;
  fat32_fs_t *fs = fat_node->fs;

  if (!fs || !buffer) {
    return 0;
  }

  uint32_t cluster = fat_node->first_cluster;
  uint32_t cluster_offset = offset / fs->bytes_per_cluster;
  uint32_t byte_offset = offset % fs->bytes_per_cluster;
  uint32_t bytes_written = 0;

  if (cluster == 0) {
    cluster = fat32_find_free_cluster(fs);
    if (cluster == 0) {
      return 0;
    }
    fat_node->first_cluster = cluster;
    fat_node->current_cluster = cluster;
    fat32_set_fat_entry(fs, cluster, FAT32_EOC);
  }

  for (uint32_t i = 0; i < cluster_offset && cluster < FAT32_EOC; i++) {
    uint32_t next = fat32_get_fat_entry(fs, cluster);
    if (next >= FAT32_EOC) {
      next = fat32_find_free_cluster(fs);
      if (next == 0) {
        return bytes_written;
      }
      fat32_set_fat_entry(fs, cluster, next);
      fat32_set_fat_entry(fs, next, FAT32_EOC);
    }
    cluster = next;
  }

  while (size > 0) {
    if (cluster >= FAT32_EOC) {
      uint32_t new_cluster = fat32_find_free_cluster(fs);
      if (new_cluster == 0) {
        break;
      }
      fat32_set_fat_entry(fs, cluster, new_cluster);
      fat32_set_fat_entry(fs, new_cluster, FAT32_EOC);
      cluster = new_cluster;
    }

    uint32_t to_write = fs->bytes_per_cluster - byte_offset;
    if (to_write > size) {
      to_write = size;
    }

    if (byte_offset != 0 || to_write != fs->bytes_per_cluster) {
      fat32_read_cluster(fs, cluster, fs->cluster_buffer);
    }

    memcpy(fs->cluster_buffer + byte_offset, buffer + bytes_written, to_write);
    fat32_write_cluster(fs, cluster, fs->cluster_buffer);

    bytes_written += to_write;
    size -= to_write;
    byte_offset = 0;

    if (size > 0) {
      cluster = fat32_get_fat_entry(fs, cluster);
    }
  }

  if (offset + bytes_written > node->size) {
    node->size = offset + bytes_written;
    fat_node->dir_entry.size = node->size;
    fat_node->modified = 1;
  }

  return bytes_written;
}

void fat32_open(vfs_node_t *node, uint32_t flags) {
  (void)node;
  (void)flags;
}

void fat32_close(vfs_node_t *node) {
  fat32_node_t *fat_node = (fat32_node_t *)node;

  if (!fat_node || !fat_node->modified) {
    return;
  }

  fat32_fs_t *fs = fat_node->fs;
  if (!fs || fat_node->parent_cluster == 0) {
    return;
  }

  // Read the parent directory cluster that contains this file's entry
  if (fat32_read_cluster(fs, fat_node->parent_cluster, fs->cluster_buffer) <
      0) {
    return;
  }

  fat32_dir_entry_t *entries = (fat32_dir_entry_t *)fs->cluster_buffer;

  // Update the directory entry with the new size and cluster info
  entries[fat_node->dir_entry_index].size = fat_node->dir_entry.size;
  entries[fat_node->dir_entry_index].first_cluster_hi =
      (fat_node->first_cluster >> 16) & 0xFFFF;
  entries[fat_node->dir_entry_index].first_cluster_lo =
      fat_node->first_cluster & 0xFFFF;

  // Write the updated directory cluster back
  fat32_write_cluster(fs, fat_node->parent_cluster, fs->cluster_buffer);
  fat_node->modified = 0;
}

vfs_node_t *fat32_readdir(vfs_node_t *node, uint32_t index) {
  fat32_node_t *fat_node = (fat32_node_t *)node;
  fat32_fs_t *fs = fat_node->fs;

  if (!(node->type & VFS_DIRECTORY)) {
    return NULL;
  }

  uint32_t cluster = fat_node->first_cluster;
  uint32_t current_index = 0;

  while (cluster < FAT32_EOC) {
    if (fat32_read_cluster(fs, cluster, fs->cluster_buffer) < 0) {
      return NULL;
    }

    fat32_dir_entry_t *entries = (fat32_dir_entry_t *)fs->cluster_buffer;
    uint32_t entries_per_cluster =
        fs->bytes_per_cluster / sizeof(fat32_dir_entry_t);

    for (uint32_t i = 0; i < entries_per_cluster; i++) {
      if (entries[i].name[0] == 0x00) {
        return NULL;
      }

      if ((uint8_t)entries[i].name[0] == 0xE5) {
        continue;
      }

      if (entries[i].attr & FAT32_ATTR_LFN) {
        continue;
      }

      if (entries[i].attr & FAT32_ATTR_VOLUME_ID) {
        continue;
      }

      if (entries[i].name[0] == '.' && entries[i].name[1] == ' ') {
        continue;
      }

      if (entries[i].name[0] == '.' && entries[i].name[1] == '.' &&
          entries[i].name[2] == ' ') {
        continue;
      }

      if (current_index == index) {
        return (vfs_node_t *)fat32_create_node(fs, &entries[i], NULL);
      }

      current_index++;
    }

    cluster = fat32_get_fat_entry(fs, cluster);
  }

  return NULL;
}

vfs_node_t *fat32_finddir(vfs_node_t *node, const char *name) {
  fat32_node_t *fat_node = (fat32_node_t *)node;
  fat32_fs_t *fs = fat_node->fs;

  if (!(node->type & VFS_DIRECTORY)) {
    return NULL;
  }

  char short_name[12];
  fat32_create_short_name(name, short_name);

  uint32_t cluster = fat_node->first_cluster;

  while (cluster < FAT32_EOC) {
    if (fat32_read_cluster(fs, cluster, fs->cluster_buffer) < 0) {
      return NULL;
    }

    fat32_dir_entry_t *entries = (fat32_dir_entry_t *)fs->cluster_buffer;
    uint32_t entries_per_cluster =
        fs->bytes_per_cluster / sizeof(fat32_dir_entry_t);

    for (uint32_t i = 0; i < entries_per_cluster; i++) {
      if (entries[i].name[0] == 0x00) {
        return NULL;
      }

      if ((uint8_t)entries[i].name[0] == 0xE5) {
        continue;
      }

      if (entries[i].attr & FAT32_ATTR_LFN) {
        continue;
      }

      if (entries[i].attr & FAT32_ATTR_VOLUME_ID) {
        continue;
      }

      char entry_name[256];
      fat32_parse_filename(entries[i].name, entry_name);

      if (strcmp(entry_name, name) == 0) {
        return (vfs_node_t *)fat32_create_node_with_parent(fs, &entries[i],
                                                           name, cluster, i);
      }
    }

    cluster = fat32_get_fat_entry(fs, cluster);
  }

  return NULL;
}

int fat32_create(vfs_node_t *parent, const char *name, uint32_t type,
                 mode_t mode) {
  fat32_node_t *fat_parent = (fat32_node_t *)parent;
  fat32_fs_t *fs = fat_parent->fs;

  if (!(parent->type & VFS_DIRECTORY)) {
    return -1;
  }

  bool read_only = (mode & (S_IWUSR | S_IWGRP | S_IWOTH)) == 0;

  uint32_t new_cluster = fat32_find_free_cluster(fs);
  if (new_cluster == 0) {
    return -1;
  }

  fat32_set_fat_entry(fs, new_cluster, FAT32_EOC);

  fat32_dir_entry_t new_entry;
  memset(&new_entry, 0, sizeof(fat32_dir_entry_t));

  fat32_create_short_name(name, new_entry.name);
  new_entry.attr =
      (type == VFS_DIRECTORY) ? FAT32_ATTR_DIRECTORY : FAT32_ATTR_ARCHIVE;
  if (read_only) {
    new_entry.attr |= FAT32_ATTR_READ_ONLY;
  }
  new_entry.first_cluster_hi = (new_cluster >> 16) & 0xFFFF;
  new_entry.first_cluster_lo = new_cluster & 0xFFFF;
  new_entry.size = 0;

  uint32_t cluster = fat_parent->first_cluster;

  while (cluster < FAT32_EOC) {
    if (fat32_read_cluster(fs, cluster, fs->cluster_buffer) < 0) {
      return -1;
    }

    fat32_dir_entry_t *entries = (fat32_dir_entry_t *)fs->cluster_buffer;
    uint32_t entries_per_cluster =
        fs->bytes_per_cluster / sizeof(fat32_dir_entry_t);

    for (uint32_t i = 0; i < entries_per_cluster; i++) {
      if (entries[i].name[0] == 0x00 || (uint8_t)entries[i].name[0] == 0xE5) {
        memcpy(&entries[i], &new_entry, sizeof(fat32_dir_entry_t));
        fat32_write_cluster(fs, cluster, fs->cluster_buffer);

        if (type == VFS_DIRECTORY) {
          memset(fs->cluster_buffer, 0, fs->bytes_per_cluster);

          fat32_dir_entry_t *dir_entries =
              (fat32_dir_entry_t *)fs->cluster_buffer;

          memset(dir_entries[0].name, ' ', 11);
          dir_entries[0].name[0] = '.';
          dir_entries[0].attr = FAT32_ATTR_DIRECTORY;
          dir_entries[0].first_cluster_hi = (new_cluster >> 16) & 0xFFFF;
          dir_entries[0].first_cluster_lo = new_cluster & 0xFFFF;

          memset(dir_entries[1].name, ' ', 11);
          dir_entries[1].name[0] = '.';
          dir_entries[1].name[1] = '.';
          dir_entries[1].attr = FAT32_ATTR_DIRECTORY;
          dir_entries[1].first_cluster_hi =
              (fat_parent->first_cluster >> 16) & 0xFFFF;
          dir_entries[1].first_cluster_lo = fat_parent->first_cluster & 0xFFFF;

          fat32_write_cluster(fs, new_cluster, fs->cluster_buffer);
        }

        return 0;
      }
    }

    uint32_t next = fat32_get_fat_entry(fs, cluster);
    if (next >= FAT32_EOC) {
      uint32_t new_dir_cluster = fat32_find_free_cluster(fs);
      if (new_dir_cluster == 0) {
        return -1;
      }
      fat32_set_fat_entry(fs, cluster, new_dir_cluster);
      fat32_set_fat_entry(fs, new_dir_cluster, FAT32_EOC);

      memset(fs->cluster_buffer, 0, fs->bytes_per_cluster);
      fat32_write_cluster(fs, new_dir_cluster, fs->cluster_buffer);

      cluster = new_dir_cluster;
    } else {
      cluster = next;
    }
  }

  return -1;
}

int fat32_unlink(vfs_node_t *parent, const char *name) {
  fat32_node_t *fat_parent = (fat32_node_t *)parent;
  fat32_fs_t *fs = fat_parent->fs;

  if (!(parent->type & VFS_DIRECTORY)) {
    return -1;
  }

  uint32_t cluster = fat_parent->first_cluster;

  while (cluster < FAT32_EOC) {
    if (fat32_read_cluster(fs, cluster, fs->cluster_buffer) < 0) {
      return -1;
    }

    fat32_dir_entry_t *entries = (fat32_dir_entry_t *)fs->cluster_buffer;
    uint32_t entries_per_cluster =
        fs->bytes_per_cluster / sizeof(fat32_dir_entry_t);

    for (uint32_t i = 0; i < entries_per_cluster; i++) {
      if (entries[i].name[0] == 0x00) {
        return -1;
      }

      if ((uint8_t)entries[i].name[0] == 0xE5) {
        continue;
      }

      char entry_name[256];
      fat32_parse_filename(entries[i].name, entry_name);

      if (strcmp(entry_name, name) == 0) {
        uint32_t file_cluster = ((uint32_t)entries[i].first_cluster_hi << 16) |
                                entries[i].first_cluster_lo;

        while (file_cluster < FAT32_EOC && file_cluster != 0) {
          uint32_t next = fat32_get_fat_entry(fs, file_cluster);
          fat32_set_fat_entry(fs, file_cluster, FAT32_FREE_CLUSTER);
          file_cluster = next;
        }

        entries[i].name[0] = 0xE5;
        fat32_write_cluster(fs, cluster, fs->cluster_buffer);
        return 0;
      }
    }

    cluster = fat32_get_fat_entry(fs, cluster);
  }

  return -1;
}

vfs_node_t *fat32_mount(const char *device, const char *mountpoint) {
  (void)mountpoint;

  if (device && device[0]) {
    block_device_t *blk = block_device_find(device);
    if (blk) {
      vfs_node_t *root = fat32_mount_block_device(blk, 0);
      if (root) {
        return root;
      }
      kprint("FAT32: failed to mount block device, falling back to RAM\n");
    }
  }

  fat32_fs_t *fs = kmalloc(sizeof(fat32_fs_t));
  if (!fs) {
    return NULL;
  }

  memset(fs, 0, sizeof(fat32_fs_t));

  fs->sectors_per_cluster = 8;
  fs->bytes_per_cluster = fs->sectors_per_cluster * FAT32_SECTOR_SIZE;
  fs->total_clusters = 1024;
  fs->block = NULL;
  fs->partition_lba = 0;
  fs->fat_start_lba = 0;
  fs->data_start_lba = 0;
  fs->fat_count = 1;
  fs->fat_sectors =
      (fs->total_clusters * sizeof(uint32_t) + FAT32_SECTOR_SIZE - 1) /
      FAT32_SECTOR_SIZE;
  memset(&fs->bpb, 0, sizeof(fs->bpb));
  fs->bpb.bytes_per_sector = FAT32_SECTOR_SIZE;
  fs->bpb.sectors_per_cluster = fs->sectors_per_cluster;
  fs->bpb.number_of_fats = 1;
  fs->bpb.fat_size_32 = fs->fat_sectors;
  fs->bpb.root_cluster = 2;

  fs->fat_buffer = kmalloc(fs->total_clusters * sizeof(uint32_t));
  if (!fs->fat_buffer) {
    kfree(fs);
    return NULL;
  }

  fs->cluster_buffer = kmalloc(fs->bytes_per_cluster);
  if (!fs->cluster_buffer) {
    kfree(fs->fat_buffer);
    kfree(fs);
    return NULL;
  }

  // Allocate RAM storage for data region (all clusters)
  uint32_t data_size = (fs->total_clusters - 2) * fs->bytes_per_cluster;
  fs->data_region = kmalloc(data_size);
  if (!fs->data_region) {
    kfree(fs->cluster_buffer);
    kfree(fs->fat_buffer);
    kfree(fs);
    return NULL;
  }
  memset(fs->data_region, 0, data_size);

  memset(fs->fat_buffer, 0, fs->total_clusters * sizeof(uint32_t));
  fs->fat_buffer[0] = 0x0FFFFFF8;
  fs->fat_buffer[1] = 0x0FFFFFFF;
  fs->fat_buffer[2] = FAT32_EOC;

  // Initialize the root directory cluster (cluster 2) with empty entries
  memset(fs->cluster_buffer, 0, fs->bytes_per_cluster);
  fat32_write_cluster(fs, 2, fs->cluster_buffer);

  fat32_dir_entry_t root_entry;
  memset(&root_entry, 0, sizeof(fat32_dir_entry_t));
  memset(root_entry.name, ' ', 11);
  root_entry.name[0] = '/';
  root_entry.attr = FAT32_ATTR_DIRECTORY;
  root_entry.first_cluster_hi = 0;
  root_entry.first_cluster_lo = 2;

  fat32_node_t *root = fat32_create_node(fs, &root_entry, "/");
  if (!root) {
    kfree(fs->cluster_buffer);
    kfree(fs->fat_buffer);
    kfree(fs);
    return NULL;
  }

  root->base.fs = &fat32_filesystem;
  strcpy(root->base.name, "/");

  kprint("FAT32 filesystem mounted (RAM-based)\n");

  return (vfs_node_t *)root;
}

void fat32_unmount(vfs_node_t *node) {
  if (!node) {
    return;
  }

  fat32_node_t *fat_node = (fat32_node_t *)node;
  fat32_fs_t *fs = fat_node->fs;

  if (fs) {
    if (fs->fat_buffer) {
      kfree(fs->fat_buffer);
    }
    if (fs->cluster_buffer) {
      kfree(fs->cluster_buffer);
    }
    if (fs->data_region) {
      kfree(fs->data_region);
    }
    kfree(fs);
  }

  kfree(fat_node);
}

void fat32_init(void) { vfs_register_filesystem(&fat32_filesystem); }

vfs_node_t *fat32_mount_ramdisk(uint8_t *data, uint64_t size) {
  if (!data || size < sizeof(fat32_bpb_t)) {
    kprint("Invalid ramdisk data\n");
    return NULL;
  }

  fat32_bpb_t *bpb = (fat32_bpb_t *)data;

  // Verify FAT32 signature
  if (bpb->boot_signature != 0x29) {
    kprint("Invalid FAT32 boot signature\n");
    return NULL;
  }

  fat32_fs_t *fs = kmalloc(sizeof(fat32_fs_t));
  if (!fs) {
    return NULL;
  }

  memset(fs, 0, sizeof(fat32_fs_t));

  // Parse BPB
  fs->sectors_per_cluster = bpb->sectors_per_cluster;
  fs->bytes_per_cluster = fs->sectors_per_cluster * bpb->bytes_per_sector;

  uint32_t total_sectors =
      bpb->total_sectors_32 ? bpb->total_sectors_32 : bpb->total_sectors_16;
  uint32_t fat_sectors = bpb->fat_size_32 * bpb->number_of_fats;
  uint32_t data_sectors = total_sectors - (bpb->reserved_sectors + fat_sectors);
  fs->total_clusters = data_sectors / fs->sectors_per_cluster;

  // Calculate offsets
  uint32_t fat_offset = bpb->reserved_sectors * bpb->bytes_per_sector;
  uint32_t data_offset = fat_offset + (fat_sectors * bpb->bytes_per_sector);

  fs->block = NULL;
  fs->partition_lba = 0;
  fs->fat_start_lba = 0;
  fs->data_start_lba = 0;
  fs->fat_count = bpb->number_of_fats;
  fs->fat_sectors = bpb->fat_size_32;
  memcpy(&fs->bpb, bpb, sizeof(fat32_bpb_t));

  // Set up FAT buffer
  fs->fat_buffer = kmalloc(fs->total_clusters * sizeof(uint32_t));
  if (!fs->fat_buffer) {
    kfree(fs);
    return NULL;
  }

  // Copy FAT from ramdisk
  uint32_t fat_bytes = fs->total_clusters * sizeof(uint32_t);
  memcpy(fs->fat_buffer, data + fat_offset, fat_bytes);

  fs->cluster_buffer = kmalloc(fs->bytes_per_cluster);
  if (!fs->cluster_buffer) {
    kfree(fs->fat_buffer);
    kfree(fs);
    return NULL;
  }

  // Set up data region - copy from ramdisk instead of just pointing
  uint32_t data_size = (fs->total_clusters - 2) * fs->bytes_per_cluster;
  fs->data_region = kmalloc(data_size);
  if (!fs->data_region) {
    kfree(fs->cluster_buffer);
    kfree(fs->fat_buffer);
    kfree(fs);
    return NULL;
  }

  // Copy data region from ramdisk
  memcpy(fs->data_region, data + data_offset, data_size);

  // Create root node
  fat32_dir_entry_t root_entry;
  memset(&root_entry, 0, sizeof(fat32_dir_entry_t));
  memset(root_entry.name, ' ', 11);
  root_entry.name[0] = '/';
  root_entry.attr = FAT32_ATTR_DIRECTORY;
  root_entry.first_cluster_hi = (bpb->root_cluster >> 16) & 0xFFFF;
  root_entry.first_cluster_lo = bpb->root_cluster & 0xFFFF;

  fat32_node_t *root = fat32_create_node(fs, &root_entry, "/");
  if (!root) {
    kfree(fs->cluster_buffer);
    kfree(fs->fat_buffer);
    kfree(fs);
    return NULL;
  }

  root->base.fs = &fat32_filesystem;
  strcpy(root->base.name, "/");

  kprint("FAT32 filesystem mounted from ramdisk\n");

  return (vfs_node_t *)root;
}

vfs_node_t *fat32_mount_block_device(block_device_t *device,
                                     uint64_t lba_offset) {
  if (!device) {
    return NULL;
  }

  uint32_t sector_size = device->block_size;
  if (sector_size < sizeof(fat32_bpb_t)) {
    kprint("FAT32: sector too small\n");
    return NULL;
  }

  uint8_t *sector = kmalloc(sector_size);
  if (!sector) {
    return NULL;
  }

  if (block_device_read(device, lba_offset, 1, sector) != 0) {
    kfree(sector);
    return NULL;
  }

  fat32_bpb_t *bpb = (fat32_bpb_t *)sector;
  if (bpb->boot_signature != 0x29) {
    kprint("FAT32: invalid boot signature\n");
    kfree(sector);
    return NULL;
  }

  fat32_fs_t *fs = kmalloc(sizeof(fat32_fs_t));
  if (!fs) {
    kfree(sector);
    return NULL;
  }

  memset(fs, 0, sizeof(fat32_fs_t));

  uint32_t bytes_per_sector = bpb->bytes_per_sector;
  if (bytes_per_sector == 0) {
    bytes_per_sector = FAT32_SECTOR_SIZE;
  }

  fs->sectors_per_cluster = bpb->sectors_per_cluster;
  fs->bytes_per_cluster = fs->sectors_per_cluster * bytes_per_sector;

  uint64_t total_sectors =
      bpb->total_sectors_32 ? bpb->total_sectors_32 : bpb->total_sectors_16;
  uint64_t fat_sectors = (uint64_t)bpb->fat_size_32 * bpb->number_of_fats;
  uint64_t data_sectors = total_sectors - (bpb->reserved_sectors + fat_sectors);
  fs->total_clusters = (uint32_t)(data_sectors / fs->sectors_per_cluster);

  fs->fat_start_lba = lba_offset + bpb->reserved_sectors;
  fs->fat_sectors = bpb->fat_size_32;
  fs->fat_count = bpb->number_of_fats;
  fs->partition_lba = lba_offset;
  fs->data_start_lba =
      fs->fat_start_lba + (uint64_t)bpb->number_of_fats * bpb->fat_size_32;
  fs->block = device;
  memcpy(&fs->bpb, bpb, sizeof(fat32_bpb_t));

  fs->fat_buffer = kmalloc(fs->total_clusters * sizeof(uint32_t));
  if (!fs->fat_buffer) {
    kfree(fs);
    kfree(sector);
    return NULL;
  }

  uint32_t cluster_buffer_size = fs->bytes_per_cluster;
  fs->cluster_buffer = kmalloc(cluster_buffer_size);
  if (!fs->cluster_buffer) {
    kfree(fs->fat_buffer);
    kfree(fs);
    kfree(sector);
    return NULL;
  }

  fs->data_region = NULL;

  uint64_t fat_bytes_total = (uint64_t)bpb->fat_size_32 * bytes_per_sector;
  uint8_t *fat_temp = kmalloc(fat_bytes_total);
  if (!fat_temp) {
    kfree(fs->cluster_buffer);
    kfree(fs->fat_buffer);
    kfree(fs);
    kfree(sector);
    return NULL;
  }

  for (uint32_t i = 0; i < bpb->fat_size_32; i++) {
    if (block_device_read(device, fs->fat_start_lba + i, 1,
                          fat_temp + (uint64_t)i * bytes_per_sector) != 0) {
      kfree(fat_temp);
      kfree(fs->cluster_buffer);
      kfree(fs->fat_buffer);
      kfree(fs);
      kfree(sector);
      return NULL;
    }
  }

  uint32_t entries = (uint32_t)(fat_bytes_total / 4);
  uint32_t limit = fs->total_clusters < entries ? fs->total_clusters : entries;
  uint32_t *fat_entries = (uint32_t *)fat_temp;
  for (uint32_t i = 0; i < limit; i++) {
    fs->fat_buffer[i] = fat_entries[i] & 0x0FFFFFFF;
  }
  for (uint32_t i = limit; i < fs->total_clusters; i++) {
    fs->fat_buffer[i] = FAT32_FREE_CLUSTER;
  }

  kfree(fat_temp);

  fat32_dir_entry_t root_entry;
  memset(&root_entry, 0, sizeof(fat32_dir_entry_t));
  memset(root_entry.name, ' ', 11);
  root_entry.name[0] = '/';
  root_entry.attr = FAT32_ATTR_DIRECTORY;
  root_entry.first_cluster_hi = (bpb->root_cluster >> 16) & 0xFFFF;
  root_entry.first_cluster_lo = bpb->root_cluster & 0xFFFF;

  fat32_node_t *root = fat32_create_node(fs, &root_entry, "/");
  if (!root) {
    kfree(fs->cluster_buffer);
    kfree(fs->fat_buffer);
    kfree(fs);
    kfree(sector);
    return NULL;
  }

  root->base.fs = &fat32_filesystem;
  strcpy(root->base.name, "/");

  kprint("FAT32 filesystem mounted from block device\n");

  kfree(sector);
  return (vfs_node_t *)root;
}

vfs_filesystem_t *fat32_get_filesystem(void) { return &fat32_filesystem; }
