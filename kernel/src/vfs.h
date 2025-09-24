#ifndef VFS_H
#define VFS_H

#include <stddef.h>
#include <stdint.h>

#include "types.h"

#define VFS_MAX_NAME 256
#define VFS_MAX_PATH 4096
#define VFS_MAX_FILESYSTEMS 16
#define VFS_MAX_MOUNT_POINTS 32
#define VFS_MAX_OPEN_FILES 256

typedef enum {
  VFS_FILE = 1,
  VFS_DIRECTORY = 2,
  VFS_CHARDEVICE = 3,
  VFS_BLOCKDEVICE = 4,
  VFS_PIPE = 5,
  VFS_SYMLINK = 6,
  VFS_MOUNTPOINT = 8
} vfs_node_type_t;

typedef enum {
  VFS_READ = 0x01,
  VFS_WRITE = 0x02,
  VFS_APPEND = 0x04,
  VFS_CREATE = 0x08,
  VFS_TRUNCATE = 0x10
} vfs_flags_t;

typedef enum { SEEK_SET = 0, SEEK_CUR = 1, SEEK_END = 2 } vfs_seek_mode_t;

struct vfs_node;
struct vfs_filesystem;

typedef uint32_t (*vfs_read_t)(struct vfs_node *, uint32_t offset,
                               uint32_t size, uint8_t *buffer);
typedef uint32_t (*vfs_write_t)(struct vfs_node *, uint32_t offset,
                                uint32_t size, uint8_t *buffer);
typedef void (*vfs_open_t)(struct vfs_node *, uint32_t flags);
typedef void (*vfs_close_t)(struct vfs_node *);
typedef struct vfs_node *(*vfs_readdir_t)(struct vfs_node *, uint32_t index);
typedef struct vfs_node *(*vfs_finddir_t)(struct vfs_node *, const char *name);
typedef int (*vfs_create_t)(struct vfs_node *, const char *name, uint32_t type,
                            mode_t mode);
typedef int (*vfs_unlink_t)(struct vfs_node *, const char *name);

typedef struct vfs_node {
  char name[VFS_MAX_NAME];
  uint32_t inode;
  uint32_t type;
  uint32_t flags;
  mode_t mode;
  uint32_t uid;
  uint32_t gid;
  uint32_t size;
  uint32_t impl;

  vfs_read_t read;
  vfs_write_t write;
  vfs_open_t open;
  vfs_close_t close;
  vfs_readdir_t readdir;
  vfs_finddir_t finddir;
  vfs_create_t create;
  vfs_unlink_t unlink;

  void *ptr;
  struct vfs_filesystem *fs;
} vfs_node_t;

typedef struct vfs_filesystem {
  char name[32];
  vfs_node_t *(*mount)(const char *device, const char *mountpoint);
  void (*unmount)(vfs_node_t *node);
  struct vfs_filesystem *next;
} vfs_filesystem_t;

typedef struct vfs_mount {
  char mountpoint[VFS_MAX_PATH];
  vfs_node_t *root;
  vfs_filesystem_t *fs;
  struct vfs_mount *next;
} vfs_mount_t;

typedef struct vfs_file {
  vfs_node_t *node;
  uint32_t offset;
  uint32_t flags;
  int fd;
  int in_use;
  int refcount;
} vfs_file_t;

typedef struct {
  char d_name[VFS_MAX_NAME];
  uint32_t d_ino;
  uint32_t d_type;
} vfs_dirent_t;

void vfs_init(void);
int vfs_register_filesystem(vfs_filesystem_t *fs);
int vfs_register_special(const char *path, vfs_node_t *node);
int vfs_mount(const char *device, const char *mountpoint, const char *fstype);
int vfs_unmount(const char *mountpoint);

vfs_node_t *vfs_open(const char *path, uint32_t flags, mode_t mode);
void vfs_close(vfs_node_t *node);
uint32_t vfs_read(vfs_node_t *node, uint32_t offset, uint32_t size,
                  uint8_t *buffer);
uint32_t vfs_write(vfs_node_t *node, uint32_t offset, uint32_t size,
                   uint8_t *buffer);
vfs_node_t *vfs_readdir(vfs_node_t *node, uint32_t index);
vfs_node_t *vfs_finddir(vfs_node_t *node, const char *name);
int vfs_create(vfs_node_t *parent, const char *name, uint32_t type,
               mode_t mode);
int vfs_unlink(vfs_node_t *parent, const char *name);

int vfs_open_fd(const char *path, uint32_t flags, mode_t mode);
int vfs_create_fd(vfs_node_t *node, uint32_t flags);
void vfs_close_fd(int fd);
void vfs_retain_fd(int fd);
uint32_t vfs_read_fd(int fd, uint8_t *buffer, uint32_t size);
uint32_t vfs_write_fd(int fd, uint8_t *buffer, uint32_t size);
int vfs_seek_fd(int fd, int32_t offset, int whence);

vfs_node_t *vfs_get_root(void);
void vfs_set_root(vfs_node_t *root);
vfs_node_t *vfs_resolve_path(const char *path);
vfs_node_t *vfs_get_node_from_fd(int fd);

#endif
