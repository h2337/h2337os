#include "vfs.h"
#include "console.h"
#include "heap.h"
#include "libc.h"
#include "process.h"
#include "sync.h"
#include <stddef.h>

static vfs_node_t *vfs_root = NULL;
static vfs_filesystem_t *filesystems = NULL;
static vfs_mount_t *mount_points = NULL;
static vfs_file_t open_files[VFS_MAX_OPEN_FILES];
static int next_fd = 3;

// Synchronization for VFS operations
static spinlock_t vfs_lock = SPINLOCK_INIT("vfs");
static spinlock_t fd_lock = SPINLOCK_INIT("fd_table");

void vfs_init(void) {
  kprint("Initializing Virtual File System...\n");

  memset(open_files, 0, sizeof(open_files));

  vfs_root = kmalloc(sizeof(vfs_node_t));
  if (!vfs_root) {
    kprint("Failed to allocate VFS root\n");
    return;
  }

  memset(vfs_root, 0, sizeof(vfs_node_t));
  strcpy(vfs_root->name, "/");
  vfs_root->type = VFS_DIRECTORY;
  vfs_root->flags = VFS_READ;

  kprint("VFS initialized\n");
}

int vfs_register_filesystem(vfs_filesystem_t *fs) {
  if (!fs) {
    return -1;
  }

  fs->next = filesystems;
  filesystems = fs;

  kprint("Registered filesystem: ");
  kprint(fs->name);
  kprint("\n");

  return 0;
}

vfs_filesystem_t *vfs_find_filesystem(const char *name) {
  vfs_filesystem_t *fs = filesystems;

  while (fs) {
    if (strcmp(fs->name, name) == 0) {
      return fs;
    }
    fs = fs->next;
  }

  return NULL;
}

int vfs_mount(const char *device, const char *mountpoint, const char *fstype) {
  vfs_filesystem_t *fs = vfs_find_filesystem(fstype);
  if (!fs) {
    kprint("Filesystem type not found: ");
    kprint(fstype);
    kprint("\n");
    return -1;
  }

  vfs_mount_t *mount = kmalloc(sizeof(vfs_mount_t));
  if (!mount) {
    return -1;
  }

  strcpy(mount->mountpoint, mountpoint);
  mount->fs = fs;
  mount->root = fs->mount(device, mountpoint);

  if (!mount->root) {
    kfree(mount);
    return -1;
  }

  mount->next = mount_points;
  mount_points = mount;

  if (strcmp(mountpoint, "/") == 0) {
    vfs_root = mount->root;
  }

  kprint("Mounted ");
  kprint(fstype);
  kprint(" at ");
  kprint(mountpoint);
  kprint("\n");

  return 0;
}

int vfs_unmount(const char *mountpoint) {
  vfs_mount_t *mount = mount_points;
  vfs_mount_t *prev = NULL;

  while (mount) {
    if (strcmp(mount->mountpoint, mountpoint) == 0) {
      if (mount->fs->unmount) {
        mount->fs->unmount(mount->root);
      }

      if (prev) {
        prev->next = mount->next;
      } else {
        mount_points = mount->next;
      }

      kfree(mount);
      return 0;
    }
    prev = mount;
    mount = mount->next;
  }

  return -1;
}

static char *vfs_normalize_path(const char *path, char *normalized) {
  char fullpath[VFS_MAX_PATH];

  // Check if path is absolute or relative
  if (path[0] == '/') {
    strcpy(fullpath, path);
  } else {
    // Relative path - prepend current working directory
    const char *cwd = process_get_cwd();
    strcpy(fullpath, cwd);

    // Ensure cwd ends with /
    size_t cwd_len = strlen(fullpath);
    if (cwd_len > 1 && fullpath[cwd_len - 1] != '/') {
      strcat(fullpath, "/");
    }

    strcat(fullpath, path);
  }

  // Now normalize the path (handle . and ..)
  char *src = fullpath;
  char *dst = normalized;
  *dst++ = '/';

  while (*src) {
    if (*src == '/') {
      src++;
      continue;
    }

    if (*src == '.') {
      if (src[1] == '/' || src[1] == '\0') {
        // Skip "./" or trailing "."
        src++;
        if (*src == '/')
          src++;
        continue;
      } else if (src[1] == '.' && (src[2] == '/' || src[2] == '\0')) {
        // Handle ".." - go back one directory
        src += 2;
        if (*src == '/')
          src++;

        // Remove last directory from dst
        if (dst > normalized + 1) {
          dst--; // Skip the trailing /
          while (dst > normalized && *(dst - 1) != '/') {
            dst--;
          }
        }
        continue;
      }
    }

    // Copy normal path component
    while (*src && *src != '/') {
      *dst++ = *src++;
    }

    if (*src == '/') {
      *dst++ = '/';
      src++;
    }
  }

  // Remove trailing slash unless it's root
  if (dst > normalized + 1 && *(dst - 1) == '/') {
    dst--;
  }

  *dst = '\0';
  return normalized;
}

vfs_node_t *vfs_resolve_path(const char *path) {
  if (!path || !vfs_root) {
    return NULL;
  }

  char normalized[VFS_MAX_PATH];
  vfs_normalize_path(path, normalized);

  if (normalized[0] == '/' && normalized[1] == '\0') {
    return vfs_root;
  }

  char pathcopy[VFS_MAX_PATH];
  strcpy(pathcopy, normalized);

  vfs_node_t *current = vfs_root;
  char *token = strtok(pathcopy, "/");

  while (token && current) {
    if (current->finddir) {
      current = current->finddir(current, token);
    } else {
      return NULL;
    }
    token = strtok(NULL, "/");
  }

  return current;
}

vfs_node_t *vfs_open(const char *path, uint32_t flags) {
  vfs_node_t *node = vfs_resolve_path(path);

  if (!node && (flags & VFS_CREATE)) {
    char normalized[VFS_MAX_PATH];
    vfs_normalize_path(path, normalized);

    char dirpath[VFS_MAX_PATH];
    char filename[VFS_MAX_NAME];

    strcpy(dirpath, normalized);
    char *last_slash = NULL;
    for (char *p = dirpath; *p; p++) {
      if (*p == '/') {
        last_slash = p;
      }
    }

    vfs_node_t *parent;
    if (last_slash) {
      strcpy(filename, last_slash + 1);
      *last_slash = '\0';
      if (dirpath[0] == '\0') {
        parent = vfs_root;
      } else {
        parent = vfs_resolve_path(dirpath);
      }
    } else {
      // This shouldn't happen after normalization, but handle it
      strcpy(filename, normalized);
      parent = vfs_root;
    }

    if (parent && parent->create) {
      if (parent->create(parent, filename, VFS_FILE) == 0) {
        node = vfs_resolve_path(path);
      }
    }
  }

  if (node && node->open) {
    node->open(node, flags);
  }

  return node;
}

void vfs_close(vfs_node_t *node) {
  if (node && node->close) {
    node->close(node);
  }
}

uint32_t vfs_read(vfs_node_t *node, uint32_t offset, uint32_t size,
                  uint8_t *buffer) {
  if (node && node->read) {
    return node->read(node, offset, size, buffer);
  }
  return 0;
}

uint32_t vfs_write(vfs_node_t *node, uint32_t offset, uint32_t size,
                   uint8_t *buffer) {
  if (node && node->write) {
    return node->write(node, offset, size, buffer);
  }
  return 0;
}

vfs_node_t *vfs_readdir(vfs_node_t *node, uint32_t index) {
  if (node && node->readdir && (node->type & VFS_DIRECTORY)) {
    return node->readdir(node, index);
  }
  return NULL;
}

vfs_node_t *vfs_finddir(vfs_node_t *node, const char *name) {
  if (node && node->finddir && (node->type & VFS_DIRECTORY)) {
    return node->finddir(node, name);
  }
  return NULL;
}

int vfs_create(vfs_node_t *parent, const char *name, uint32_t type) {
  if (parent && parent->create && (parent->type & VFS_DIRECTORY)) {
    return parent->create(parent, name, type);
  }
  return -1;
}

int vfs_unlink(vfs_node_t *parent, const char *name) {
  if (parent && parent->unlink && (parent->type & VFS_DIRECTORY)) {
    return parent->unlink(parent, name);
  }
  return -1;
}

int vfs_open_fd(const char *path, uint32_t flags) {
  vfs_node_t *node = vfs_open(path, flags);
  if (!node) {
    return -1;
  }

  // Lock the file descriptor table
  spin_lock(&fd_lock);

  int result_fd = -1;
  for (int i = 0; i < VFS_MAX_OPEN_FILES; i++) {
    if (!open_files[i].in_use) {
      open_files[i].node = node;
      open_files[i].offset = 0;
      open_files[i].flags = flags;
      open_files[i].fd = next_fd++;
      open_files[i].in_use = 1;
      result_fd = open_files[i].fd;
      break;
    }
  }

  spin_unlock(&fd_lock);

  if (result_fd == -1) {
    vfs_close(node);
  }
  return result_fd;
}

void vfs_close_fd(int fd) {
  spin_lock(&fd_lock);
  for (int i = 0; i < VFS_MAX_OPEN_FILES; i++) {
    if (open_files[i].in_use && open_files[i].fd == fd) {
      vfs_node_t *node = open_files[i].node;
      open_files[i].in_use = 0;
      spin_unlock(&fd_lock);
      vfs_close(node); // Call vfs_close outside of lock to avoid deadlock
      return;
    }
  }
  spin_unlock(&fd_lock);
}

uint32_t vfs_read_fd(int fd, uint8_t *buffer, uint32_t size) {
  for (int i = 0; i < VFS_MAX_OPEN_FILES; i++) {
    if (open_files[i].in_use && open_files[i].fd == fd) {
      uint32_t bytes =
          vfs_read(open_files[i].node, open_files[i].offset, size, buffer);
      open_files[i].offset += bytes;
      return bytes;
    }
  }
  return 0;
}

uint32_t vfs_write_fd(int fd, uint8_t *buffer, uint32_t size) {
  for (int i = 0; i < VFS_MAX_OPEN_FILES; i++) {
    if (open_files[i].in_use && open_files[i].fd == fd) {
      uint32_t bytes =
          vfs_write(open_files[i].node, open_files[i].offset, size, buffer);
      open_files[i].offset += bytes;
      return bytes;
    }
  }
  return 0;
}

int vfs_seek_fd(int fd, int32_t offset, int whence) {
  for (int i = 0; i < VFS_MAX_OPEN_FILES; i++) {
    if (open_files[i].in_use && open_files[i].fd == fd) {
      switch (whence) {
      case SEEK_SET:
        open_files[i].offset = offset;
        break;
      case SEEK_CUR:
        open_files[i].offset += offset;
        break;
      case SEEK_END:
        open_files[i].offset = open_files[i].node->size + offset;
        break;
      default:
        return -1;
      }
      return open_files[i].offset;
    }
  }
  return -1;
}

vfs_node_t *vfs_get_root(void) { return vfs_root; }

void vfs_set_root(vfs_node_t *root) { vfs_root = root; }