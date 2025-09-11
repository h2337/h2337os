#include "syscall.h"
#include "console.h"
#include "heap.h"
#include "idt.h"
#include "libc.h"
#include "process.h"
#include "types.h"
#include "vfs.h"
#include "vmm.h"
#include <stddef.h>

extern void syscall_entry(void);

static uint64_t sys_exit(int exit_code) {
  kprint("Process exiting with code: ");
  kprint_hex(exit_code);
  kprint("\n");

  // The assembly code will handle the actual exit
  return 0;
}

static uint64_t sys_write(int fd, const char *buf, size_t count) {
  if (fd == 1 || fd == 2) {
    for (size_t i = 0; i < count; i++) {
      kputchar(buf[i]);
    }
    return count;
  }
  return -1;
}

static uint64_t sys_read(int fd, char *buf, size_t count) {
  process_t *proc = process_get_current();
  if (!proc || fd < 0 || fd >= 256)
    return -1;

  int vfs_fd = proc->fd_table[fd];
  if (vfs_fd < 0)
    return -1;

  // For stdin, we'd need keyboard input
  if (fd == 0) {
    // TODO: Implement keyboard input
    return 0;
  }

  return vfs_read_fd(vfs_fd, (uint8_t *)buf, count);
}

static uint64_t sys_open(const char *path, int flags, int mode) {
  (void)mode; // TODO: Implement mode support

  process_t *proc = process_get_current();
  if (!proc || !path)
    return -1;

  // Find free fd in process table
  int fd = -1;
  for (int i = 3; i < 256; i++) { // Start from 3 (after stdin/stdout/stderr)
    if (proc->fd_table[i] == -1) {
      fd = i;
      break;
    }
  }

  if (fd == -1)
    return -1; // No free file descriptors

  // Convert flags to VFS flags
  uint32_t vfs_flags = 0;
  if (flags & 0x01)
    vfs_flags |= VFS_READ;
  if (flags & 0x02)
    vfs_flags |= VFS_WRITE;
  if (flags & 0x40)
    vfs_flags |= VFS_CREATE;
  if (flags & 0x200)
    vfs_flags |= VFS_TRUNCATE;
  if (flags & 0x400)
    vfs_flags |= VFS_APPEND;

  int vfs_fd = vfs_open_fd(path, vfs_flags);
  if (vfs_fd < 0)
    return -1;

  proc->fd_table[fd] = vfs_fd;
  return fd;
}

static uint64_t sys_close(int fd) {
  process_t *proc = process_get_current();
  if (!proc || fd < 0 || fd >= 256)
    return -1;

  // Don't close stdin/stdout/stderr
  if (fd < 3)
    return -1;

  int vfs_fd = proc->fd_table[fd];
  if (vfs_fd < 0)
    return -1;

  vfs_close_fd(vfs_fd);
  proc->fd_table[fd] = -1;
  return 0;
}

static uint64_t sys_fork(void) {
  process_t *child = process_fork();
  if (!child)
    return -1;

  // In parent, return child PID
  // In child, this will return 0 when it runs
  // We need to set the return value in child's context
  child->context.rax = 0; // Child gets 0 as return value

  return child->pid; // Parent gets child PID
}

static uint64_t sys_execve(const char *path, char *const argv[],
                           char *const envp[]) {
  (void)path;
  (void)argv;
  (void)envp;
  return -1;
}

static uint64_t sys_waitpid(int pid, int *status, int options) {
  return process_waitpid(pid, status, options);
}

static uint64_t sys_getpid(void) {
  process_t *current = process_get_current();
  return current ? current->pid : 0;
}

static uint64_t sys_getppid(void) {
  process_t *current = process_get_current();
  return current ? current->ppid : 0;
}

static uint64_t sys_brk(void *addr) {
  process_t *proc = process_get_current();
  if (!proc)
    return -1;

  if (addr == NULL) {
    // Return current break
    return (uint64_t)proc->brk;
  }

  // Set new break
  if ((uintptr_t)addr < (uintptr_t)proc->brk_start ||
      (uintptr_t)addr > 0x20000000) {
    return -1;
  }

  proc->brk = addr;
  return (uint64_t)addr;
}

static uint64_t sys_mmap(void *addr, size_t length, int prot, int flags, int fd,
                         off_t offset) {
  (void)addr;
  (void)prot;
  (void)flags;
  (void)fd;
  (void)offset;

  if (length == 0)
    return -1;

  void *ptr = kmalloc(length);
  if (!ptr)
    return -1;

  memset(ptr, 0, length);
  return (uint64_t)ptr;
}

static uint64_t sys_munmap(void *addr, size_t length) {
  (void)length;
  kfree(addr);
  return 0;
}

static uint64_t sys_time(time_t *tloc) {
  static time_t current_time = 1609459200;
  current_time++;

  if (tloc) {
    *tloc = current_time;
  }
  return current_time;
}

static uint64_t sys_getcwd(char *buf, size_t size) {
  if (!buf || size == 0)
    return -1;

  const char *cwd = process_get_cwd();
  if (!cwd) {
    strcpy(buf, "/");
    return (uint64_t)buf;
  }

  size_t len = strlen(cwd);
  if (len >= size)
    return -1;

  strcpy(buf, cwd);
  return (uint64_t)buf;
}

static uint64_t sys_chdir(const char *path) {
  if (!path)
    return -1;
  return process_set_cwd(path);
}

static uint64_t sys_stat(const char *path, struct stat *statbuf) {
  if (!path || !statbuf)
    return -1;

  vfs_node_t *node = vfs_resolve_path(path);
  if (!node)
    return -1;

  memset(statbuf, 0, sizeof(struct stat));
  statbuf->st_ino = node->inode;
  statbuf->st_mode = 0;
  if (node->type & VFS_FILE)
    statbuf->st_mode |= 0100000;
  if (node->type & VFS_DIRECTORY)
    statbuf->st_mode |= 0040000;
  statbuf->st_uid = node->uid;
  statbuf->st_gid = node->gid;
  statbuf->st_size = node->size;
  statbuf->st_blksize = 512;
  statbuf->st_blocks = (node->size + 511) / 512;

  return 0;
}

static uint64_t sys_fstat(int fd, struct stat *statbuf) {
  process_t *proc = process_get_current();
  if (!proc || fd < 0 || fd >= 256 || !statbuf)
    return -1;

  // Handle stdin/stdout/stderr
  if (fd < 3) {
    memset(statbuf, 0, sizeof(struct stat));
    statbuf->st_mode = 0020000; // Character device
    statbuf->st_blksize = 512;
    return 0;
  }

  int vfs_fd = proc->fd_table[fd];
  if (vfs_fd < 0)
    return -1;

  // TODO: Get node from VFS fd and fill stat
  memset(statbuf, 0, sizeof(struct stat));
  statbuf->st_mode = 0100000; // Regular file for now
  statbuf->st_blksize = 512;
  return 0;
}

static uint64_t sys_lseek(int fd, off_t offset, int whence) {
  process_t *proc = process_get_current();
  if (!proc || fd < 0 || fd >= 256)
    return -1;

  // Can't seek on stdin/stdout/stderr
  if (fd < 3)
    return -1;

  int vfs_fd = proc->fd_table[fd];
  if (vfs_fd < 0)
    return -1;

  return vfs_seek_fd(vfs_fd, offset, whence);
}

static uint64_t sys_ioctl(int fd, unsigned long request, void *arg) {
  (void)fd;
  (void)request;
  (void)arg;
  return -1;
}

static uint64_t sys_dup(int oldfd) {
  process_t *proc = process_get_current();
  if (!proc || oldfd < 0 || oldfd >= 256)
    return -1;

  int vfs_fd = proc->fd_table[oldfd];
  if (vfs_fd < 0)
    return -1;

  // Find free fd
  for (int i = 0; i < 256; i++) {
    if (proc->fd_table[i] == -1) {
      proc->fd_table[i] = vfs_fd;
      // TODO: Increment reference count in VFS
      return i;
    }
  }

  return -1;
}

static uint64_t sys_dup2(int oldfd, int newfd) {
  process_t *proc = process_get_current();
  if (!proc || oldfd < 0 || oldfd >= 256 || newfd < 0 || newfd >= 256)
    return -1;

  if (oldfd == newfd)
    return newfd;

  int vfs_fd = proc->fd_table[oldfd];
  if (vfs_fd < 0)
    return -1;

  // Close newfd if it's open
  if (proc->fd_table[newfd] >= 0) {
    vfs_close_fd(proc->fd_table[newfd]);
  }

  proc->fd_table[newfd] = vfs_fd;
  // TODO: Increment reference count in VFS
  return newfd;
}

static uint64_t sys_pipe(int pipefd[2]) {
  (void)pipefd;
  return -1;
}

static uint64_t sys_mkdir(const char *path, mode_t mode) {
  (void)mode; // TODO: Implement mode support

  if (!path)
    return -1;

  // Find parent directory
  char parent_path[VFS_MAX_PATH];
  char dir_name[VFS_MAX_NAME];

  strncpy(parent_path, path, VFS_MAX_PATH - 1);
  parent_path[VFS_MAX_PATH - 1] = '\0';

  // Find last '/'
  char *last_slash = NULL;
  for (char *p = parent_path; *p; p++) {
    if (*p == '/')
      last_slash = p;
  }

  if (!last_slash || last_slash == parent_path) {
    // Root directory or no parent
    strncpy(dir_name, path + 1, VFS_MAX_NAME - 1);
    parent_path[1] = '\0';
  } else {
    strncpy(dir_name, last_slash + 1, VFS_MAX_NAME - 1);
    *last_slash = '\0';
  }
  dir_name[VFS_MAX_NAME - 1] = '\0';

  vfs_node_t *parent = vfs_resolve_path(parent_path);
  if (!parent)
    return -1;

  return vfs_create(parent, dir_name, VFS_DIRECTORY);
}

static uint64_t sys_rmdir(const char *path) {
  if (!path)
    return -1;

  // Find parent directory
  char parent_path[VFS_MAX_PATH];
  char dir_name[VFS_MAX_NAME];

  strncpy(parent_path, path, VFS_MAX_PATH - 1);
  parent_path[VFS_MAX_PATH - 1] = '\0';

  // Find last '/'
  char *last_slash = NULL;
  for (char *p = parent_path; *p; p++) {
    if (*p == '/')
      last_slash = p;
  }

  if (!last_slash || last_slash == parent_path) {
    // Root directory or no parent
    strncpy(dir_name, path + 1, VFS_MAX_NAME - 1);
    parent_path[1] = '\0';
  } else {
    strncpy(dir_name, last_slash + 1, VFS_MAX_NAME - 1);
    *last_slash = '\0';
  }
  dir_name[VFS_MAX_NAME - 1] = '\0';

  vfs_node_t *parent = vfs_resolve_path(parent_path);
  if (!parent)
    return -1;

  // Check if it's a directory
  vfs_node_t *node = vfs_finddir(parent, dir_name);
  if (!node || !(node->type & VFS_DIRECTORY))
    return -1;

  return vfs_unlink(parent, dir_name);
}

static uint64_t sys_unlink(const char *path) {
  if (!path)
    return -1;

  // Find parent directory
  char parent_path[VFS_MAX_PATH];
  char file_name[VFS_MAX_NAME];

  strncpy(parent_path, path, VFS_MAX_PATH - 1);
  parent_path[VFS_MAX_PATH - 1] = '\0';

  // Find last '/'
  char *last_slash = NULL;
  for (char *p = parent_path; *p; p++) {
    if (*p == '/')
      last_slash = p;
  }

  if (!last_slash || last_slash == parent_path) {
    // Root directory or no parent
    strncpy(file_name, path + 1, VFS_MAX_NAME - 1);
    parent_path[1] = '\0';
  } else {
    strncpy(file_name, last_slash + 1, VFS_MAX_NAME - 1);
    *last_slash = '\0';
  }
  file_name[VFS_MAX_NAME - 1] = '\0';

  vfs_node_t *parent = vfs_resolve_path(parent_path);
  if (!parent)
    return -1;

  return vfs_unlink(parent, file_name);
}

uint64_t syscall_handler(uint64_t syscall_number, uint64_t arg1, uint64_t arg2,
                         uint64_t arg3, uint64_t arg4, uint64_t arg5) {
  (void)arg4;
  (void)arg5;

  switch (syscall_number) {
  case SYSCALL_EXIT:
    return sys_exit((int)arg1);
  case SYSCALL_WRITE:
    return sys_write((int)arg1, (const char *)arg2, (size_t)arg3);
  case SYSCALL_READ:
    return sys_read((int)arg1, (char *)arg2, (size_t)arg3);
  case SYSCALL_OPEN:
    return sys_open((const char *)arg1, (int)arg2, (int)arg3);
  case SYSCALL_CLOSE:
    return sys_close((int)arg1);
  case SYSCALL_FORK:
    return sys_fork();
  case SYSCALL_EXECVE:
    return sys_execve((const char *)arg1, (char *const *)arg2,
                      (char *const *)arg3);
  case SYSCALL_WAITPID:
    return sys_waitpid((int)arg1, (int *)arg2, (int)arg3);
  case SYSCALL_GETPID:
    return sys_getpid();
  case SYSCALL_GETPPID:
    return sys_getppid();
  case SYSCALL_BRK:
    return sys_brk((void *)arg1);
  case SYSCALL_MMAP:
    return sys_mmap((void *)arg1, (size_t)arg2, (int)arg3, (int)arg4, (int)arg5,
                    0);
  case SYSCALL_MUNMAP:
    return sys_munmap((void *)arg1, (size_t)arg2);
  case SYSCALL_TIME:
    return sys_time((time_t *)arg1);
  case SYSCALL_GETCWD:
    return sys_getcwd((char *)arg1, (size_t)arg2);
  case SYSCALL_CHDIR:
    return sys_chdir((const char *)arg1);
  case SYSCALL_STAT:
    return sys_stat((const char *)arg1, (struct stat *)arg2);
  case SYSCALL_FSTAT:
    return sys_fstat((int)arg1, (struct stat *)arg2);
  case SYSCALL_LSEEK:
    return sys_lseek((int)arg1, (off_t)arg2, (int)arg3);
  case SYSCALL_IOCTL:
    return sys_ioctl((int)arg1, (unsigned long)arg2, (void *)arg3);
  case SYSCALL_DUP:
    return sys_dup((int)arg1);
  case SYSCALL_DUP2:
    return sys_dup2((int)arg1, (int)arg2);
  case SYSCALL_PIPE:
    return sys_pipe((int *)arg1);
  case SYSCALL_MKDIR:
    return sys_mkdir((const char *)arg1, (mode_t)arg2);
  case SYSCALL_RMDIR:
    return sys_rmdir((const char *)arg1);
  case SYSCALL_UNLINK:
    return sys_unlink((const char *)arg1);
  default:
    kprint("Unknown syscall: ");
    kprint_hex(syscall_number);
    kprint("\n");
    return -1;
  }
}

void syscall_init(void) {
  idt_set_gate(0x80, (uint64_t)syscall_entry, 0x08, 0xEE);

  kprint("Syscall handler initialized at interrupt 0x80\n");
}