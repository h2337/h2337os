#ifndef TYPES_H
#define TYPES_H

#include <stdint.h>

typedef long time_t;
typedef long off_t;
typedef unsigned int mode_t;
typedef long intptr_t;

#define S_IFMT 00170000
#define S_IFSOCK 0140000
#define S_IFLNK 0120000
#define S_IFREG 0100000
#define S_IFBLK 0060000
#define S_IFDIR 0040000
#define S_IFCHR 0020000
#define S_IFIFO 0010000

#define S_IRUSR 00400
#define S_IWUSR 00200
#define S_IXUSR 00100
#define S_IRGRP 00040
#define S_IWGRP 00020
#define S_IXGRP 00010
#define S_IROTH 00004
#define S_IWOTH 00002
#define S_IXOTH 00001

#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#define S_ISCHR(m) (((m) & S_IFMT) == S_IFCHR)
#define S_ISFIFO(m) (((m) & S_IFMT) == S_IFIFO)

#define WNOHANG 0x01
#define WUNTRACED 0x02
#define WCONTINUED 0x08

struct stat {
  uint64_t st_dev;
  uint64_t st_ino;
  mode_t st_mode;
  uint64_t st_nlink;
  uint32_t st_uid;
  uint32_t st_gid;
  uint64_t st_rdev;
  off_t st_size;
  uint64_t st_blksize;
  uint64_t st_blocks;
  time_t st_atime;
  time_t st_mtime;
  time_t st_ctime;
};

#endif
