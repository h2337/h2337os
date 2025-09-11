#ifndef TYPES_H
#define TYPES_H

#include <stdint.h>

typedef long time_t;
typedef long off_t;
typedef unsigned int mode_t;
typedef long intptr_t;

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