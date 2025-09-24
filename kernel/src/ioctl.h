#ifndef IOCTL_H
#define IOCTL_H

#include <stdint.h>

#define TIOCGWINSZ 0x5413
#define TIOCSWINSZ 0x5414
#define FIONREAD 0x541B

struct winsize {
  uint16_t ws_row;
  uint16_t ws_col;
  uint16_t ws_xpixel;
  uint16_t ws_ypixel;
};

#endif
