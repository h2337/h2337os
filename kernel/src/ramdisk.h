#ifndef RAMDISK_H
#define RAMDISK_H

#include <stdint.h>

void ramdisk_init(void);
uint8_t *ramdisk_get_data(void);
uint64_t ramdisk_get_size(void);

#endif