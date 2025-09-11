#ifndef PIT_H
#define PIT_H

#include <stdint.h>

#define PIT_CHANNEL0_DATA 0x40
#define PIT_CHANNEL1_DATA 0x41
#define PIT_CHANNEL2_DATA 0x42
#define PIT_COMMAND 0x43

#define PIT_CHANNEL0 0x00
#define PIT_CHANNEL1 0x40
#define PIT_CHANNEL2 0x80

#define PIT_LATCH_MODE 0x00
#define PIT_LOBYTE_MODE 0x10
#define PIT_HIBYTE_MODE 0x20
#define PIT_LOBYTE_HIBYTE_MODE 0x30

#define PIT_MODE0 0x00
#define PIT_MODE1 0x02
#define PIT_MODE2 0x04
#define PIT_MODE3 0x06
#define PIT_MODE4 0x08
#define PIT_MODE5 0x0A

#define PIT_BINARY_MODE 0x00
#define PIT_BCD_MODE 0x01

#define PIT_BASE_FREQUENCY 1193182
#define PIT_DEFAULT_FREQUENCY 100

void pit_init(void);
void pit_set_frequency(uint32_t freq);
uint64_t pit_get_ticks(void);
uint64_t pit_get_seconds(void);
uint64_t pit_get_milliseconds(void);
void pit_sleep(uint32_t milliseconds);
void pit_handler(void);

#endif