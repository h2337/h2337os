#include "pit.h"
#include "console.h"
#include "idt.h"
#include "pic.h"
#include "process.h"
#include <stdint.h>

static volatile uint64_t timer_ticks = 0;
static uint32_t timer_frequency = PIT_DEFAULT_FREQUENCY;

static inline void outb(uint16_t port, uint8_t val) {
  asm volatile("outb %0, %1" : : "a"(val), "Nd"(port));
}

static inline uint8_t inb(uint16_t port) {
  uint8_t ret;
  asm volatile("inb %1, %0" : "=a"(ret) : "Nd"(port));
  return ret;
}

void pit_handler(void) {
  timer_ticks++;
  scheduler_tick();
  pic_send_eoi(0);
}

void pit_set_frequency(uint32_t freq) {
  if (freq == 0) {
    freq = PIT_DEFAULT_FREQUENCY;
  }

  timer_frequency = freq;
  uint32_t divisor = PIT_BASE_FREQUENCY / freq;

  if (divisor > 65535) {
    divisor = 65535;
  }

  uint8_t command =
      PIT_CHANNEL0 | PIT_LOBYTE_HIBYTE_MODE | PIT_MODE3 | PIT_BINARY_MODE;
  outb(PIT_COMMAND, command);

  outb(PIT_CHANNEL0_DATA, (uint8_t)(divisor & 0xFF));
  outb(PIT_CHANNEL0_DATA, (uint8_t)((divisor >> 8) & 0xFF));
}

uint64_t pit_get_ticks(void) { return timer_ticks; }

uint64_t pit_get_seconds(void) { return timer_ticks / timer_frequency; }

uint64_t pit_get_milliseconds(void) {
  return (timer_ticks * 1000) / timer_frequency;
}

void pit_sleep(uint32_t milliseconds) {
  uint64_t target_ticks = timer_ticks + (milliseconds * timer_frequency) / 1000;

  while (timer_ticks < target_ticks) {
    asm volatile("hlt");
  }
}

void pit_init(void) {
  kprint("Initializing PIT...\n");

  timer_ticks = 0;
  pit_set_frequency(PIT_DEFAULT_FREQUENCY);
  pic_clear_mask(0);

  kprint("PIT configured for 100 Hz\n");
}
