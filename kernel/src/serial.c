#include "serial.h"
#include "libc.h"

static inline void outb(uint16_t port, uint8_t val) {
  asm volatile("outb %0, %1" : : "a"(val), "Nd"(port));
}

static inline uint8_t inb(uint16_t port) {
  uint8_t ret;
  asm volatile("inb %1, %0" : "=a"(ret) : "Nd"(port));
  return ret;
}

void serial_init(uint16_t port) {
  outb(port + 1, 0x00);
  outb(port + 3, 0x80);
  outb(port + 0, 0x03);
  outb(port + 1, 0x00);
  outb(port + 3, 0x03);
  outb(port + 2, 0xC7);
  outb(port + 4, 0x0B);
  outb(port + 4, 0x1E);
  outb(port + 0, 0xAE);

  if (inb(port + 0) != 0xAE) {
    return;
  }

  outb(port + 4, 0x0F);
}

bool serial_received(uint16_t port) { return (inb(port + 5) & 0x01) != 0; }

char serial_read(uint16_t port) {
  while (!serial_received(port))
    ;
  return inb(port);
}

bool serial_is_transmit_empty(uint16_t port) {
  return (inb(port + 5) & 0x20) != 0;
}

void serial_write(uint16_t port, char c) {
  while (!serial_is_transmit_empty(port))
    ;
  outb(port, c);
}

void serial_writestring(uint16_t port, const char *str) {
  size_t len = strlen(str);
  for (size_t i = 0; i < len; i++) {
    serial_write(port, str[i]);
  }
}