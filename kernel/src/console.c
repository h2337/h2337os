#include "console.h"
#include "flanterm/flanterm.h"
#include "flanterm/flanterm_backends/fb.h"
#include "libc.h"
#include "serial.h"

struct flanterm_context *ft_ctx;
static bool serial_enabled = false;

void console_init(struct limine_framebuffer *fb) {
  ft_ctx = flanterm_fb_init(
      NULL, NULL, fb->address, fb->width, fb->height, fb->pitch,
      fb->red_mask_size, fb->red_mask_shift, fb->green_mask_size,
      fb->green_mask_shift, fb->blue_mask_size, fb->blue_mask_shift, NULL, NULL,
      NULL, NULL, NULL, NULL, NULL, NULL, 0, 0, 1, 0, 0, 0);

  serial_init(COM1);
  serial_enabled = true;
  kprint("Serial I/O initialized on COM1 (0x3F8)\n");
}

void kprint(const char *str) {
  flanterm_write(ft_ctx, str, strlen(str));
  if (serial_enabled) {
    serial_writestring(COM1, str);
  }
}

void kputchar(char c) {
  char str[2] = {c, '\0'};
  flanterm_write(ft_ctx, str, 1);
  if (serial_enabled) {
    serial_write(COM1, c);
  }
}

char kgetchar(void) {
  if (serial_enabled) {
    return serial_read(COM1);
  }
  return 0;
}

void kprint_hex(uint64_t value) {
  char hex_chars[] = "0123456789ABCDEF";
  char buffer[17];
  int i;

  for (i = 15; i >= 0; i--) {
    buffer[i] = hex_chars[value & 0xF];
    value >>= 4;
  }
  buffer[16] = '\0';

  kprint(buffer);
}

void kprint_hex8(uint8_t value) {
  char hex_chars[] = "0123456789ABCDEF";
  char buffer[3];

  buffer[0] = hex_chars[(value >> 4) & 0xF];
  buffer[1] = hex_chars[value & 0xF];
  buffer[2] = '\0';

  kprint(buffer);
}

void kprint_hex16(uint16_t value) {
  char hex_chars[] = "0123456789ABCDEF";
  char buffer[5];

  buffer[0] = hex_chars[(value >> 12) & 0xF];
  buffer[1] = hex_chars[(value >> 8) & 0xF];
  buffer[2] = hex_chars[(value >> 4) & 0xF];
  buffer[3] = hex_chars[value & 0xF];
  buffer[4] = '\0';

  kprint(buffer);
}

void kprint_dec(uint32_t value) {
  char buffer[11]; // Max 10 digits + null terminator
  int i = 10;

  buffer[i] = '\0';

  if (value == 0) {
    buffer[--i] = '0';
  } else {
    while (value > 0 && i > 0) {
      buffer[--i] = '0' + (value % 10);
      value /= 10;
    }
  }

  kprint(&buffer[i]);
}