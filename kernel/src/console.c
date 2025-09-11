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