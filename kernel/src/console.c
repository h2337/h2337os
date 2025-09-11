#include "console.h"
#include "flanterm/flanterm.h"
#include "flanterm/flanterm_backends/fb.h"
#include "libc.h"

struct flanterm_context *ft_ctx;

void console_init(struct limine_framebuffer *fb) {
  ft_ctx = flanterm_fb_init(
      NULL, NULL, fb->address, fb->width, fb->height, fb->pitch,
      fb->red_mask_size, fb->red_mask_shift, fb->green_mask_size,
      fb->green_mask_shift, fb->blue_mask_size, fb->blue_mask_shift, NULL, NULL,
      NULL, NULL, NULL, NULL, NULL, NULL, 0, 0, 1, 0, 0, 0);
}

void kprint(const char *str) { flanterm_write(ft_ctx, str, strlen(str)); }