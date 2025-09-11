#include "console.h"
#include "flanterm/flanterm.h"
#include "flanterm/flanterm_backends/fb.h"
#include "gdt.h"
#include "idt.h"
#include <limine.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

__attribute__((
    used, section(".limine_requests"))) static volatile LIMINE_BASE_REVISION(3);

__attribute__((
    used,
    section(
        ".limine_requests"))) static volatile struct limine_framebuffer_request
    framebuffer_request = {.id = LIMINE_FRAMEBUFFER_REQUEST, .revision = 0};

__attribute__((used,
               section(".limine_requests_"
                       "start"))) static volatile LIMINE_REQUESTS_START_MARKER;

__attribute__((
    used,
    section(
        ".limine_requests_end"))) static volatile LIMINE_REQUESTS_END_MARKER;

static void hcf(void) {
  for (;;) {
    asm("hlt");
  }
}

void kmain(void) {
  if (LIMINE_BASE_REVISION_SUPPORTED == false) {
    hcf();
  }

  if (framebuffer_request.response == NULL ||
      framebuffer_request.response->framebuffer_count < 1) {
    hcf();
  }

  struct limine_framebuffer *framebuffer =
      framebuffer_request.response->framebuffers[0];

  console_init(framebuffer);

  kprint("h2337os kernel starting...\n");

  gdt_init();
  idt_init();

  kprint("Interrupt system initialized successfully!\n");

  hcf();
}
