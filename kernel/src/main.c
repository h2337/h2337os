#include "console.h"
#include "flanterm/flanterm.h"
#include "flanterm/flanterm_backends/fb.h"
#include "gdt.h"
#include "heap.h"
#include "idt.h"
#include "limine_requests.h"
#include "pmm.h"
#include "vmm.h"
#include <limine.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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

  kprint("Initializing memory management...\n");
  pmm_init();
  vmm_init();
  heap_init();

  kprint("\n=== Memory Management Initialized ===\n");
  kprint("Total memory: ");
  kprint_hex(pmm_get_total_pages() * PAGE_SIZE);
  kprint(" bytes\n");
  kprint("Free memory:  ");
  kprint_hex(pmm_get_free_pages() * PAGE_SIZE);
  kprint(" bytes\n");
  kprint("Used memory:  ");
  kprint_hex(pmm_get_used_pages() * PAGE_SIZE);
  kprint(" bytes\n");

  kprint("\n=== Testing Memory Allocation ===\n");

  void *test1 = kmalloc(64);
  kprint("kmalloc(64) returned: 0x");
  kprint_hex((uint64_t)test1);
  kprint("\n");

  void *test2 = kmalloc(1024);
  kprint("kmalloc(1024) returned: 0x");
  kprint_hex((uint64_t)test2);
  kprint("\n");

  void *test3 = kcalloc(10, sizeof(uint64_t));
  kprint("kcalloc(10, 8) returned: 0x");
  kprint_hex((uint64_t)test3);
  kprint("\n");

  kfree(test1);
  kprint("Freed first allocation\n");

  void *test4 = kmalloc(32);
  kprint("kmalloc(32) returned: 0x");
  kprint_hex((uint64_t)test4);
  kprint(" (should reuse freed space)\n");

  kfree(test2);
  kfree(test3);
  kfree(test4);
  kprint("All test allocations freed\n");

  kprint("\n=== System Ready ===\n");

  hcf();
}
