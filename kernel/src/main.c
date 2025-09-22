#include "console.h"
#include "fat32.h"
#include "flanterm/flanterm.h"
#include "flanterm/flanterm_backends/fb.h"
#include "gdt.h"
#include "heap.h"
#include "idt.h"
#include "keyboard.h"
#include "limine_requests.h"
#include "pic.h"
#include "pit.h"
#include "pmm.h"
#include "process.h"
#include "ramdisk.h"
#include "shell.h"
#include "smp.h"
#include "syscall.h"
#include "usermode.h"
#include "vfs.h"
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
  pic_init();
  pit_init();
  syscall_init();

  kprint("Initializing memory management...\n");
  pmm_init();
  vmm_init();
  heap_init();

  kprint("\n=== Initializing SMP ===\n");
  smp_init();

  kprint("\n=== Initializing Keyboard ===\n");
  keyboard_init();

  kprint("\n=== Initializing Process Management ===\n");
  process_init();

  smp_resume_secondary_cpus();

  kprint("\n=== Initializing Filesystem ===\n");
  vfs_init();
  fat32_init();
  ramdisk_init();

  asm volatile("sti");
  kprint("Interrupts enabled\n");

  kprint("\n=== System Ready ===\n");

  // Enable scheduler for background processes
  scheduler_init();

  // Initialize and run shell in main kernel thread
  shell_init();
  shell_run();
}
