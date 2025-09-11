#include "usermode.h"
#include "console.h"
#include "heap.h"
#include "keyboard.h"
#include "libc.h"
#include "pmm.h"
#include "vmm.h"

extern void enter_usermode(void *entry_point, void *user_stack);

// Simple user code that prints a message and exits
static uint8_t user_code[] = {
    // mov rax, 1 (write syscall)
    0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,
    // mov rdi, 1 (stdout)
    0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00,
    // lea rsi, [rel message] - load address of message
    0x48, 0x8d, 0x35, 0x1a, 0x00, 0x00, 0x00,
    // mov rdx, 22 (message length)
    0x48, 0xc7, 0xc2, 0x16, 0x00, 0x00, 0x00,
    // int 0x80
    0xcd, 0x80,
    // mov rax, 0 (exit syscall)
    0x48, 0xc7, 0xc0, 0x00, 0x00, 0x00, 0x00,
    // mov rdi, 0 (exit code)
    0x48, 0xc7, 0xc7, 0x00, 0x00, 0x00, 0x00,
    // int 0x80
    0xcd, 0x80,
    // Should never reach here
    0xeb, 0xfe,
    // Message data
    'H', 'e', 'l', 'l', 'o', ' ', 'f', 'r', 'o', 'm', ' ', 'u', 's', 'e', 'r',
    ' ', 'm', 'o', 'd', 'e', '!', '\n', '\0'};

void usermode_test(void) {
  kprint("Preparing to enter user mode...\n");

  // Allocate physical pages for user code and stack
  void *user_code_phys = pmm_alloc(1);
  if (!user_code_phys) {
    kprint("Failed to allocate memory for user code\n");
    return;
  }

  void *user_stack_phys = pmm_alloc(1);
  if (!user_stack_phys) {
    kprint("Failed to allocate memory for user stack\n");
    pmm_free(user_code_phys, 1);
    return;
  }

  // Map them to user-accessible virtual addresses
  void *user_code_virt = (void *)0x400000;
  void *user_stack_virt = (void *)0x600000;

  page_table_t *kernel_pagemap = vmm_get_kernel_pagemap();

  if (!vmm_map_page(kernel_pagemap, (uint64_t)user_code_virt,
                    (uint64_t)user_code_phys,
                    VMM_PRESENT | VMM_WRITABLE | VMM_USER)) {
    kprint("Failed to map user code page\n");
    pmm_free(user_code_phys, 1);
    pmm_free(user_stack_phys, 1);
    return;
  }

  if (!vmm_map_page(kernel_pagemap, (uint64_t)user_stack_virt,
                    (uint64_t)user_stack_phys,
                    VMM_PRESENT | VMM_WRITABLE | VMM_USER)) {
    kprint("Failed to map user stack page\n");
    vmm_unmap_page(kernel_pagemap, (uint64_t)user_code_virt);
    pmm_free(user_code_phys, 1);
    pmm_free(user_stack_phys, 1);
    return;
  }

  // Copy user code to the mapped page
  memcpy(user_code_virt, user_code, sizeof(user_code));

  uint64_t *stack_top = (uint64_t *)((uint8_t *)user_stack_virt + 4096);

  kprint("User code at: ");
  kprint_hex((uint64_t)user_code_virt);
  kprint("\n");
  kprint("User stack at: ");
  kprint_hex((uint64_t)stack_top);
  kprint("\n");

  kprint("Entering user mode...\n");

  // Enter user mode - will return here after exit syscall
  enter_usermode(user_code_virt, (void *)stack_top);

  // Clean up after returning from user mode
  kprint("Returned to kernel mode\n");

  vmm_unmap_page(kernel_pagemap, (uint64_t)user_code_virt);
  vmm_unmap_page(kernel_pagemap, (uint64_t)user_stack_virt);
  pmm_free(user_code_phys, 1);
  pmm_free(user_stack_phys, 1);

  kprint("User mode test completed\n");

  // Ensure interrupts are enabled
  asm volatile("sti");

  // Flush any pending keyboard input
  keyboard_flush_buffer();
}