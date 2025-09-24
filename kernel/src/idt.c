#include "idt.h"
#include "console.h"
#include "keyboard.h"
#include "libc.h"
#include "limine_requests.h"
#include "pic.h"
#include "pit.h"
#include "pmm.h"
#include "process.h"
#include "smp.h"
#include "vmm.h"
#include <stdbool.h>
#include <stddef.h>

static struct idt_entry idt[256];
static struct idt_ptr idtr;

extern void isr0(void);
extern void isr1(void);
extern void isr2(void);
extern void isr3(void);
extern void isr4(void);
extern void isr5(void);
extern void isr6(void);
extern void isr7(void);
extern void isr8(void);
extern void isr9(void);
extern void isr10(void);
extern void isr11(void);
extern void isr12(void);
extern void isr13(void);
extern void isr14(void);
extern void isr15(void);
extern void isr16(void);
extern void isr17(void);
extern void isr18(void);
extern void isr19(void);
extern void isr20(void);
extern void isr21(void);
extern void isr22(void);
extern void isr23(void);
extern void isr24(void);
extern void isr25(void);
extern void isr26(void);
extern void isr27(void);
extern void isr28(void);
extern void isr29(void);
extern void isr30(void);
extern void isr31(void);

extern void isr32(void);
extern void isr33(void);
extern void isr34(void);
extern void isr35(void);
extern void isr36(void);
extern void isr37(void);
extern void isr38(void);
extern void isr39(void);
extern void isr40(void);
extern void isr41(void);
extern void isr42(void);
extern void isr43(void);
extern void isr44(void);
extern void isr45(void);
extern void isr46(void);
extern void isr47(void);
extern void isr64(void);

static const char *exception_messages[] = {"Division By Zero",
                                           "Debug",
                                           "Non Maskable Interrupt",
                                           "Breakpoint",
                                           "Into Detected Overflow",
                                           "Out of Bounds",
                                           "Invalid Opcode",
                                           "No Coprocessor",
                                           "Double Fault",
                                           "Coprocessor Segment Overrun",
                                           "Bad TSS",
                                           "Segment Not Present",
                                           "Stack Fault",
                                           "General Protection Fault",
                                           "Page Fault",
                                           "Unknown Interrupt",
                                           "Coprocessor Fault",
                                           "Alignment Check",
                                           "Machine Check",
                                           "SIMD Floating-Point Exception",
                                           "Virtualization Exception",
                                           "Control Protection Exception",
                                           "Reserved",
                                           "Reserved",
                                           "Reserved",
                                           "Reserved",
                                           "Reserved",
                                           "Reserved",
                                           "Hypervisor Injection Exception",
                                           "VMM Communication Exception",
                                           "Security Exception",
                                           "Reserved"};

void idt_set_gate(uint8_t num, uint64_t handler, uint16_t selector,
                  uint8_t flags) {
  idt[num].offset_low = handler & 0xFFFF;
  idt[num].offset_middle = (handler >> 16) & 0xFFFF;
  idt[num].offset_high = (handler >> 32) & 0xFFFFFFFF;
  idt[num].selector = selector;
  idt[num].ist = 0;
  idt[num].type_attributes = flags;
  idt[num].reserved = 0;
}

static void load_idt(void) {
  idtr.limit = sizeof(idt) - 1;
  idtr.base = (uint64_t)&idt;
  asm volatile("lidt %0" : : "m"(idtr));
}

void irq_handler(struct interrupt_frame *frame) {
  if (frame->int_no == 32) {
    pit_handler();
  } else if (frame->int_no == 33) {
    keyboard_handler();
  } else if (frame->int_no == LAPIC_TIMER_VECTOR) {
    smp_handle_apic_timer(frame);
  } else if (frame->int_no >= 32 && frame->int_no <= 47) {
    pic_send_eoi(frame->int_no - 32);
  } else {
    // Unknown IRQ source; acknowledge legacy PIC if applicable
    if (frame->int_no >= 32 && frame->int_no <= 47) {
      pic_send_eoi(frame->int_no - 32);
    }
  }
}

static uint64_t get_hhdm_offset(void) {
  if (hhdm_request.response) {
    return hhdm_request.response->offset;
  }
  return 0;
}

static bool map_zero_page(process_t *proc, uint64_t page_addr, uint64_t flags) {
  void *phys_ptr = pmm_alloc_zero(1);
  if (!phys_ptr) {
    return false;
  }

  if (!vmm_map_page(proc->pagemap, page_addr, (uint64_t)phys_ptr,
                    flags | VMM_USER)) {
    pmm_free(phys_ptr, 1);
    return false;
  }

  return true;
}

static bool handle_cow_fault(process_t *proc, uint64_t page_addr) {
  uint64_t entry = 0;
  if (!vmm_get_entry(proc->pagemap, page_addr, &entry)) {
    return false;
  }

  if (!(entry & VMM_COW)) {
    return false;
  }

  uint64_t phys = entry & 0x000FFFFFFFFFF000ULL;
  if (!phys) {
    return false;
  }

  const uint64_t preserve_mask = VMM_USER | VMM_WRITE_THROUGH |
                                 VMM_CACHE_DISABLE | VMM_GLOBAL |
                                 VMM_NO_EXECUTE;
  uint64_t base_flags = (entry & preserve_mask) | VMM_USER;

  uint32_t refs = pmm_ref_get(phys);
  if (refs > 1) {
    void *new_phys_ptr = pmm_alloc(1);
    if (!new_phys_ptr) {
      return false;
    }

    uint64_t new_phys = (uint64_t)new_phys_ptr;
    uint64_t hhdm = get_hhdm_offset();
    if (!hhdm) {
      pmm_free(new_phys_ptr, 1);
      return false;
    }

    memcpy((void *)(new_phys + hhdm), (void *)(phys + hhdm), PAGE_SIZE);

    uint64_t new_flags = base_flags | VMM_WRITABLE;
    if (!vmm_map_page(proc->pagemap, page_addr, new_phys, new_flags)) {
      pmm_free(new_phys_ptr, 1);
      return false;
    }

    pmm_ref_dec(phys);
  } else {
    if (!vmm_update_entry(proc->pagemap, page_addr, VMM_WRITABLE, VMM_COW)) {
      return false;
    }
  }

  return true;
}

static bool handle_user_page_fault(struct interrupt_frame *frame) {
  uint64_t fault_addr;
  asm volatile("mov %%cr2, %0" : "=r"(fault_addr));

  process_t *proc = process_get_current();
  if (!proc || !proc->pagemap) {
    return false;
  }

  bool user = (frame->err_code & (1 << 2)) != 0;
  if (!user) {
    return false;
  }

  bool present = (frame->err_code & 0x1) != 0;
  bool write = (frame->err_code & 0x2) != 0;

  uint64_t page_addr = fault_addr & ~(uint64_t)(PAGE_SIZE - 1);
  bool in_heap = fault_addr >= (uint64_t)proc->brk_start &&
                 fault_addr < (uint64_t)proc->brk;

  vm_region_t *region = process_vm_find_region(proc, fault_addr);

  if (!present) {
    if (in_heap) {
      uint64_t flags = VMM_NO_EXECUTE | VMM_WRITABLE | VMM_USER;
      return map_zero_page(proc, page_addr, flags);
    }

    if (region) {
      uint64_t flags =
          region->flags ? region->flags : (VMM_USER | VMM_NO_EXECUTE);
      return map_zero_page(proc, page_addr, flags);
    }

    return false;
  }

  if (!write) {
    return false;
  }

  if (in_heap) {
    return handle_cow_fault(proc, page_addr);
  }

  if (region) {
    if (!(region->flags & VMM_WRITABLE)) {
      return false;
    }
    return handle_cow_fault(proc, page_addr);
  }

  return false;
}

void exception_handler(struct interrupt_frame *frame) {
  if (frame->int_no >= 32) {
    irq_handler(frame);
    return;
  }

  bool user_mode = (frame->cs & 0x3) == 0x3;

  if (frame->int_no == 14 && handle_user_page_fault(frame)) {
    return;
  }

  kprint("\n=== EXCEPTION OCCURRED ===\n");
  kprint("Exception: ");

  if (frame->int_no < 32) {
    kprint(exception_messages[frame->int_no]);
  } else {
    kprint("Unknown Exception");
  }

  kprint(" (#");
  kprint_hex(frame->int_no);
  kprint(")\n");

  if (frame->err_code != 0) {
    kprint("Error Code: 0x");
    kprint_hex(frame->err_code);
    kprint("\n");
  }

  if (frame->int_no == 14) {
    uint64_t cr2;
    asm volatile("mov %%cr2, %0" : "=r"(cr2));
    kprint("Faulting address: 0x");
    kprint_hex(cr2);
    kprint("\n");
  }

  if (user_mode) {
    process_t *proc = process_get_current();
    kprint("Terminating process due to exception\n");
    if (proc) {
      kprint("Process PID: ");
      kprint_hex(proc->pid);
      kprint("\n");
      process_exit(128 + (int)frame->int_no);
      return;
    }
  }

  kprint("\n=== REGISTER DUMP ===\n");
  kprint("RAX: 0x");
  kprint_hex(frame->rax);
  kprint("  RBX: 0x");
  kprint_hex(frame->rbx);
  kprint("\n");

  kprint("RCX: 0x");
  kprint_hex(frame->rcx);
  kprint("  RDX: 0x");
  kprint_hex(frame->rdx);
  kprint("\n");

  kprint("RSI: 0x");
  kprint_hex(frame->rsi);
  kprint("  RDI: 0x");
  kprint_hex(frame->rdi);
  kprint("\n");

  kprint("RBP: 0x");
  kprint_hex(frame->rbp);
  kprint("  RSP: 0x");
  kprint_hex(frame->rsp);
  kprint("\n");

  kprint("R8:  0x");
  kprint_hex(frame->r8);
  kprint("  R9:  0x");
  kprint_hex(frame->r9);
  kprint("\n");

  kprint("R10: 0x");
  kprint_hex(frame->r10);
  kprint("  R11: 0x");
  kprint_hex(frame->r11);
  kprint("\n");

  kprint("R12: 0x");
  kprint_hex(frame->r12);
  kprint("  R13: 0x");
  kprint_hex(frame->r13);
  kprint("\n");

  kprint("R14: 0x");
  kprint_hex(frame->r14);
  kprint("  R15: 0x");
  kprint_hex(frame->r15);
  kprint("\n");

  kprint("\nRIP: 0x");
  kprint_hex(frame->rip);
  kprint("  CS:  0x");
  kprint_hex(frame->cs);
  kprint("\n");

  kprint("RFLAGS: 0x");
  kprint_hex(frame->rflags);
  kprint("  SS: 0x");
  kprint_hex(frame->ss);
  kprint("\n");

  kprint("\n=== SYSTEM HALTED ===\n");

  for (;;) {
    asm volatile("cli; hlt");
  }
}

void idt_init(void) {
  for (int i = 0; i < 256; i++) {
    idt_set_gate(i, 0, 0, 0);
  }

  idt_set_gate(0, (uint64_t)isr0, 0x08, 0x8E);
  idt_set_gate(1, (uint64_t)isr1, 0x08, 0x8E);
  idt_set_gate(2, (uint64_t)isr2, 0x08, 0x8E);
  idt_set_gate(3, (uint64_t)isr3, 0x08, 0x8E);
  idt_set_gate(4, (uint64_t)isr4, 0x08, 0x8E);
  idt_set_gate(5, (uint64_t)isr5, 0x08, 0x8E);
  idt_set_gate(6, (uint64_t)isr6, 0x08, 0x8E);
  idt_set_gate(7, (uint64_t)isr7, 0x08, 0x8E);
  idt_set_gate(8, (uint64_t)isr8, 0x08, 0x8E);
  idt_set_gate(9, (uint64_t)isr9, 0x08, 0x8E);
  idt_set_gate(10, (uint64_t)isr10, 0x08, 0x8E);
  idt_set_gate(11, (uint64_t)isr11, 0x08, 0x8E);
  idt_set_gate(12, (uint64_t)isr12, 0x08, 0x8E);
  idt_set_gate(13, (uint64_t)isr13, 0x08, 0x8E);
  idt_set_gate(14, (uint64_t)isr14, 0x08, 0x8E);
  idt_set_gate(15, (uint64_t)isr15, 0x08, 0x8E);
  idt_set_gate(16, (uint64_t)isr16, 0x08, 0x8E);
  idt_set_gate(17, (uint64_t)isr17, 0x08, 0x8E);
  idt_set_gate(18, (uint64_t)isr18, 0x08, 0x8E);
  idt_set_gate(19, (uint64_t)isr19, 0x08, 0x8E);
  idt_set_gate(20, (uint64_t)isr20, 0x08, 0x8E);
  idt_set_gate(21, (uint64_t)isr21, 0x08, 0x8E);
  idt_set_gate(22, (uint64_t)isr22, 0x08, 0x8E);
  idt_set_gate(23, (uint64_t)isr23, 0x08, 0x8E);
  idt_set_gate(24, (uint64_t)isr24, 0x08, 0x8E);
  idt_set_gate(25, (uint64_t)isr25, 0x08, 0x8E);
  idt_set_gate(26, (uint64_t)isr26, 0x08, 0x8E);
  idt_set_gate(27, (uint64_t)isr27, 0x08, 0x8E);
  idt_set_gate(28, (uint64_t)isr28, 0x08, 0x8E);
  idt_set_gate(29, (uint64_t)isr29, 0x08, 0x8E);
  idt_set_gate(30, (uint64_t)isr30, 0x08, 0x8E);
  idt_set_gate(31, (uint64_t)isr31, 0x08, 0x8E);

  idt_set_gate(32, (uint64_t)isr32, 0x08, 0x8E);
  idt_set_gate(33, (uint64_t)isr33, 0x08, 0x8E);
  idt_set_gate(34, (uint64_t)isr34, 0x08, 0x8E);
  idt_set_gate(35, (uint64_t)isr35, 0x08, 0x8E);
  idt_set_gate(36, (uint64_t)isr36, 0x08, 0x8E);
  idt_set_gate(37, (uint64_t)isr37, 0x08, 0x8E);
  idt_set_gate(38, (uint64_t)isr38, 0x08, 0x8E);
  idt_set_gate(39, (uint64_t)isr39, 0x08, 0x8E);
  idt_set_gate(40, (uint64_t)isr40, 0x08, 0x8E);
  idt_set_gate(41, (uint64_t)isr41, 0x08, 0x8E);
  idt_set_gate(42, (uint64_t)isr42, 0x08, 0x8E);
  idt_set_gate(43, (uint64_t)isr43, 0x08, 0x8E);
  idt_set_gate(44, (uint64_t)isr44, 0x08, 0x8E);
  idt_set_gate(45, (uint64_t)isr45, 0x08, 0x8E);
  idt_set_gate(46, (uint64_t)isr46, 0x08, 0x8E);
  idt_set_gate(47, (uint64_t)isr47, 0x08, 0x8E);
  idt_set_gate(LAPIC_TIMER_VECTOR, (uint64_t)isr64, 0x08, 0x8E);

  load_idt();

  kprint("IDT initialized\n");
}

void idt_reload(void) { load_idt(); }
