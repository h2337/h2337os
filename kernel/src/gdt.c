#include "gdt.h"
#include "console.h"
#include <stddef.h>

#define GDT_ENTRIES 7

static struct gdt_entry gdt[GDT_ENTRIES];
static struct gdt_ptr gdtr;
static struct tss tss;
static uint64_t kernel_stack[8192];

static void gdt_set_gate(int32_t num, uint64_t base, uint32_t limit,
                         uint8_t access, uint8_t flags) {
  gdt[num].base_low = (base & 0xFFFF);
  gdt[num].base_middle = (base >> 16) & 0xFF;
  gdt[num].base_high = (base >> 24) & 0xFF;

  gdt[num].limit_low = (limit & 0xFFFF);
  gdt[num].granularity = ((limit >> 16) & 0x0F) | (flags & 0xF0);
  gdt[num].access = access;
}

static void gdt_set_tss(int32_t num, uint64_t base, uint32_t limit,
                        uint8_t access, uint8_t flags) {
  struct gdt_entry64 *tss_entry = (struct gdt_entry64 *)&gdt[num];

  tss_entry->limit_low = limit & 0xFFFF;
  tss_entry->base_low = base & 0xFFFF;
  tss_entry->base_middle = (base >> 16) & 0xFF;
  tss_entry->access = access;
  tss_entry->limit_high_flags = ((limit >> 16) & 0x0F) | (flags & 0xF0);
  tss_entry->base_high = (base >> 24) & 0xFF;
  tss_entry->base_upper = (base >> 32) & 0xFFFFFFFF;
  tss_entry->reserved = 0;
}

void tss_set_kernel_stack(uint64_t stack) { tss.rsp0 = stack; }

void gdt_init(void) {
  gdtr.limit = (sizeof(struct gdt_entry) * GDT_ENTRIES) - 1;
  gdtr.base = (uint64_t)&gdt;

  gdt_set_gate(0, 0, 0, 0, 0);
  gdt_set_gate(1, 0, 0xFFFFF, 0x9A, 0xAF);
  gdt_set_gate(2, 0, 0xFFFFF, 0x92, 0xCF);
  gdt_set_gate(3, 0, 0xFFFFF, 0xFA, 0xAF);
  gdt_set_gate(4, 0, 0xFFFFF, 0xF2, 0xCF);

  for (size_t i = 0; i < sizeof(tss); i++) {
    ((uint8_t *)&tss)[i] = 0;
  }

  tss.rsp0 = (uint64_t)&kernel_stack[8191];
  tss.iopb_offset = sizeof(tss);

  gdt_set_tss(5, (uint64_t)&tss, sizeof(tss) - 1, 0x89, 0x00);

  asm volatile("lgdt %0" : : "m"(gdtr));

  asm volatile("mov $0x10, %%ax\n"
               "mov %%ax, %%ds\n"
               "mov %%ax, %%es\n"
               "mov %%ax, %%fs\n"
               "mov %%ax, %%gs\n"
               "mov %%ax, %%ss\n"
               "push $0x08\n"
               "lea 1f(%%rip), %%rax\n"
               "push %%rax\n"
               "lretq\n"
               "1:\n"
               :
               :
               : "rax", "memory");

  asm volatile("mov $0x2B, %%ax\n"
               "ltr %%ax\n"
               :
               :
               : "ax");

  kprint("GDT and TSS initialized\n");
}