#include "gdt.h"
#include "console.h"
#include "libc.h"
#include "smp.h"
#include <stddef.h>

#define GDT_ENTRIES 7
static struct gdt_entry gdt_tables[SMP_MAX_CPUS][GDT_ENTRIES];
static struct gdt_ptr gdt_descriptors[SMP_MAX_CPUS];
static struct tss tss_tables[SMP_MAX_CPUS];
static uint64_t kernel_stacks[SMP_MAX_CPUS][8192];

static void gdt_set_gate(struct gdt_entry *table, int32_t num, uint64_t base,
                         uint32_t limit, uint8_t access, uint8_t flags) {
  table[num].base_low = (base & 0xFFFF);
  table[num].base_middle = (base >> 16) & 0xFF;
  table[num].base_high = (base >> 24) & 0xFF;

  table[num].limit_low = (limit & 0xFFFF);
  table[num].granularity = ((limit >> 16) & 0x0F) | (flags & 0xF0);
  table[num].access = access;
}

static void gdt_set_tss(struct gdt_entry *table, int32_t num, uint64_t base,
                        uint32_t limit, uint8_t access, uint8_t flags) {
  struct gdt_entry64 *tss_entry = (struct gdt_entry64 *)&table[num];

  tss_entry->limit_low = limit & 0xFFFF;
  tss_entry->base_low = base & 0xFFFF;
  tss_entry->base_middle = (base >> 16) & 0xFF;
  tss_entry->access = access;
  tss_entry->limit_high_flags = ((limit >> 16) & 0x0F) | (flags & 0xF0);
  tss_entry->base_high = (base >> 24) & 0xFF;
  tss_entry->base_upper = (base >> 32) & 0xFFFFFFFF;
  tss_entry->reserved = 0;
}

static void gdt_load_for_cpu(uint32_t cpu_id) {
  if (cpu_id >= SMP_MAX_CPUS) {
    return;
  }

  struct gdt_entry *table = gdt_tables[cpu_id];
  struct gdt_ptr *descriptor = &gdt_descriptors[cpu_id];
  struct tss *tss = &tss_tables[cpu_id];

  memset(table, 0, sizeof(struct gdt_entry) * GDT_ENTRIES);
  descriptor->limit = (sizeof(struct gdt_entry) * GDT_ENTRIES) - 1;
  descriptor->base = (uint64_t)table;

  gdt_set_gate(table, 0, 0, 0, 0, 0);
  gdt_set_gate(table, 1, 0, 0xFFFFF, 0x9A, 0xAF);
  gdt_set_gate(table, 2, 0, 0xFFFFF, 0x92, 0xCF);
  gdt_set_gate(table, 3, 0, 0xFFFFF, 0xFA, 0xAF);
  gdt_set_gate(table, 4, 0, 0xFFFFF, 0xF2, 0xCF);

  memset(tss, 0, sizeof(struct tss));
  tss->rsp0 = (uint64_t)&kernel_stacks[cpu_id][8191];
  tss->iopb_offset = sizeof(struct tss);

  gdt_set_tss(table, 5, (uint64_t)tss, sizeof(struct tss) - 1, 0x89, 0x00);

  asm volatile("lgdt %0" : : "m"(*descriptor));

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

  if (cpu_id == 0) {
    kprint("GDT and TSS initialized\n");
  }
}

void gdt_init(void) { gdt_load_for_cpu(0); }

void gdt_init_ap(uint32_t cpu_id) { gdt_load_for_cpu(cpu_id); }

void tss_set_kernel_stack(uint32_t cpu_id, uint64_t stack) {
  if (cpu_id >= SMP_MAX_CPUS) {
    return;
  }
  tss_tables[cpu_id].rsp0 = stack;
}
