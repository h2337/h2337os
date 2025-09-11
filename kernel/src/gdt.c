#include "gdt.h"
#include "console.h"

static struct gdt_entry gdt[5];
static struct gdt_ptr gdtr;

static void gdt_set_gate(int32_t num, uint32_t base, uint32_t limit,
                         uint8_t access, uint8_t gran) {
  gdt[num].base_low = (base & 0xFFFF);
  gdt[num].base_middle = (base >> 16) & 0xFF;
  gdt[num].base_high = (base >> 24) & 0xFF;

  gdt[num].limit_low = (limit & 0xFFFF);
  gdt[num].granularity = (limit >> 16) & 0x0F;

  gdt[num].granularity |= gran & 0xF0;
  gdt[num].access = access;
}

void gdt_init(void) {
  gdtr.limit = (sizeof(struct gdt_entry) * 5) - 1;
  gdtr.base = (uint64_t)&gdt;

  gdt_set_gate(0, 0, 0, 0, 0);
  gdt_set_gate(1, 0, 0xFFFFF, 0x9A, 0xAF);
  gdt_set_gate(2, 0, 0xFFFFF, 0x92, 0xCF);
  gdt_set_gate(3, 0, 0xFFFFF, 0xFA, 0xAF);
  gdt_set_gate(4, 0, 0xFFFFF, 0xF2, 0xCF);

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

  kprint("GDT initialized\n");
}