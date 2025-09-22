#include "smp.h"
#include "console.h"
#include "gdt.h"
#include "idt.h"
#include "libc.h"
#include "limine_requests.h"
#include "pmm.h"
#include "process.h"
#include "sync.h"
#include "vmm.h"
#include <limine.h>
#include <stddef.h>
#include <stdint.h>

#define IA32_APIC_BASE 0x1B
#define IA32_GS_BASE 0xC0000101
#define IA32_KERNEL_GS_BASE 0xC0000102

#define LAPIC_REG_ID 0x020
#define LAPIC_REG_EOI 0x0B0
#define LAPIC_REG_SVR 0x0F0
#define LAPIC_REG_TPR 0x080
#define LAPIC_REG_TIMER_DIV 0x3E0
#define LAPIC_REG_TIMER_INIT 0x380
#define LAPIC_REG_TIMER_CUR 0x390
#define LAPIC_REG_LVT_TIMER 0x320

#define LAPIC_ENABLE 0x100
#define LAPIC_TIMER_PERIODIC 0x20000
#define LAPIC_TIMER_DIVIDE 0x3
#define LAPIC_TIMER_INITIAL 0x20000

static cpu_local_t cpu_locals[SMP_MAX_CPUS] = {{0}};
static cpu_local_t *lapic_id_map[256] = {0};
static uint32_t cpu_count = 1;
static bool smp_enabled = false;
static bool smp_initialized = false;
static bool smp_bootstrap_started = false;

static volatile uint32_t ap_online_count = 1;
static volatile uint32_t ap_ready_count = 0;

static uint64_t hhdm_offset = 0;
static volatile uint32_t *lapic_base = NULL;

static inline uint64_t rdmsr(uint32_t msr) {
  uint32_t low, high;
  __asm__ volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(msr));
  return ((uint64_t)high << 32) | low;
}

static inline void wrmsr(uint32_t msr, uint64_t value) {
  uint32_t low = (uint32_t)(value & 0xFFFFFFFF);
  uint32_t high = (uint32_t)(value >> 32);
  __asm__ volatile("wrmsr" : : "c"(msr), "a"(low), "d"(high));
}

static inline void cpu_pause(void) { __asm__ volatile("pause" ::: "memory"); }

static inline uint64_t virt_to_phys(uint64_t addr) {
  if (hhdm_offset && addr >= hhdm_offset) {
    return addr - hhdm_offset;
  }
  return addr;
}

static void smp_set_gs_base(cpu_local_t *cpu) {
  wrmsr(IA32_GS_BASE, (uint64_t)(uintptr_t)cpu);
  wrmsr(IA32_KERNEL_GS_BASE, (uint64_t)(uintptr_t)cpu);
}

static inline volatile uint32_t *lapic_addr(uint32_t reg) {
  return (volatile uint32_t *)((uintptr_t)lapic_base + reg);
}

static inline void lapic_write(uint32_t reg, uint32_t value) {
  if (!lapic_base)
    return;
  *lapic_addr(reg) = value;
  (void)*lapic_addr(reg);
}

static inline uint32_t lapic_read(uint32_t reg) {
  if (!lapic_base)
    return 0;
  return *lapic_addr(reg);
}

static void lapic_setup_base(void) {
  if (lapic_base == NULL) {
    if (hhdm_request.response != NULL) {
      hhdm_offset = hhdm_request.response->offset;
    }

    uint64_t apic_msr = rdmsr(IA32_APIC_BASE);
    apic_msr |= (1ULL << 11);
    wrmsr(IA32_APIC_BASE, apic_msr);

    uint64_t lapic_phys = apic_msr & 0xFFFFF000ULL;
    uint64_t lapic_virt = lapic_phys + hhdm_offset;

    page_table_t *kernel_map = vmm_get_kernel_pagemap();
    vmm_map_page(kernel_map, lapic_virt, lapic_phys,
                 VMM_WRITABLE | VMM_CACHE_DISABLE | VMM_GLOBAL);

    lapic_base = (volatile uint32_t *)lapic_virt;
  }

  lapic_write(LAPIC_REG_SVR, LAPIC_ENABLE | 0xFF);
  lapic_write(LAPIC_REG_TPR, 0);
}

static void lapic_configure_timer(void) {
  if (!lapic_base)
    return;

  lapic_write(LAPIC_REG_TIMER_DIV, LAPIC_TIMER_DIVIDE);
  lapic_write(LAPIC_REG_LVT_TIMER, LAPIC_TIMER_VECTOR | LAPIC_TIMER_PERIODIC);
  lapic_write(LAPIC_REG_TIMER_INIT, LAPIC_TIMER_INITIAL);
}

void smp_start_lapic_timer(void) { lapic_configure_timer(); }

static void lapic_eoi(void) { lapic_write(LAPIC_REG_EOI, 0); }

cpu_local_t *smp_get_cpu_local_by_index(uint32_t cpu_id) {
  if (cpu_id >= SMP_MAX_CPUS) {
    return NULL;
  }
  return &cpu_locals[cpu_id];
}

cpu_local_t *smp_get_cpu_local(void) {
  uint64_t gs_base = rdmsr(IA32_GS_BASE);
  if (gs_base == 0) {
    gs_base = rdmsr(IA32_KERNEL_GS_BASE);
  }

  if (gs_base != 0) {
    return (cpu_local_t *)(uintptr_t)gs_base;
  }

  if (lapic_base != NULL) {
    uint32_t lapic_id_reg = lapic_read(LAPIC_REG_ID);
    uint32_t lapic_id = (lapic_id_reg >> 24) & 0xFF;
    if (lapic_id < 256 && lapic_id_map[lapic_id] != NULL) {
      return lapic_id_map[lapic_id];
    }
  }

  return &cpu_locals[0];
}

uint32_t smp_get_cpu_id(void) { return smp_get_cpu_local()->cpu_id; }

uint32_t smp_get_cpu_count(void) { return cpu_count; }

bool smp_is_active(void) { return smp_enabled; }

void smp_set_current_process(struct process *process) {
  cpu_local_t *cpu = smp_get_cpu_local();
  cpu->current_process = process;
}

void smp_set_idle_process(uint32_t cpu_id, struct process *process) {
  cpu_local_t *cpu = smp_get_cpu_local_by_index(cpu_id);
  if (cpu) {
    cpu->idle_process = process;
  }
}

static void smp_log_cpu_count(uint32_t count) {
  kprint("SMP: CPUs online: ");
  kprint_hex(count);
  kprint("\n");
}

static void smp_register_boot_cpu(void) {
  cpu_local_t *cpu0 = &cpu_locals[0];
  memset(cpu0, 0, sizeof(cpu_local_t));
  cpu0->cpu_id = 0;
  cpu0->online = true;
  cpu0->ready = true;
  cpu0->start_requested = true;
  smp_set_gs_base(cpu0);
  lapic_setup_base();
}

static void smp_mark_cpu_online(cpu_local_t *cpu) {
  if (!cpu)
    return;
  cpu->online = true;
  __atomic_fetch_add(&ap_online_count, 1, __ATOMIC_SEQ_CST);
}

static void smp_wait_for_ap_startup(uint32_t target) {
  while (__atomic_load_n(&ap_online_count, __ATOMIC_SEQ_CST) < target) {
    cpu_pause();
  }
}

static void smp_setup_cpu_descriptor(cpu_local_t *cpu, uint32_t cpu_id,
                                     uint32_t lapic_id) {
  memset(cpu, 0, sizeof(cpu_local_t));
  cpu->cpu_id = cpu_id;
  cpu->lapic_id = lapic_id;
  cpu->online = false;
  cpu->ready = false;
  cpu->start_requested = false;
}

static void smp_wait_for_ap_ready(uint32_t target) {
  while (__atomic_load_n(&ap_ready_count, __ATOMIC_SEQ_CST) < target) {
    cpu_pause();
  }
}

static void smp_ap_entry(struct LIMINE_MP(info) * info);

void smp_init(void) {
  if (smp_initialized || smp_bootstrap_started) {
    return;
  }
  smp_bootstrap_started = true;

  memset(lapic_id_map, 0, sizeof(lapic_id_map));
  memset(cpu_locals, 0, sizeof(cpu_locals));

  if (hhdm_request.response != NULL) {
    hhdm_offset = hhdm_request.response->offset;
  }

  smp_register_boot_cpu();
  process_t *bootstrap_proc = process_get_current();
  if (bootstrap_proc) {
    smp_set_idle_process(0, bootstrap_proc);
    smp_set_current_process(bootstrap_proc);
  }
  struct LIMINE_MP(response) *resp = smp_request.response;
  kprint("SMP response at 0x");
  kprint_hex((uint64_t)resp);
  kprint("\n");
  if (resp == NULL || resp->cpu_count <= 1) {
    cpu_count = 1;
    smp_enabled = false;
    smp_log_cpu_count(cpu_count);
    return;
  }

  uint32_t configured = 1;

  if (resp != NULL) {
    pmm_mark_used_range(virt_to_phys((uint64_t)resp), sizeof(*resp));
    if (resp->cpus != NULL) {
      size_t ptr_array_size =
          resp->cpu_count * sizeof(struct LIMINE_MP(info) *);
      pmm_mark_used_range(virt_to_phys((uint64_t)resp->cpus), ptr_array_size);
    }
  }

  for (uint32_t i = 0; i < resp->cpu_count; i++) {
    struct LIMINE_MP(info) *info = resp->cpus[i];
    kprint("CPU info ptr 0x");
    kprint_hex((uint64_t)info);
    kprint("\n");
    if (info) {
      pmm_mark_used_range(virt_to_phys((uint64_t)info), sizeof(*info));
    }
    if (info->lapic_id == resp->bsp_lapic_id) {
      cpu_locals[0].lapic_id = info->lapic_id;
      info->extra_argument = (uint64_t)(uintptr_t)&cpu_locals[0];
      lapic_id_map[info->lapic_id & 0xFF] = &cpu_locals[0];
      break;
    }
  }

  for (uint32_t i = 0; i < resp->cpu_count && configured < SMP_MAX_CPUS; i++) {
    struct LIMINE_MP(info) *info = resp->cpus[i];
    if (info->lapic_id == resp->bsp_lapic_id) {
      continue;
    }

    cpu_local_t *cpu = &cpu_locals[configured];
    smp_setup_cpu_descriptor(cpu, configured, info->lapic_id);
    info->extra_argument = (uint64_t)(uintptr_t)cpu;
    lapic_id_map[info->lapic_id & 0xFF] = cpu;
    configured++;
  }

  cpu_count = configured;
  smp_enabled = (cpu_count > 1);
  smp_log_cpu_count(cpu_count);

  if (!smp_enabled) {
    smp_initialized = true;
    smp_bootstrap_started = false;
    return;
  }

  ap_ready_count = 0;

  for (uint32_t i = 0; i < resp->cpu_count; i++) {
    struct LIMINE_MP(info) *info = resp->cpus[i];
    cpu_local_t *cpu = (cpu_local_t *)(uintptr_t)info->extra_argument;
    if (!cpu || cpu->cpu_id == 0) {
      continue;
    }
    if (cpu->cpu_id >= cpu_count) {
      continue;
    }
    info->goto_address = smp_ap_entry;
  }

  smp_bootstrap_started = false;
}

void smp_resume_secondary_cpus(void) {
  if (smp_initialized) {
    return;
  }

  if (!smp_enabled) {
    smp_initialized = true;
    return;
  }

  uint32_t expected_ready = cpu_count > 0 ? (cpu_count - 1) : 0;
  if (expected_ready > 0) {
    smp_wait_for_ap_ready(expected_ready);
  }

  ap_online_count = 1;

  for (uint32_t i = 1; i < cpu_count; i++) {
    cpu_local_t *cpu = &cpu_locals[i];
    __atomic_store_n(&cpu->start_requested, true, __ATOMIC_RELEASE);
  }

  smp_wait_for_ap_startup(cpu_count);
  kprint("SMP: Secondary CPUs initialised\n");

  smp_initialized = true;
}

static void smp_ap_entry(struct LIMINE_MP(info) * info) {
  cpu_local_t *cpu = (cpu_local_t *)(uintptr_t)info->extra_argument;
  if (!cpu) {
    for (;;) {
      asm volatile("hlt");
    }
  }

  smp_set_gs_base(cpu);
  gdt_init_ap(cpu->cpu_id);
  idt_reload();
  lapic_setup_base();

  cpu->ready = true;
  __atomic_fetch_add(&ap_ready_count, 1, __ATOMIC_SEQ_CST);

  while (!__atomic_load_n(&cpu->start_requested, __ATOMIC_ACQUIRE)) {
    cpu_pause();
  }

  process_init_ap(cpu->cpu_id);
  if (cpu->idle_process == NULL) {
    kprint("SMP: Failed to initialise idle process for CPU ");
    kprint_hex(cpu->cpu_id);
    kprint("\n");
    for (;;) {
      asm volatile("cli; hlt");
    }
  }

  smp_set_current_process(cpu->idle_process);
  smp_mark_cpu_online(cpu);

  smp_start_lapic_timer();

  asm volatile("sti");
  context_switch(NULL, &cpu->idle_process->context);

  for (;;) {
    asm volatile("hlt");
  }
}

void smp_handle_apic_timer(struct interrupt_frame *frame) {
  (void)frame;
  lapic_eoi();
  smp_get_cpu_local()->scheduler_ticks++;
  scheduler_tick();
}
