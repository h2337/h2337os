#include "process.h"
#include "console.h"
#include "heap.h"
#include "libc.h"
#include "pit.h"
#include "pmm.h"
#include "smp.h"
#include "sync.h"
#include "types.h"
#include "vfs.h"
#include "vmm.h"
#include <stddef.h>
#include <stdint.h>

#define IDLE_PID_BASE 0xFFFF0000U
#define PROCESS_DEFAULT_MMAP_BASE 0x2000000000ULL

static process_t *process_list_head = NULL;
static process_t *current_processes[SMP_MAX_CPUS] = {0};
static process_t *idle_processes[SMP_MAX_CPUS] = {0};
static uint32_t next_pid = 1;
static uint32_t process_count = 0;
static int scheduler_enabled = 0;

static spinlock_t process_list_lock = SPINLOCK_INIT("process_list");
static spinlock_t pid_counter_lock = SPINLOCK_INIT("pid_counter");
static spinlock_t scheduler_lock = SPINLOCK_INIT("scheduler");

typedef struct run_queue {
  spinlock_t lock;
  process_t *heads[PROCESS_PRIORITY_COUNT];
  process_t *tails[PROCESS_PRIORITY_COUNT];
  size_t load;
} run_queue_t;

static run_queue_t cpu_run_queues[SMP_MAX_CPUS];

#define SCHEDULER_BALANCE_INTERVAL 64

static inline bool is_idle_process(process_t *process);
static inline bool scheduler_cpu_online(uint32_t cpu_id);
static inline uint32_t current_cpu_index(void);

static inline int clamp_priority(int priority) {
  if (priority < PROCESS_PRIORITY_HIGH) {
    return PROCESS_PRIORITY_HIGH;
  }
  if (priority > PROCESS_PRIORITY_LOW) {
    return PROCESS_PRIORITY_LOW;
  }
  return priority;
}

static inline uint64_t priority_time_slice(int priority) {
  priority = clamp_priority(priority);
  switch (priority) {
  case PROCESS_PRIORITY_HIGH: {
    uint64_t slice = DEFAULT_TIME_SLICE / 2;
    return slice > 0 ? slice : 1;
  }
  case PROCESS_PRIORITY_LOW:
    return DEFAULT_TIME_SLICE * 2;
  default:
    return DEFAULT_TIME_SLICE;
  }
}

static inline bool process_has_affinity(process_t *proc, uint32_t cpu_id) {
  if (!proc) {
    return false;
  }
  if (proc->affinity_mask == PROCESS_AFFINITY_ALL) {
    return true;
  }
  if (cpu_id >= 32) {
    return false;
  }
  return (proc->affinity_mask & (1u << cpu_id)) != 0;
}

static inline bool scheduler_cpu_online(uint32_t cpu_id) {
  cpu_local_t *local = smp_get_cpu_local_by_index(cpu_id);
  return local && local->online;
}

static void run_queue_init(run_queue_t *rq) {
  spinlock_init(&rq->lock, "run_queue");
  memset(rq->heads, 0, sizeof(rq->heads));
  memset(rq->tails, 0, sizeof(rq->tails));
  rq->load = 0;
}

static void run_queue_insert_locked(run_queue_t *rq, process_t *proc,
                                    bool front) {
  int priority = clamp_priority(proc->priority);
  if (proc->on_run_queue) {
    return;
  }

  process_t **head = &rq->heads[priority];
  process_t **tail = &rq->tails[priority];

  proc->run_next = NULL;
  proc->run_prev = NULL;

  if (front) {
    if (*head) {
      proc->run_next = *head;
      (*head)->run_prev = proc;
    } else {
      *tail = proc;
    }
    *head = proc;
  } else {
    if (*tail) {
      (*tail)->run_next = proc;
      proc->run_prev = *tail;
    } else {
      *head = proc;
    }
    *tail = proc;
  }

  proc->on_run_queue = true;
  rq->load++;
}

static void run_queue_remove_locked(run_queue_t *rq, process_t *proc) {
  if (!proc || !proc->on_run_queue) {
    return;
  }

  int priority = clamp_priority(proc->priority);
  process_t **head = &rq->heads[priority];
  process_t **tail = &rq->tails[priority];

  if (proc->run_prev) {
    proc->run_prev->run_next = proc->run_next;
  }
  if (proc->run_next) {
    proc->run_next->run_prev = proc->run_prev;
  }
  if (*head == proc) {
    *head = proc->run_next;
  }
  if (*tail == proc) {
    *tail = proc->run_prev;
  }

  proc->run_next = NULL;
  proc->run_prev = NULL;
  proc->on_run_queue = false;
  if (rq->load > 0) {
    rq->load--;
  }
}

static process_t *run_queue_select_locked(run_queue_t *rq) {
  for (int prio = PROCESS_PRIORITY_HIGH; prio <= PROCESS_PRIORITY_LOW; ++prio) {
    process_t *node = rq->heads[prio];
    while (node && node->state != PROCESS_STATE_READY) {
      // Skip stale entries that might still be marked ready elsewhere
      process_t *next = node->run_next;
      run_queue_remove_locked(rq, node);
      node = next;
    }
    if (node) {
      run_queue_remove_locked(rq, node);
      return node;
    }
  }
  return NULL;
}

static process_t *run_queue_steal_locked(run_queue_t *rq, uint32_t target_cpu) {
  for (int prio = PROCESS_PRIORITY_LOW; prio >= PROCESS_PRIORITY_HIGH; --prio) {
    process_t *node = rq->tails[prio];
    while (node) {
      process_t *prev = node->run_prev;
      if (node->state == PROCESS_STATE_READY &&
          process_has_affinity(node, target_cpu)) {
        run_queue_remove_locked(rq, node);
        return node;
      }
      node = prev;
    }
  }
  return NULL;
}

static void scheduler_trigger_balance(uint32_t cpu_id);

static uint32_t scheduler_select_cpu(process_t *proc, uint32_t preferred_cpu) {
  uint32_t cpu_count = smp_get_cpu_count();
  if (cpu_count == 0) {
    cpu_count = 1;
  }
  if (cpu_count > SMP_MAX_CPUS) {
    cpu_count = SMP_MAX_CPUS;
  }

  if (preferred_cpu < cpu_count && scheduler_cpu_online(preferred_cpu) &&
      process_has_affinity(proc, preferred_cpu)) {
    return preferred_cpu;
  }

  uint32_t best_cpu = SMP_MAX_CPUS;
  size_t best_load = (size_t)-1;

  for (uint32_t cpu = 0; cpu < cpu_count; ++cpu) {
    if (!scheduler_cpu_online(cpu) || !process_has_affinity(proc, cpu)) {
      continue;
    }

    size_t load = __atomic_load_n(&cpu_run_queues[cpu].load, __ATOMIC_RELAXED);
    if (best_cpu == SMP_MAX_CPUS || load < best_load ||
        (load == best_load && cpu == preferred_cpu)) {
      best_cpu = cpu;
      best_load = load;
    }
  }

  if (best_cpu != SMP_MAX_CPUS) {
    return best_cpu;
  }

  uint32_t current_cpu = current_cpu_index();
  if (scheduler_cpu_online(current_cpu) &&
      process_has_affinity(proc, current_cpu)) {
    return current_cpu;
  }

  return 0;
}

static void scheduler_enqueue_process(process_t *proc, uint32_t preferred_cpu,
                                      bool front) {
  if (!proc || is_idle_process(proc)) {
    return;
  }

  uint32_t target_cpu = scheduler_select_cpu(proc, preferred_cpu);
  if (target_cpu >= SMP_MAX_CPUS) {
    target_cpu = target_cpu % SMP_MAX_CPUS;
  }

  if (!scheduler_cpu_online(target_cpu) ||
      !process_has_affinity(proc, target_cpu)) {
    uint32_t fallback = current_cpu_index();
    if (!scheduler_cpu_online(fallback) ||
        !process_has_affinity(proc, fallback)) {
      fallback = 0;
    }
    target_cpu = fallback % SMP_MAX_CPUS;
  }

  run_queue_t *rq = &cpu_run_queues[target_cpu];
  irq_state_t flags = spin_lock_irqsave(&rq->lock);
  proc->last_cpu = target_cpu;
  proc->time_slice = priority_time_slice(proc->priority);
  proc->ticks_remaining = proc->time_slice;
  run_queue_insert_locked(rq, proc, front);
  spin_unlock_irqrestore(&rq->lock, flags);
}

static void scheduler_remove_from_queue(process_t *proc) {
  if (!proc || !proc->on_run_queue) {
    return;
  }

  uint32_t cpu = proc->last_cpu;
  if (cpu >= SMP_MAX_CPUS) {
    cpu = cpu % SMP_MAX_CPUS;
  }

  run_queue_t *rq = &cpu_run_queues[cpu];
  irq_state_t flags = spin_lock_irqsave(&rq->lock);
  run_queue_remove_locked(rq, proc);
  spin_unlock_irqrestore(&rq->lock, flags);
}

extern void context_switch(context_t *old, context_t *new);

static void idle_task(void) {
  while (1) {
    asm volatile("hlt");
  }
}

static inline uint32_t current_cpu_index(void) { return smp_get_cpu_id(); }

static inline bool is_idle_process(process_t *process) {
  for (uint32_t i = 0; i < SMP_MAX_CPUS; i++) {
    if (idle_processes[i] == process) {
      return true;
    }
  }
  return false;
}

static inline uint64_t align_down(uint64_t value, uint64_t align) {
  return value & ~(align - 1);
}

static inline uint64_t align_up(uint64_t value, uint64_t align) {
  return (value + align - 1) & ~(align - 1);
}

static bool vm_region_conflicts(vm_region_t *head, uint64_t start,
                                uint64_t end) {
  vm_region_t *region = head;
  while (region) {
    if (!(end <= region->start || start >= region->end)) {
      return true;
    }
    region = region->next;
  }
  return false;
}

static vm_region_t *vm_region_clone_list(vm_region_t *head) {
  vm_region_t *new_head = NULL;
  vm_region_t **tail = &new_head;

  while (head) {
    vm_region_t *node = kmalloc(sizeof(vm_region_t));
    if (!node) {
      vm_region_t *iter = new_head;
      while (iter) {
        vm_region_t *next = iter->next;
        kfree(iter);
        iter = next;
      }
      return NULL;
    }

    *node = *head;
    node->next = NULL;
    *tail = node;
    tail = &node->next;
    head = head->next;
  }

  return new_head;
}

static void vm_region_free_list(vm_region_t *head) {
  while (head) {
    vm_region_t *next = head->next;
    kfree(head);
    head = next;
  }
}

uint64_t process_vm_reserve_addr(process_t *proc, size_t length) {
  if (!proc) {
    return 0;
  }

  uint64_t aligned_length = align_up((uint64_t)length, PAGE_SIZE);
  if (aligned_length == 0) {
    aligned_length = PAGE_SIZE;
  }

  uint64_t base = align_up(proc->mmap_base, PAGE_SIZE);
  uint64_t end = base + aligned_length;

  if (end < base || end >= 0x0000800000000000ULL) {
    return 0;
  }

  proc->mmap_base = end;
  return base;
}

vm_region_t *process_vm_add_region(process_t *proc, uint64_t start,
                                   uint64_t length, int prot, int flags, int fd,
                                   off_t offset) {
  if (!proc || length == 0) {
    return NULL;
  }

  uint64_t aligned_start = align_down(start, PAGE_SIZE);
  uint64_t aligned_length = align_up(length, PAGE_SIZE);
  uint64_t aligned_end = aligned_start + aligned_length;

  if (aligned_end <= aligned_start) {
    return NULL;
  }

  if (vm_region_conflicts(proc->vm_regions, aligned_start, aligned_end)) {
    return NULL;
  }

  vm_region_t *region = kmalloc(sizeof(vm_region_t));
  if (!region) {
    return NULL;
  }

  region->start = aligned_start;
  region->end = aligned_end;
  region->flags = 0;
  region->prot = prot;
  region->map_flags = flags;
  region->fd = fd;
  region->offset = offset;
  region->next = proc->vm_regions;
  proc->vm_regions = region;
  return region;
}

vm_region_t *process_vm_find_region(process_t *proc, uint64_t addr) {
  if (!proc) {
    return NULL;
  }

  uint64_t aligned_addr = align_down(addr, PAGE_SIZE);
  vm_region_t *region = proc->vm_regions;
  while (region) {
    if (aligned_addr >= region->start && aligned_addr < region->end) {
      return region;
    }
    region = region->next;
  }
  return NULL;
}

int process_vm_remove_region(process_t *proc, uint64_t start, uint64_t length) {
  if (!proc || length == 0) {
    return -1;
  }

  uint64_t aligned_start = align_down(start, PAGE_SIZE);
  uint64_t aligned_length = align_up(length, PAGE_SIZE);
  uint64_t aligned_end = aligned_start + aligned_length;

  vm_region_t *prev = NULL;
  vm_region_t *region = proc->vm_regions;

  while (region) {
    if (region->start == aligned_start && region->end == aligned_end) {
      if (prev) {
        prev->next = region->next;
      } else {
        proc->vm_regions = region->next;
      }
      kfree(region);
      return 0;
    }
    prev = region;
    region = region->next;
  }

  return -1;
}

void process_vm_unmap_range(process_t *proc, uint64_t start, uint64_t length) {
  if (!proc || !proc->pagemap || length == 0) {
    return;
  }

  uint64_t aligned_start = align_down(start, PAGE_SIZE);
  uint64_t aligned_end = aligned_start + align_up(length, PAGE_SIZE);

  for (uint64_t addr = aligned_start; addr < aligned_end; addr += PAGE_SIZE) {
    uint64_t phys = vmm_get_phys(proc->pagemap, addr);
    if (phys) {
      if (vmm_unmap_page(proc->pagemap, addr)) {
        pmm_ref_dec(phys);
      }
    }
  }
}

void process_vm_clear_regions(process_t *proc) {
  if (!proc) {
    return;
  }

  vm_region_t *region = proc->vm_regions;
  while (region) {
    vm_region_t *next = region->next;
    kfree(region);
    region = next;
  }
  proc->vm_regions = NULL;
  proc->mmap_base = PROCESS_DEFAULT_MMAP_BASE;
}

static process_t *get_current_process_local(void) {
  return current_processes[current_cpu_index()];
}

static void set_current_process_local(process_t *process) {
  uint32_t cpu = current_cpu_index();
  current_processes[cpu] = process;
  smp_set_current_process(process);
}

static process_t *create_idle_process(uint32_t cpu_id) {
  process_t *idle = kmalloc(sizeof(process_t));
  if (!idle) {
    kprint("kmalloc idle failed\n");
    return NULL;
  }

  for (size_t i = 0; i < sizeof(process_t); i++) {
    ((uint8_t *)idle)[i] = 0;
  }
  idle->pid = (cpu_id == 0) ? 0 : (IDLE_PID_BASE + cpu_id);
  idle->ppid = 0;
  strcpy(idle->name, "idle");
  strcpy(idle->cwd, "/");
  idle->state = PROCESS_STATE_READY;
  idle->priority = PROCESS_PRIORITY_LOW;
  idle->affinity_mask = (cpu_id < 32) ? (1u << cpu_id) : PROCESS_AFFINITY_ALL;
  idle->last_cpu = cpu_id;
  idle->time_slice = priority_time_slice(idle->priority);
  idle->ticks_remaining = idle->time_slice;
  idle->sleep_until_tick = 0;
  idle->stack_size = KERNEL_STACK_SIZE;
  idle->stack = kmalloc(KERNEL_STACK_SIZE);
  if (!idle->stack) {
    kprint("Idle stack allocation failed for CPU ");
    kprint_hex(cpu_id);
    kprint("\n");
    kfree(idle);
    return NULL;
  }

  memset(idle->stack, 0, KERNEL_STACK_SIZE);
  uint64_t *stack_top =
      (uint64_t *)((uint8_t *)idle->stack + KERNEL_STACK_SIZE);
  memset(&idle->context, 0, sizeof(context_t));
  idle->context.rsp = (uint64_t)stack_top;
  idle->context.rip = (uint64_t)idle_task;
  idle->context.rflags = 0x202;
  idle->pagemap = vmm_get_kernel_pagemap();
  idle->owns_pagemap = false;
  idle->mmap_base = PROCESS_DEFAULT_MMAP_BASE;

  for (int i = 0; i < 256; i++) {
    idle->fd_table[i] = -1;
  }

  spin_lock(&process_list_lock);
  if (!process_list_head) {
    process_list_head = idle;
  } else {
    process_t *last = process_list_head;
    while (last->next) {
      last = last->next;
    }
    last->next = idle;
    idle->prev = last;
  }
  process_count++;
  spin_unlock(&process_list_lock);

  idle_processes[cpu_id] = idle;
  smp_set_idle_process(cpu_id, idle);
  return idle;
}

void process_init(void) {
  kprint("Initializing process management...\n");

  memset(current_processes, 0, sizeof(current_processes));
  memset(idle_processes, 0, sizeof(idle_processes));
  for (uint32_t i = 0; i < SMP_MAX_CPUS; ++i) {
    run_queue_init(&cpu_run_queues[i]);
  }

  process_t *idle0 = create_idle_process(0);
  if (!idle0) {
    kprint("Failed to allocate idle process\n");
    return;
  }

  idle0->state = PROCESS_STATE_RUNNING;
  idle0->ticks_remaining = idle0->time_slice;
  set_current_process_local(idle0);

  smp_start_lapic_timer();

  kprint("Process init complete\n");
  kprint("Process management initialized\n");
}

void process_init_ap(uint32_t cpu_id) {
  process_t *idle = create_idle_process(cpu_id);
  if (!idle) {
    kprint("Failed to allocate idle process for CPU ");
    kprint_hex(cpu_id);
    kprint("\n");
    return;
  }

  idle->state = PROCESS_STATE_RUNNING;
  idle->ticks_remaining = idle->time_slice;
  current_processes[cpu_id] = idle;
  smp_set_current_process(idle);
}

process_t *process_create(const char *name, void (*entry_point)(void)) {
  process_t *process = kmalloc(sizeof(process_t));
  if (!process) {
    return NULL;
  }

  memset(process, 0, sizeof(process_t));
  process->mmap_base = PROCESS_DEFAULT_MMAP_BASE;

  spin_lock(&pid_counter_lock);
  process->pid = next_pid++;
  spin_unlock(&pid_counter_lock);

  process_t *parent = get_current_process_local();
  process->ppid = parent ? parent->pid : 0;
  strncpy(process->name, name, 63);
  process->name[63] = '\0';
  if (parent) {
    strcpy(process->cwd, parent->cwd);
  } else {
    strcpy(process->cwd, "/");
  }
  process->state = PROCESS_STATE_READY;
  process->priority = PROCESS_PRIORITY_DEFAULT;
  process->affinity_mask = PROCESS_AFFINITY_ALL;
  process->last_cpu = current_cpu_index();
  process->time_slice = priority_time_slice(process->priority);
  process->ticks_remaining = process->time_slice;
  process->sleep_until_tick = 0;

  for (int i = 0; i < 256; i++) {
    process->fd_table[i] = -1;
  }

  process->brk = (void *)0x10000000;
  process->brk_start = process->brk;

  process->parent = parent;
  process->children = NULL;
  process->sibling = NULL;
  process->exit_status = 0;

  process->pagemap = vmm_get_kernel_pagemap();
  process->owns_pagemap = false;

  process->stack_size = KERNEL_STACK_SIZE;
  process->stack = kmalloc(KERNEL_STACK_SIZE);
  if (!process->stack) {
    kfree(process);
    return NULL;
  }

  memset(process->stack, 0, KERNEL_STACK_SIZE);
  uint64_t *stack_top =
      (uint64_t *)((uint8_t *)process->stack + KERNEL_STACK_SIZE);
  memset(&process->context, 0, sizeof(context_t));
  process->context.rsp = (uint64_t)stack_top;
  process->context.rip = (uint64_t)entry_point;
  process->context.rflags = 0x202;

  spin_lock(&process_list_lock);
  if (process_list_head) {
    process_t *last = process_list_head;
    while (last->next) {
      last = last->next;
    }
    last->next = process;
    process->prev = last;
  } else {
    process_list_head = process;
  }
  process_count++;
  spin_unlock(&process_list_lock);

  if (parent) {
    process->sibling = parent->children;
    parent->children = process;
  }

  kprint("Created process '");
  kprint(name);
  kprint("' with PID ");
  kprint_hex(process->pid);
  kprint("\n");

  if (scheduler_enabled) {
    scheduler_enqueue_process(process, process->last_cpu, false);
    schedule();
  }

  return process;
}

void process_destroy(process_t *process) {
  if (!process || is_idle_process(process)) {
    return;
  }

  if (process->state != PROCESS_STATE_TERMINATED) {
    process->state = PROCESS_STATE_TERMINATED;
  }

  for (int i = 0; i < 256; i++) {
    int fd = process->fd_table[i];
    if (fd >= 0) {
      if (fd >= 3) {
        vfs_close_fd(fd);
      }
      process->fd_table[i] = -1;
    }
  }

  spin_lock(&process_list_lock);
  if (process->prev) {
    process->prev->next = process->next;
  }
  if (process->next) {
    process->next->prev = process->prev;
  }
  if (process == process_list_head) {
    process_list_head = process->next;
  }
  process_count--;
  spin_unlock(&process_list_lock);

  scheduler_remove_from_queue(process);

  process_vm_clear_regions(process);

  if (process->stack) {
    kfree(process->stack);
  }

  if (process->owns_pagemap && process->pagemap) {
    vmm_destroy_pagemap(process->pagemap);
    process->pagemap = NULL;
    process->owns_pagemap = false;
  }

  kfree(process);
}

void process_exit(int exit_code) {
  process_t *proc = get_current_process_local();
  if (proc && !is_idle_process(proc)) {
    proc->exit_status = exit_code;
    proc->state = PROCESS_STATE_ZOMBIE;

    if (proc->parent && proc->parent->state == PROCESS_STATE_BLOCKED) {
      proc->parent->state = PROCESS_STATE_READY;
      if (scheduler_enabled && !is_idle_process(proc->parent)) {
        scheduler_enqueue_process(proc->parent, proc->parent->last_cpu, true);
      }
    }

    process_t *fallback_idle = idle_processes[0];
    if (!fallback_idle) {
      fallback_idle = proc;
    }

    process_t *child = proc->children;
    while (child) {
      process_t *next = child->sibling;
      child->parent = fallback_idle;
      child->ppid = fallback_idle ? fallback_idle->pid : 0;
      child->sibling = fallback_idle ? fallback_idle->children : NULL;
      if (fallback_idle) {
        fallback_idle->children = child;
      }
      child = next;
    }
    proc->children = NULL;

    schedule();
  }
}

void process_yield(void) {
  if (scheduler_enabled) {
    schedule();
  }
}

void process_sleep(uint32_t milliseconds) {
  process_t *proc = get_current_process_local();
  if (proc && scheduler_enabled) {
    proc->state = PROCESS_STATE_BLOCKED;
    uint64_t ticks =
        ((uint64_t)milliseconds * PIT_DEFAULT_FREQUENCY + 999) / 1000;
    if (ticks == 0) {
      ticks = 1;
    }
    proc->sleep_until_tick = pit_get_ticks() + ticks;
    proc->ticks_remaining = 0;
    schedule();
  } else {
    pit_sleep(milliseconds);
  }
}

void process_wake(process_t *process) {
  if (process && process->state == PROCESS_STATE_BLOCKED) {
    process->state = PROCESS_STATE_READY;
    process->ticks_remaining = process->time_slice;
    process->sleep_until_tick = 0;
    if (scheduler_enabled) {
      scheduler_enqueue_process(process, process->last_cpu, false);
    }
  }
}

process_t *process_get_current(void) { return get_current_process_local(); }

process_t *process_get_by_pid(uint32_t pid) {
  process_t *p = process_list_head;
  while (p) {
    if (p->pid == pid) {
      return p;
    }
    p = p->next;
  }
  return NULL;
}

void process_list(void) {
  kprint("PID  PPID  STATE     CPU  TICKS    NAME\n");
  kprint("---  ----  --------  ---  -------  ----------------\n");

  process_t *p = process_list_head;
  while (p) {
    kprint_hex(p->pid);
    kprint("   ");
    kprint_hex(p->ppid);
    kprint("   ");

    switch (p->state) {
    case PROCESS_STATE_READY:
      kprint("READY   ");
      break;
    case PROCESS_STATE_RUNNING:
      kprint("RUNNING ");
      break;
    case PROCESS_STATE_BLOCKED:
      kprint("BLOCKED ");
      break;
    case PROCESS_STATE_TERMINATED:
      kprint("TERMINATED");
      break;
    case PROCESS_STATE_ZOMBIE:
      kprint("ZOMBIE  ");
      break;
    }

    kprint("  ");
    uint32_t cpu_id = SMP_MAX_CPUS;
    for (uint32_t i = 0; i < SMP_MAX_CPUS; i++) {
      if (idle_processes[i] == p || current_processes[i] == p) {
        cpu_id = i;
        break;
      }
    }
    if (cpu_id == SMP_MAX_CPUS) {
      kprint("-- ");
    } else {
      kprint_hex(cpu_id);
      kprint(" ");
    }

    kprint_hex(p->total_ticks);
    kprint("  ");
    kprint(p->name);
    kprint("\n");

    p = p->next;
  }

  kprint("\nTotal processes: ");
  kprint_hex(process_count);
  kprint("\n");
}

uint32_t process_get_count(void) { return process_count; }

void scheduler_init(void) {
  scheduler_enabled = 1;
  kprint("Scheduler enabled\n");
}

void scheduler_tick(void) {
  if (!scheduler_enabled) {
    return;
  }

  process_t *current = get_current_process_local();
  if (!current) {
    return;
  }

  current->total_ticks++;

  process_t *to_wake[MAX_PROCESSES];
  size_t wake_count = 0;

  uint64_t current_ticks = pit_get_ticks();

  spin_lock(&process_list_lock);
  process_t *p = process_list_head;
  while (p) {
    if (p->state == PROCESS_STATE_BLOCKED) {
      bool should_wake = false;
      if (p->sleep_until_tick != 0) {
        if ((int64_t)(current_ticks - p->sleep_until_tick) >= 0) {
          should_wake = true;
        }
      } else if (p->ticks_remaining > 0) {
        p->ticks_remaining--;
        if (p->ticks_remaining == 0) {
          should_wake = true;
        }
      }

      if (should_wake && wake_count < MAX_PROCESSES) {
        p->sleep_until_tick = 0;
        p->ticks_remaining = p->time_slice;
        p->state = PROCESS_STATE_READY;
        to_wake[wake_count++] = p;
      }
    }
    p = p->next;
  }
  spin_unlock(&process_list_lock);

  for (size_t i = 0; i < wake_count; ++i) {
    if (!is_idle_process(to_wake[i])) {
      scheduler_enqueue_process(to_wake[i], to_wake[i]->last_cpu, false);
    }
  }

  uint32_t cpu_id = current_cpu_index();
  run_queue_t *rq = &cpu_run_queues[cpu_id % SMP_MAX_CPUS];

  if (!is_idle_process(current)) {
    if (current->ticks_remaining > 0) {
      current->ticks_remaining--;
    }
    if (current->ticks_remaining == 0) {
      schedule();
    }
  } else {
    if (__atomic_load_n(&rq->load, __ATOMIC_RELAXED) > 0) {
      schedule();
    }
  }

  cpu_local_t *cpu = smp_get_cpu_local();
  if (cpu && (cpu->scheduler_ticks % SCHEDULER_BALANCE_INTERVAL) == 0) {
    scheduler_trigger_balance(cpu->cpu_id);
  }
}

void schedule(void) {
  if (!scheduler_enabled) {
    return;
  }

  uint32_t cpu_id = current_cpu_index();
  process_t *old_process = get_current_process_local();
  run_queue_t *rq = &cpu_run_queues[cpu_id];

  irq_state_t flags = spin_lock_irqsave(&rq->lock);

  process_t *migrate_process = NULL;
  if (old_process && old_process->state == PROCESS_STATE_RUNNING &&
      !is_idle_process(old_process)) {
    old_process->state = PROCESS_STATE_READY;
    old_process->time_slice = priority_time_slice(old_process->priority);
    old_process->ticks_remaining = old_process->time_slice;
    if (process_has_affinity(old_process, cpu_id)) {
      old_process->last_cpu = cpu_id;
      run_queue_insert_locked(rq, old_process, false);
    } else {
      migrate_process = old_process;
    }
  }

  process_t *next_process = run_queue_select_locked(rq);
  spin_unlock_irqrestore(&rq->lock, flags);

  if (migrate_process) {
    scheduler_enqueue_process(migrate_process, cpu_id, false);
  }

  if (!next_process) {
    next_process =
        idle_processes[cpu_id] ? idle_processes[cpu_id] : idle_processes[0];
    if (!next_process) {
      return;
    }
  }

  if (old_process && old_process != next_process &&
      is_idle_process(old_process)) {
    old_process->state = PROCESS_STATE_READY;
  }

  if (old_process == next_process) {
    next_process->state = PROCESS_STATE_RUNNING;
    next_process->last_cpu = cpu_id;
    next_process->ticks_remaining = next_process->time_slice;
    set_current_process_local(next_process);
    return;
  }

  page_table_t *old_map = (old_process && old_process->pagemap)
                              ? old_process->pagemap
                              : vmm_get_kernel_pagemap();
  page_table_t *new_map = (next_process && next_process->pagemap)
                              ? next_process->pagemap
                              : vmm_get_kernel_pagemap();

  next_process->state = PROCESS_STATE_RUNNING;
  next_process->last_cpu = cpu_id;
  next_process->ticks_remaining = next_process->time_slice;
  set_current_process_local(next_process);

  if (new_map && new_map != old_map) {
    vmm_switch_pagemap(new_map);
  }

  if (old_process && next_process) {
    context_switch(&old_process->context, &next_process->context);
  } else if (next_process) {
    context_switch(NULL, &next_process->context);
  }
}

static void scheduler_trigger_balance(uint32_t cpu_id) {
  uint32_t cpu_count = smp_get_cpu_count();
  if (cpu_count == 0) {
    cpu_count = 1;
  }
  if (cpu_count > SMP_MAX_CPUS) {
    cpu_count = SMP_MAX_CPUS;
  }

  if (!scheduler_cpu_online(cpu_id)) {
    return;
  }

  if (cpu_count <= 1) {
    return;
  }

  irq_state_t sched_flags = spin_lock_irqsave(&scheduler_lock);

  size_t loads[SMP_MAX_CPUS] = {0};
  for (uint32_t i = 0; i < cpu_count; ++i) {
    if (!scheduler_cpu_online(i)) {
      loads[i] = 0;
      continue;
    }
    loads[i] = __atomic_load_n(&cpu_run_queues[i].load, __ATOMIC_RELAXED);
  }

  bool migrated = false;

  while (!migrated) {
    uint32_t busiest_cpu = cpu_id;
    size_t busiest_load = loads[busiest_cpu];

    for (uint32_t i = 0; i < cpu_count; ++i) {
      if (!scheduler_cpu_online(i)) {
        continue;
      }
      if (loads[i] > busiest_load) {
        busiest_cpu = i;
        busiest_load = loads[i];
      }
    }

    size_t target_load = loads[cpu_id];
    if (busiest_cpu == cpu_id || busiest_load <= target_load + 1) {
      break;
    }

    run_queue_t *source = &cpu_run_queues[busiest_cpu];
    run_queue_t *target = &cpu_run_queues[cpu_id];

    if (busiest_cpu == cpu_id) {
      break;
    }

    if (busiest_cpu < cpu_id) {
      spin_lock(&source->lock);
      spin_lock(&target->lock);
    } else {
      spin_lock(&target->lock);
      if (source != target) {
        spin_lock(&source->lock);
      }
    }

    process_t *migrated_proc = run_queue_steal_locked(source, cpu_id);
    if (migrated_proc) {
      migrated_proc->time_slice = priority_time_slice(migrated_proc->priority);
      migrated_proc->ticks_remaining = migrated_proc->time_slice;
      migrated_proc->last_cpu = cpu_id;
      run_queue_insert_locked(target, migrated_proc, false);
      migrated = true;
    }

    if (busiest_cpu < cpu_id) {
      spin_unlock(&target->lock);
      spin_unlock(&source->lock);
    } else {
      if (source != target) {
        spin_unlock(&source->lock);
      }
      spin_unlock(&target->lock);
    }

    if (!migrated) {
      loads[busiest_cpu] = target_load;
    }
  }

  spin_unlock_irqrestore(&scheduler_lock, sched_flags);

  if (migrated && is_idle_process(get_current_process_local())) {
    schedule();
  }
}

const char *process_get_cwd(void) {
  process_t *proc = get_current_process_local();
  if (!proc) {
    return "/";
  }
  return proc->cwd;
}

int process_set_cwd(const char *path) {
  process_t *proc = get_current_process_local();
  if (!proc) {
    return -1;
  }

  vfs_node_t *node = vfs_resolve_path(path);
  if (!node) {
    return -1;
  }

  if (!(node->type & VFS_DIRECTORY)) {
    return -1;
  }

  strncpy(proc->cwd, path, MAX_PATH_LENGTH - 1);
  proc->cwd[MAX_PATH_LENGTH - 1] = '\0';

  size_t len = strlen(proc->cwd);
  if (len > 1 && proc->cwd[len - 1] != '/') {
    if (len < MAX_PATH_LENGTH - 1) {
      proc->cwd[len] = '/';
      proc->cwd[len + 1] = '\0';
    }
  }

  return 0;
}

process_t *process_fork(void) {
  process_t *parent = get_current_process_local();
  if (!parent) {
    return NULL;
  }

  vm_region_t *cloned_regions = NULL;

  process_t *child = kmalloc(sizeof(process_t));
  if (!child) {
    return NULL;
  }

  memcpy(child, parent, sizeof(process_t));
  child->vm_regions = NULL;
  child->run_next = NULL;
  child->run_prev = NULL;
  child->on_run_queue = false;

  child->stack = kmalloc(child->stack_size);
  if (!child->stack) {
    kfree(child);
    return NULL;
  }

  memcpy(child->stack, parent->stack, child->stack_size);

  uint64_t stack_offset = (uint64_t)child->stack - (uint64_t)parent->stack;
  child->context.rsp += stack_offset;
  child->context.rbp += stack_offset;
  child->sleep_until_tick = 0;

  spin_lock(&pid_counter_lock);
  child->pid = next_pid++;
  spin_unlock(&pid_counter_lock);

  child->ppid = parent->pid;
  child->state = PROCESS_STATE_READY;
  child->total_ticks = 0;
  child->priority = clamp_priority(parent->priority);
  child->affinity_mask = parent->affinity_mask;
  child->last_cpu = parent->last_cpu;
  child->time_slice = priority_time_slice(child->priority);
  child->ticks_remaining = child->time_slice;
  child->children = NULL;
  child->sibling = NULL;
  child->next = NULL;
  child->prev = NULL;

  cloned_regions = vm_region_clone_list(parent->vm_regions);
  if (parent->vm_regions && !cloned_regions) {
    kfree(child->stack);
    kfree(child);
    return NULL;
  }

  if (parent->owns_pagemap && parent->pagemap) {
    page_table_t *clone_map = vmm_clone_user_pagemap(parent->pagemap);
    if (!clone_map) {
      if (cloned_regions) {
        vm_region_free_list(cloned_regions);
      }
      kfree(child->stack);
      kfree(child);
      return NULL;
    }
    child->pagemap = clone_map;
    child->owns_pagemap = true;
  } else {
    child->pagemap = parent->pagemap;
    child->owns_pagemap = false;
  }

  child->vm_regions = cloned_regions;
  child->mmap_base = parent->mmap_base;

  for (int i = 0; i < 256; i++) {
    int fd = child->fd_table[i];
    if (fd >= 0) {
      vfs_retain_fd(fd);
    }
  }

  child->context.rax = 0;

  child->parent = parent;
  child->sibling = parent->children;
  parent->children = child;

  spin_lock(&process_list_lock);
  if (process_list_head) {
    process_t *last = process_list_head;
    while (last->next) {
      last = last->next;
    }
    last->next = child;
    child->prev = last;
  } else {
    process_list_head = child;
  }
  process_count++;
  spin_unlock(&process_list_lock);

  if (scheduler_enabled) {
    scheduler_enqueue_process(child, child->last_cpu, false);
  }

  return child;
}

int process_waitpid(int pid, int *status, int options) {
  process_t *parent = get_current_process_local();
  if (!parent) {
    return -1;
  }

  bool nohang = (options & WNOHANG) != 0;
  int target = pid;
  if (target == 0) {
    target = -1;
  }

  while (1) {
    process_t *child = parent->children;
    process_t *prev = NULL;
    bool found_match = false;

    while (child) {
      bool matches = (target == -1) || child->pid == (uint32_t)target;
      if (matches) {
        found_match = true;
        if (child->state == PROCESS_STATE_ZOMBIE) {
          if (status) {
            *status = child->exit_status;
          }

          if (prev) {
            prev->sibling = child->sibling;
          } else {
            parent->children = child->sibling;
          }

          uint32_t child_pid = child->pid;
          process_destroy(child);
          return (int)child_pid;
        }
      }
      prev = child;
      child = child->sibling;
    }

    if (!found_match) {
      return -1;
    }

    if (nohang) {
      return 0;
    }

    parent->state = PROCESS_STATE_BLOCKED;
    process_yield();
  }
}

void process_ensure_standard_streams(process_t *proc) {
  if (!proc) {
    return;
  }

  const uint32_t std_flags[3] = {VFS_READ, VFS_WRITE, VFS_WRITE};

  for (int fd = 0; fd < 3; fd++) {
    if (proc->fd_table[fd] < 0) {
      int vfs_fd = vfs_open_fd("/dev/tty", std_flags[fd],
                               S_IFCHR | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP |
                                   S_IROTH | S_IWOTH);
      if (vfs_fd >= 0) {
        proc->fd_table[fd] = vfs_fd;
      }
    }
  }
}

void process_set_priority(process_t *proc, int priority) {
  if (!proc || is_idle_process(proc)) {
    return;
  }

  int old_priority = proc->priority;
  int new_priority = clamp_priority(priority);
  if (old_priority == new_priority) {
    return;
  }

  uint64_t new_slice = priority_time_slice(new_priority);
  uint32_t cpu = proc->last_cpu;
  if (cpu >= SMP_MAX_CPUS) {
    cpu = current_cpu_index();
    if (cpu >= SMP_MAX_CPUS) {
      cpu = 0;
    }
  }

  if (proc->on_run_queue) {
    run_queue_t *rq = &cpu_run_queues[cpu];
    irq_state_t flags = spin_lock_irqsave(&rq->lock);
    if (proc->on_run_queue) {
      run_queue_remove_locked(rq, proc);
    }
    proc->priority = new_priority;
    proc->time_slice = new_slice;
    proc->ticks_remaining = proc->time_slice;
    if (proc->state == PROCESS_STATE_READY) {
      bool promote = new_priority < old_priority;
      run_queue_insert_locked(rq, proc, promote);
    }
    spin_unlock_irqrestore(&rq->lock, flags);
  } else {
    proc->priority = new_priority;
    proc->time_slice = new_slice;
    if (proc->state == PROCESS_STATE_RUNNING ||
        proc->state == PROCESS_STATE_READY) {
      proc->ticks_remaining = proc->time_slice;
    }
  }
}

void process_set_affinity(process_t *proc, uint32_t affinity_mask) {
  if (!proc || is_idle_process(proc)) {
    return;
  }

  uint32_t new_mask = affinity_mask ? affinity_mask : PROCESS_AFFINITY_ALL;
  if (proc->affinity_mask == new_mask) {
    return;
  }

  proc->affinity_mask = new_mask;

  if (proc->on_run_queue) {
    uint32_t cpu = proc->last_cpu;
    if (cpu >= SMP_MAX_CPUS) {
      cpu = cpu % SMP_MAX_CPUS;
    }
    run_queue_t *rq = &cpu_run_queues[cpu];
    irq_state_t flags = spin_lock_irqsave(&rq->lock);
    if (proc->on_run_queue) {
      run_queue_remove_locked(rq, proc);
    }
    spin_unlock_irqrestore(&rq->lock, flags);

    if (scheduler_enabled && proc->state == PROCESS_STATE_READY) {
      scheduler_enqueue_process(proc, cpu, false);
    }
  } else if (proc->state == PROCESS_STATE_READY && scheduler_enabled) {
    scheduler_enqueue_process(proc, proc->last_cpu, false);
  }

  if (proc->state == PROCESS_STATE_RUNNING &&
      !process_has_affinity(proc, current_cpu_index())) {
    proc->ticks_remaining = 0;
  }
}

void *process_sbrk(intptr_t increment) {
  process_t *proc = get_current_process_local();
  if (!proc || !proc->pagemap) {
    return (void *)-1;
  }

  if (increment == 0) {
    return proc->brk;
  }

  const uintptr_t user_heap_limit = 0x20000000ULL;

  uintptr_t current_brk = (uintptr_t)proc->brk;
  uintptr_t new_brk;

  if (increment > 0) {
    uintptr_t inc = (uintptr_t)increment;
    if (UINTPTR_MAX - current_brk < inc) {
      return (void *)-1;
    }
    new_brk = current_brk + inc;
  } else {
    uintptr_t dec = (uintptr_t)(-increment);
    if (current_brk < dec) {
      return (void *)-1;
    }
    new_brk = current_brk - dec;
  }

  if (new_brk < (uintptr_t)proc->brk_start || new_brk > user_heap_limit) {
    return (void *)-1;
  }

  uintptr_t old_page_aligned = align_up(current_brk, PAGE_SIZE);
  uintptr_t new_page_aligned = align_up(new_brk, PAGE_SIZE);

  void *old_brk_ptr = (void *)current_brk;

  if (increment < 0 && new_page_aligned < old_page_aligned) {
    uint64_t range_start = new_page_aligned;
    uint64_t range_len = old_page_aligned - new_page_aligned;
    process_vm_unmap_range(proc, range_start, range_len);
  }

  proc->brk = (void *)new_brk;
  return old_brk_ptr;
}

int scheduler_is_enabled(void) { return scheduler_enabled; }
