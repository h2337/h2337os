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

static inline bool is_idle_for_other_cpu(process_t *process, uint32_t cpu_id) {
  for (uint32_t i = 0; i < SMP_MAX_CPUS; i++) {
    if (idle_processes[i] == process) {
      return i != cpu_id;
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
                                   uint64_t length, int prot, int flags,
                                   int fd, off_t offset) {
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

int process_vm_remove_region(process_t *proc, uint64_t start,
                             uint64_t length) {
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
  idle->time_slice = DEFAULT_TIME_SLICE;
  idle->ticks_remaining = DEFAULT_TIME_SLICE;
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
  process->time_slice = DEFAULT_TIME_SLICE;
  process->ticks_remaining = DEFAULT_TIME_SLICE;
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

  uint64_t current_ticks = pit_get_ticks();
  process_t *p = process_list_head;
  while (p) {
    if (p->state == PROCESS_STATE_BLOCKED) {
      if (p->sleep_until_tick != 0) {
        if ((int64_t)(current_ticks - p->sleep_until_tick) >= 0) {
          process_wake(p);
        }
      } else if (p->ticks_remaining > 0) {
        p->ticks_remaining--;
        if (p->ticks_remaining == 0) {
          process_wake(p);
        }
      }
    }
    p = p->next;
  }

  if (current->state == PROCESS_STATE_RUNNING) {
    current->ticks_remaining--;
    if (current->ticks_remaining == 0) {
      schedule();
    }
  }
}

void schedule(void) {
  if (!scheduler_enabled || !process_list_head) {
    return;
  }

  uint32_t cpu_id = current_cpu_index();
  irq_state_t flags = spin_lock_irqsave(&scheduler_lock);
  spin_lock(&process_list_lock);

  process_t *old_process = get_current_process_local();
  process_t *next_process = NULL;

  if (old_process && old_process->state == PROCESS_STATE_RUNNING) {
    old_process->state = PROCESS_STATE_READY;
  }

  process_t *start = old_process ? old_process->next : process_list_head;
  if (!start) {
    start = process_list_head;
  }

  process_t *p = start;
  while (p) {
    if (p->state == PROCESS_STATE_READY && !is_idle_for_other_cpu(p, cpu_id)) {
      next_process = p;
      break;
    }
    p = p->next ? p->next : process_list_head;
    if (p == start) {
      break;
    }
  }

  if (!next_process) {
    next_process =
        idle_processes[cpu_id] ? idle_processes[cpu_id] : idle_processes[0];
  }

  if (old_process == next_process) {
    if (old_process) {
      old_process->state = PROCESS_STATE_RUNNING;
      old_process->ticks_remaining = old_process->time_slice;
    }
    spin_unlock(&process_list_lock);
    spin_unlock_irqrestore(&scheduler_lock, flags);
    return;
  }

  if (next_process) {
    next_process->state = PROCESS_STATE_RUNNING;
    next_process->ticks_remaining = next_process->time_slice;
    set_current_process_local(next_process);
  }

  page_table_t *old_map = (old_process && old_process->pagemap)
                              ? old_process->pagemap
                              : vmm_get_kernel_pagemap();
  page_table_t *new_map = (next_process && next_process->pagemap)
                              ? next_process->pagemap
                              : vmm_get_kernel_pagemap();

  spin_unlock(&process_list_lock);

  if (new_map && new_map != old_map) {
    vmm_switch_pagemap(new_map);
  }

  spin_unlock_irqrestore(&scheduler_lock, flags);

  if (old_process && next_process) {
    context_switch(&old_process->context, &next_process->context);
  } else if (next_process) {
    context_switch(NULL, &next_process->context);
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
  child->ticks_remaining = DEFAULT_TIME_SLICE;
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

  return child;
}

int process_waitpid(int pid, int *status, int options) {
  (void)options;

  process_t *parent = get_current_process_local();
  if (!parent) {
    return -1;
  }

  while (1) {
    process_t *child = parent->children;
    process_t *prev = NULL;

    while (child) {
      if ((pid == -1 || child->pid == (uint32_t)pid) &&
          child->state == PROCESS_STATE_ZOMBIE) {
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

        return child_pid;
      }
      prev = child;
      child = child->sibling;
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
      int vfs_fd = vfs_open_fd("/dev/tty", std_flags[fd]);
      if (vfs_fd >= 0) {
        proc->fd_table[fd] = vfs_fd;
      }
    }
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
