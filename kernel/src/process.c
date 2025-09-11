#include "process.h"
#include "console.h"
#include "heap.h"
#include "libc.h"
#include "pit.h"
#include <stddef.h>
#include <stdint.h>

static process_t *process_list_head = NULL;
static process_t *current_process = NULL;
static process_t *idle_process = NULL;
static uint32_t next_pid = 1;
static uint32_t process_count = 0;
static int scheduler_enabled = 0;

extern void context_switch(context_t *old, context_t *new);

static void idle_task(void) {
  while (1) {
    asm volatile("hlt");
  }
}

void process_init(void) {
  kprint("Initializing process management...\n");

  idle_process = kmalloc(sizeof(process_t));
  if (!idle_process) {
    kprint("Failed to allocate idle process\n");
    return;
  }

  memset(idle_process, 0, sizeof(process_t));
  idle_process->pid = 0;
  idle_process->ppid = 0;
  strcpy(idle_process->name, "idle");
  idle_process->state = PROCESS_STATE_READY;
  idle_process->time_slice = DEFAULT_TIME_SLICE;
  idle_process->ticks_remaining = DEFAULT_TIME_SLICE;

  idle_process->stack_size = KERNEL_STACK_SIZE;
  idle_process->stack = kmalloc(KERNEL_STACK_SIZE);
  if (!idle_process->stack) {
    kprint("Failed to allocate idle process stack\n");
    kfree(idle_process);
    idle_process = NULL;
    return;
  }

  uint64_t *stack_top =
      (uint64_t *)((uint8_t *)idle_process->stack + KERNEL_STACK_SIZE);

  // Initialize context for first switch
  memset(&idle_process->context, 0, sizeof(context_t));
  idle_process->context.rsp = (uint64_t)stack_top;
  idle_process->context.rip = (uint64_t)idle_task;
  idle_process->context.rflags = 0x202; // Interrupts enabled

  process_list_head = idle_process;
  current_process = idle_process;
  process_count = 1;

  kprint("Process management initialized\n");
}

process_t *process_create(const char *name, void (*entry_point)(void)) {
  process_t *process = kmalloc(sizeof(process_t));
  if (!process) {
    return NULL;
  }

  memset(process, 0, sizeof(process_t));
  process->pid = next_pid++;
  process->ppid = current_process ? current_process->pid : 0;
  strncpy(process->name, name, 63);
  process->name[63] = '\0';
  process->state = PROCESS_STATE_READY;
  process->time_slice = DEFAULT_TIME_SLICE;
  process->ticks_remaining = DEFAULT_TIME_SLICE;

  process->stack_size = KERNEL_STACK_SIZE;
  process->stack = kmalloc(KERNEL_STACK_SIZE);
  if (!process->stack) {
    kfree(process);
    return NULL;
  }

  memset(process->stack, 0, KERNEL_STACK_SIZE);

  uint64_t *stack_top =
      (uint64_t *)((uint8_t *)process->stack + KERNEL_STACK_SIZE);

  // Set up initial stack
  // When context_switch loads this context, it will push RIP and then ret to it
  // So we just need the stack pointer to be at the right place

  // Initialize context for first switch
  memset(&process->context, 0, sizeof(context_t));
  process->context.rsp = (uint64_t)stack_top;   // Stack pointer at top
  process->context.rip = (uint64_t)entry_point; // Where to jump
  process->context.rflags = 0x202;              // Interrupts enabled

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

  kprint("Created process '");
  kprint(name);
  kprint("' with PID ");
  kprint_hex(process->pid);
  kprint("\n");

  // Force a schedule to run the new process
  if (scheduler_enabled) {
    schedule();
  }

  return process;
}

void process_destroy(process_t *process) {
  if (!process || process == idle_process) {
    return;
  }

  if (process->state != PROCESS_STATE_TERMINATED) {
    process->state = PROCESS_STATE_TERMINATED;
  }

  if (process->prev) {
    process->prev->next = process->next;
  }
  if (process->next) {
    process->next->prev = process->prev;
  }
  if (process == process_list_head) {
    process_list_head = process->next;
  }

  if (process->stack) {
    kfree(process->stack);
  }

  kfree(process);
  process_count--;
}

void process_exit(int exit_code) {
  (void)exit_code;

  if (current_process && current_process != idle_process) {
    current_process->state = PROCESS_STATE_TERMINATED;
    schedule();
  }
}

void process_yield(void) {
  if (scheduler_enabled) {
    schedule();
  }
}

void process_sleep(uint32_t milliseconds) {
  if (current_process && scheduler_enabled) {
    current_process->state = PROCESS_STATE_BLOCKED;
    current_process->ticks_remaining =
        (milliseconds * PIT_DEFAULT_FREQUENCY) / 1000;
    schedule();
  } else {
    pit_sleep(milliseconds);
  }
}

void process_wake(process_t *process) {
  if (process && process->state == PROCESS_STATE_BLOCKED) {
    process->state = PROCESS_STATE_READY;
    process->ticks_remaining = process->time_slice;
  }
}

process_t *process_get_current(void) { return current_process; }

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
  kprint("PID  PPID  STATE     TICKS    NAME\n");
  kprint("---  ----  --------  -------  ----------------\n");

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
  if (!scheduler_enabled || !current_process) {
    return;
  }

  // Update tick counts
  current_process->total_ticks++;

  // Wake up sleeping processes
  process_t *p = process_list_head;
  while (p) {
    if (p->state == PROCESS_STATE_BLOCKED && p->ticks_remaining > 0) {
      p->ticks_remaining--;
      if (p->ticks_remaining == 0) {
        process_wake(p);
      }
    }
    p = p->next;
  }

  // Decrement time slice and schedule if needed
  if (current_process->state == PROCESS_STATE_RUNNING) {
    current_process->ticks_remaining--;
    if (current_process->ticks_remaining == 0) {
      // Time slice expired, schedule next process
      schedule();
    }
  }
}

void schedule(void) {
  if (!scheduler_enabled || !process_list_head) {
    return;
  }

  // Disable interrupts during scheduling
  asm volatile("cli");

  process_t *old_process = current_process;
  process_t *next_process = NULL;

  // Mark current as ready if it was running
  if (old_process && old_process->state == PROCESS_STATE_RUNNING) {
    old_process->state = PROCESS_STATE_READY;
  }

  // Find next ready process (round-robin)
  process_t *p = old_process ? old_process->next : process_list_head;
  if (!p) {
    p = process_list_head;
  }

  process_t *start = p;
  do {
    if (p->state == PROCESS_STATE_READY) {
      next_process = p;
      break;
    }
    p = p->next;
    if (!p) {
      p = process_list_head;
    }
  } while (p != start);

  // If no ready process, use idle
  if (!next_process) {
    next_process = idle_process;
  }

  // If same process, just continue
  if (next_process == old_process) {
    if (old_process->state == PROCESS_STATE_READY) {
      old_process->state = PROCESS_STATE_RUNNING;
      old_process->ticks_remaining = old_process->time_slice;
    }
    asm volatile("sti");
    return;
  }

  // Switch to next process
  next_process->state = PROCESS_STATE_RUNNING;
  next_process->ticks_remaining = next_process->time_slice;
  current_process = next_process;

  // Re-enable interrupts
  asm volatile("sti");

  // Perform context switch
  if (old_process && next_process) {
    context_switch(&old_process->context, &next_process->context);
  }
}