#ifndef PROCESS_H
#define PROCESS_H

#include <stddef.h>
#include <stdint.h>

#define MAX_PROCESSES 256
#define KERNEL_STACK_SIZE 8192
#define DEFAULT_TIME_SLICE 10

typedef enum {
  PROCESS_STATE_READY,
  PROCESS_STATE_RUNNING,
  PROCESS_STATE_BLOCKED,
  PROCESS_STATE_TERMINATED,
  PROCESS_STATE_ZOMBIE
} process_state_t;

typedef struct context {
  uint64_t r15;
  uint64_t r14;
  uint64_t r13;
  uint64_t r12;
  uint64_t r11;
  uint64_t r10;
  uint64_t r9;
  uint64_t r8;
  uint64_t rbp;
  uint64_t rdi;
  uint64_t rsi;
  uint64_t rdx;
  uint64_t rcx;
  uint64_t rbx;
  uint64_t rax;
  uint64_t rip;
  uint64_t cs;
  uint64_t rflags;
  uint64_t rsp;
  uint64_t ss;
} __attribute__((packed)) context_t;

typedef struct process {
  uint32_t pid;
  uint32_t ppid;
  char name[64];
  process_state_t state;
  context_t context;
  uint64_t *stack;
  uint64_t stack_size;
  uint64_t time_slice;
  uint64_t ticks_remaining;
  uint64_t total_ticks;
  struct process *next;
  struct process *prev;
} process_t;

void process_init(void);
process_t *process_create(const char *name, void (*entry_point)(void));
void process_destroy(process_t *process);
void process_exit(int exit_code);
void process_yield(void);
void process_sleep(uint32_t milliseconds);
void process_wake(process_t *process);
process_t *process_get_current(void);
process_t *process_get_by_pid(uint32_t pid);
void process_list(void);
uint32_t process_get_count(void);
void scheduler_init(void);
void scheduler_tick(void);
void schedule(void);
void context_switch(context_t *old, context_t *new);

#endif