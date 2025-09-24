#ifndef PROCESS_H
#define PROCESS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "types.h"
#include "vmm.h"

#define MAX_PROCESSES 256
#define KERNEL_STACK_SIZE 8192
#define DEFAULT_TIME_SLICE 10
#define MAX_PATH_LENGTH 256

#define PROCESS_PRIORITY_HIGH 0
#define PROCESS_PRIORITY_NORMAL 1
#define PROCESS_PRIORITY_LOW 2
#define PROCESS_PRIORITY_COUNT 3
#define PROCESS_PRIORITY_DEFAULT PROCESS_PRIORITY_NORMAL

#define PROCESS_AFFINITY_ALL 0xFFFFFFFFu

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

typedef struct vm_region {
  uint64_t start;
  uint64_t end;
  uint64_t flags;
  int prot;
  int map_flags;
  int fd;
  off_t offset;
  struct vm_region *next;
} vm_region_t;

typedef struct process {
  uint32_t pid;
  uint32_t ppid;
  char name[64];
  char cwd[MAX_PATH_LENGTH];
  process_state_t state;
  context_t context;
  uint64_t *stack;
  uint64_t stack_size;
  uint64_t time_slice;
  uint64_t ticks_remaining;
  uint64_t total_ticks;
  uint64_t sleep_until_tick;
  int priority;
  uint32_t affinity_mask;
  uint32_t last_cpu;
  struct process *run_next;
  struct process *run_prev;
  bool on_run_queue;

  void *brk;
  void *brk_start;

  int fd_table[256];

  int exit_status;

  page_table_t *pagemap;
  bool owns_pagemap;

  struct process *children;
  struct process *sibling;
  struct process *parent;

  struct process *next;
  struct process *prev;

  vm_region_t *vm_regions;
  uint64_t mmap_base;
} process_t;

void process_init(void);
void process_init_ap(uint32_t cpu_id);
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
const char *process_get_cwd(void);
int process_set_cwd(const char *path);
process_t *process_fork(void);
int process_waitpid(int pid, int *status, int options);
void *process_sbrk(intptr_t increment);
void process_ensure_standard_streams(process_t *proc);
vm_region_t *process_vm_find_region(process_t *proc, uint64_t addr);
vm_region_t *process_vm_add_region(process_t *proc, uint64_t start,
                                   uint64_t length, int prot, int flags, int fd,
                                   off_t offset);
int process_vm_remove_region(process_t *proc, uint64_t start, uint64_t length);
void process_vm_clear_regions(process_t *proc);
uint64_t process_vm_reserve_addr(process_t *proc, size_t length);
void process_vm_unmap_range(process_t *proc, uint64_t start, uint64_t length);
void scheduler_init(void);
void scheduler_tick(void);
void schedule(void);
void context_switch(context_t *old, context_t *new);
int scheduler_is_enabled(void);
void process_set_priority(process_t *proc, int priority);
void process_set_affinity(process_t *proc, uint32_t affinity_mask);

#endif
