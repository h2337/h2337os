#ifndef SMP_H
#define SMP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct process;
struct interrupt_frame;

#define SMP_MAX_CPUS 32
#define LAPIC_TIMER_VECTOR 0x40
#define CONSOLE_BUFFER_SIZE 256

typedef struct cpu_local {
  uint32_t cpu_id;
  uint32_t lapic_id;
  struct process *current_process;
  struct process *idle_process;
  volatile uint64_t scheduler_ticks;
  volatile bool online;
  volatile bool ready;
  volatile bool start_requested;
  char console_buffer[CONSOLE_BUFFER_SIZE];
  size_t console_buffer_len;
} cpu_local_t;

void smp_init(void);
void smp_resume_secondary_cpus(void);
bool smp_is_active(void);
uint32_t smp_get_cpu_count(void);
uint32_t smp_get_cpu_id(void);
cpu_local_t *smp_get_cpu_local(void);
cpu_local_t *smp_get_cpu_local_by_index(uint32_t cpu_id);
void smp_set_current_process(struct process *process);
void smp_set_idle_process(uint32_t cpu_id, struct process *process);
void smp_start_lapic_timer(void);
void smp_handle_apic_timer(struct interrupt_frame *frame);

#endif
