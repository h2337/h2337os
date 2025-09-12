#include <process.h>
#include <stdbool.h>
#include <stddef.h>
#include <sync.h>

// x86-64 specific functions
static inline void cpu_pause(void) { __asm__ volatile("pause" ::: "memory"); }

static inline uint64_t read_rflags(void) {
  uint64_t rflags;
  __asm__ volatile("pushfq; pop %0" : "=r"(rflags));
  return rflags;
}

static inline void write_rflags(uint64_t rflags) {
  __asm__ volatile("push %0; popfq" ::"r"(rflags) : "memory", "cc");
}

static inline void cli(void) { __asm__ volatile("cli" ::: "memory"); }

static inline void sti(void) { __asm__ volatile("sti" ::: "memory"); }

static inline bool interrupts_enabled(void) {
  return (read_rflags() & 0x200) != 0; // IF flag
}

// Atomic compare and swap
static inline bool atomic_cmpxchg(volatile uint32_t *ptr, uint32_t old_val,
                                  uint32_t new_val) {
  uint32_t ret;
  __asm__ volatile("lock cmpxchgl %2, %1"
                   : "=a"(ret), "+m"(*ptr)
                   : "r"(new_val), "0"(old_val)
                   : "memory");
  return ret == old_val;
}

// Atomic exchange
static inline uint32_t atomic_xchg(volatile uint32_t *ptr, uint32_t new_val) {
  uint32_t ret;
  __asm__ volatile("xchgl %0, %1"
                   : "=r"(ret), "+m"(*ptr)
                   : "0"(new_val)
                   : "memory");
  return ret;
}

// Initialize spinlock
void spinlock_init(spinlock_t *lock, const char *name) {
  lock->lock = 0;
  lock->lock_name = name;
  lock->owner_cpu = 0xFFFFFFFF;
}

// Acquire spinlock (busy wait)
void spin_lock(spinlock_t *lock) {
  while (atomic_xchg(&lock->lock, 1) != 0) {
    // Spin until lock becomes available
    while (lock->lock != 0) {
      cpu_pause(); // Reduce CPU power consumption while spinning
    }
  }
  __asm__ volatile("" ::: "memory"); // Memory barrier
  lock->owner_cpu = 0;               // In single-CPU system, just use 0
}

// Release spinlock
void spin_unlock(spinlock_t *lock) {
  __asm__ volatile("" ::: "memory"); // Memory barrier
  lock->owner_cpu = 0xFFFFFFFF;
  lock->lock = 0;
}

// Try to acquire spinlock without blocking
bool spin_trylock(spinlock_t *lock) {
  if (atomic_xchg(&lock->lock, 1) == 0) {
    __asm__ volatile("" ::: "memory");
    lock->owner_cpu = 0;
    return true;
  }
  return false;
}

// Acquire spinlock with IRQ save
irq_state_t spin_lock_irqsave(spinlock_t *lock) {
  irq_state_t flags = read_rflags();
  cli(); // Disable interrupts
  spin_lock(lock);
  return flags;
}

// Release spinlock and restore IRQ state
void spin_unlock_irqrestore(spinlock_t *lock, irq_state_t state) {
  spin_unlock(lock);
  if (state & 0x200) { // IF flag was set
    sti();             // Re-enable interrupts
  }
}

// Initialize mutex
void mutex_init(mutex_t *mutex, const char *name) {
  mutex->lock = 0;
  mutex->owner_pid = 0;
  mutex->mutex_name = name;
  mutex->wait_count = 0;
}

// Acquire mutex (can sleep)
void mutex_lock(mutex_t *mutex) {
  process_t *current = process_get_current();
  uint32_t current_pid = current ? current->pid : 0;

  while (atomic_xchg(&mutex->lock, 1) != 0) {
    // Mutex is held, increment wait count and yield
    // Use inline assembly for atomic increment
    __asm__ volatile("lock incl %0" : "+m"(mutex->wait_count) : : "memory");

    // Yield CPU to other processes
    if (current) {
      schedule(); // Give up CPU time
    } else {
      // In interrupt context, just spin (shouldn't happen)
      while (mutex->lock != 0) {
        cpu_pause();
      }
    }

    // Use inline assembly for atomic decrement
    __asm__ volatile("lock decl %0" : "+m"(mutex->wait_count) : : "memory");
  }

  __asm__ volatile("" ::: "memory"); // Memory barrier
  mutex->owner_pid = current_pid;
}

// Release mutex
void mutex_unlock(mutex_t *mutex) {
  __asm__ volatile("" ::: "memory"); // Memory barrier
  mutex->owner_pid = 0;
  mutex->lock = 0;

  // If there are waiters, trigger a reschedule to wake them
  if (mutex->wait_count > 0) {
    schedule();
  }
}

// Try to acquire mutex without blocking
bool mutex_trylock(mutex_t *mutex) {
  process_t *current = process_get_current();
  uint32_t current_pid = current ? current->pid : 0;

  if (atomic_xchg(&mutex->lock, 1) == 0) {
    __asm__ volatile("" ::: "memory");
    mutex->owner_pid = current_pid;
    return true;
  }
  return false;
}