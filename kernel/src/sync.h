#ifndef SYNC_H
#define SYNC_H

#include <stdbool.h>
#include <stdint.h>

// Spinlock structure
typedef struct {
  volatile uint32_t lock;
  const char *lock_name; // For debugging (renamed to avoid macro conflict)
  volatile uint32_t owner_cpu; // CPU that holds the lock
} spinlock_t;

// Mutex structure (for sleepable contexts)
typedef struct {
  volatile uint32_t lock;
  volatile uint32_t owner_pid;
  const char *mutex_name; // Renamed to avoid macro conflict
  volatile uint32_t wait_count;
} mutex_t;

// Interrupt save state for spinlocks
typedef uint64_t irq_state_t;

// Spinlock functions
void spinlock_init(spinlock_t *lock, const char *name);
void spin_lock(spinlock_t *lock);
void spin_unlock(spinlock_t *lock);
bool spin_trylock(spinlock_t *lock);

// IRQ-safe spinlock functions (disable interrupts while held)
irq_state_t spin_lock_irqsave(spinlock_t *lock);
void spin_unlock_irqrestore(spinlock_t *lock, irq_state_t state);

// Mutex functions (can sleep)
void mutex_init(mutex_t *mutex, const char *name);
void mutex_lock(mutex_t *mutex);
void mutex_unlock(mutex_t *mutex);
bool mutex_trylock(mutex_t *mutex);

// Helper macros
#define SPINLOCK_INIT(name)                                                    \
  {.lock = 0, .lock_name = name, .owner_cpu = 0xFFFFFFFF}
#define MUTEX_INIT(name)                                                       \
  {.lock = 0, .owner_pid = 0, .mutex_name = name, .wait_count = 0}

// Static initialization
#define DEFINE_SPINLOCK(varname, lockname)                                     \
  spinlock_t varname = SPINLOCK_INIT(lockname)

#define DEFINE_MUTEX(varname, mutexname) mutex_t varname = MUTEX_INIT(mutexname)

#endif // SYNC_H