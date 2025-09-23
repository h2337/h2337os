#include "tty.h"
#include "console.h"
#include "heap.h"
#include "libc.h"
#include "process.h"
#include "sync.h"
#include "vfs.h"

#define TTY_BUFFER_SIZE 1024
#define TTY_WAIT_QUEUE_CAPACITY 64

static char tty_buffer[TTY_BUFFER_SIZE];
static size_t tty_head = 0;
static size_t tty_tail = 0;
static size_t tty_count = 0;

static process_t *wait_queue[TTY_WAIT_QUEUE_CAPACITY];
static size_t wait_head = 0;
static size_t wait_tail = 0;
static size_t wait_count = 0;

static spinlock_t tty_lock = SPINLOCK_INIT("tty");

static vfs_node_t tty_node;
static bool tty_device_registered = false;

static bool enqueue_waiter(process_t *proc) {
  if (wait_count >= TTY_WAIT_QUEUE_CAPACITY) {
    return false;
  }
  wait_queue[wait_tail] = proc;
  wait_tail = (wait_tail + 1) % TTY_WAIT_QUEUE_CAPACITY;
  wait_count++;
  return true;
}

static process_t *dequeue_waiter(void) {
  if (wait_count == 0) {
    return NULL;
  }
  process_t *proc = wait_queue[wait_head];
  wait_head = (wait_head + 1) % TTY_WAIT_QUEUE_CAPACITY;
  wait_count--;
  return proc;
}

static uint32_t tty_vfs_read(vfs_node_t *node, uint32_t offset, uint32_t size,
                             uint8_t *buffer) {
  (void)node;
  (void)offset;
  return (uint32_t)tty_read((char *)buffer, size);
}

static uint32_t tty_vfs_write(vfs_node_t *node, uint32_t offset, uint32_t size,
                              uint8_t *buffer) {
  (void)node;
  (void)offset;
  return (uint32_t)tty_write((const char *)buffer, size);
}

static void tty_vfs_open(vfs_node_t *node, uint32_t flags) {
  (void)node;
  (void)flags;
}

static void tty_vfs_close(vfs_node_t *node) { (void)node; }

void tty_init(void) {
  tty_head = 0;
  tty_tail = 0;
  tty_count = 0;
  wait_head = 0;
  wait_tail = 0;
  wait_count = 0;
  tty_device_registered = false;
}

void tty_register_device(void) {
  if (tty_device_registered) {
    return;
  }

  memset(&tty_node, 0, sizeof(tty_node));
  strcpy(tty_node.name, "tty");
  tty_node.type = VFS_CHARDEVICE;
  tty_node.flags = VFS_READ | VFS_WRITE;
  tty_node.read = tty_vfs_read;
  tty_node.write = tty_vfs_write;
  tty_node.open = tty_vfs_open;
  tty_node.close = tty_vfs_close;

  vfs_register_special("/dev/tty", &tty_node);
  tty_device_registered = true;
}

size_t tty_read(char *buffer, size_t count) {
  if (!buffer || count == 0) {
    return 0;
  }

  size_t read = 0;

  while (read < count) {
    irq_state_t irq = spin_lock_irqsave(&tty_lock);

    while (tty_count == 0) {
      process_t *proc = process_get_current();
      if (!proc) {
        spin_unlock_irqrestore(&tty_lock, irq);
        return read;
      }
      if (!enqueue_waiter(proc)) {
        spin_unlock_irqrestore(&tty_lock, irq);
        process_yield();
        irq = spin_lock_irqsave(&tty_lock);
        continue;
      }

      proc->state = PROCESS_STATE_BLOCKED;
      spin_unlock_irqrestore(&tty_lock, irq);
      process_yield();
      irq = spin_lock_irqsave(&tty_lock);
    }

    char c = tty_buffer[tty_head];
    tty_head = (tty_head + 1) % TTY_BUFFER_SIZE;
    tty_count--;

    spin_unlock_irqrestore(&tty_lock, irq);

    buffer[read++] = c;
    if (c == '\n') {
      break;
    }
  }

  return read;
}

size_t tty_write(const char *buffer, size_t count) {
  if (!buffer || count == 0) {
    return 0;
  }

  for (size_t i = 0; i < count; i++) {
    kputchar(buffer[i]);
  }
  kflush();
  return count;
}

char tty_getchar(void) {
  char c = 0;
  tty_read(&c, 1);
  return c;
}

bool tty_has_input(void) {
  irq_state_t irq = spin_lock_irqsave(&tty_lock);
  bool has_data = tty_count > 0;
  spin_unlock_irqrestore(&tty_lock, irq);
  return has_data;
}

void tty_flush(void) {
  irq_state_t irq = spin_lock_irqsave(&tty_lock);
  tty_head = 0;
  tty_tail = 0;
  tty_count = 0;
  wait_head = 0;
  wait_tail = 0;
  wait_count = 0;
  spin_unlock_irqrestore(&tty_lock, irq);
}

void tty_handle_input(char c) {
  irq_state_t irq = spin_lock_irqsave(&tty_lock);

  if (tty_count < TTY_BUFFER_SIZE) {
    tty_buffer[tty_tail] = c;
    tty_tail = (tty_tail + 1) % TTY_BUFFER_SIZE;
    tty_count++;
  }

  process_t *proc = dequeue_waiter();

  spin_unlock_irqrestore(&tty_lock, irq);

  if (proc) {
    process_wake(proc);
  }
}
