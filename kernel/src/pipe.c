#include "pipe.h"
#include "heap.h"
#include "libc.h"
#include "process.h"
#include "sync.h"
#include "vfs.h"
#include <stdbool.h>

#define PIPE_BUFFER_SIZE 4096
#define PIPE_WAIT_QUEUE_CAPACITY 64

typedef struct pipe {
  spinlock_t lock;
  char buffer[PIPE_BUFFER_SIZE];
  size_t head;
  size_t tail;
  size_t count;

  process_t *read_waiters[PIPE_WAIT_QUEUE_CAPACITY];
  size_t read_head;
  size_t read_tail;
  size_t read_count;

  process_t *write_waiters[PIPE_WAIT_QUEUE_CAPACITY];
  size_t write_head;
  size_t write_tail;
  size_t write_count;

  int read_refs;
  int write_refs;
} pipe_t;

typedef struct pipe_endpoint {
  pipe_t *pipe;
  bool is_write;
  vfs_node_t node;
} pipe_endpoint_t;

static bool enqueue_reader(pipe_t *pipe, process_t *proc) {
  if (pipe->read_count >= PIPE_WAIT_QUEUE_CAPACITY) {
    return false;
  }
  pipe->read_waiters[pipe->read_tail] = proc;
  pipe->read_tail = (pipe->read_tail + 1) % PIPE_WAIT_QUEUE_CAPACITY;
  pipe->read_count++;
  return true;
}

static process_t *dequeue_reader(pipe_t *pipe) {
  if (pipe->read_count == 0) {
    return NULL;
  }
  process_t *proc = pipe->read_waiters[pipe->read_head];
  pipe->read_head = (pipe->read_head + 1) % PIPE_WAIT_QUEUE_CAPACITY;
  pipe->read_count--;
  return proc;
}

static bool enqueue_writer(pipe_t *pipe, process_t *proc) {
  if (pipe->write_count >= PIPE_WAIT_QUEUE_CAPACITY) {
    return false;
  }
  pipe->write_waiters[pipe->write_tail] = proc;
  pipe->write_tail = (pipe->write_tail + 1) % PIPE_WAIT_QUEUE_CAPACITY;
  pipe->write_count++;
  return true;
}

static process_t *dequeue_writer(pipe_t *pipe) {
  if (pipe->write_count == 0) {
    return NULL;
  }
  process_t *proc = pipe->write_waiters[pipe->write_head];
  pipe->write_head = (pipe->write_head + 1) % PIPE_WAIT_QUEUE_CAPACITY;
  pipe->write_count--;
  return proc;
}

static pipe_endpoint_t *endpoint_from_node(vfs_node_t *node) {
  if (!node) {
    return NULL;
  }
  return (pipe_endpoint_t *)node->ptr;
}

static size_t pipe_read_data(pipe_t *pipe, char *buffer, size_t count) {
  size_t read = 0;

  while (read < count) {
    irq_state_t irq = spin_lock_irqsave(&pipe->lock);

    while (pipe->count == 0) {
      if (pipe->write_refs == 0) {
        spin_unlock_irqrestore(&pipe->lock, irq);
        return read;
      }

      process_t *proc = process_get_current();
      if (!proc) {
        spin_unlock_irqrestore(&pipe->lock, irq);
        return read;
      }

      if (!enqueue_reader(pipe, proc)) {
        spin_unlock_irqrestore(&pipe->lock, irq);
        process_yield();
        irq = spin_lock_irqsave(&pipe->lock);
        continue;
      }

      proc->state = PROCESS_STATE_BLOCKED;
      spin_unlock_irqrestore(&pipe->lock, irq);
      process_yield();
      irq = spin_lock_irqsave(&pipe->lock);
    }

    char c = pipe->buffer[pipe->head];
    pipe->head = (pipe->head + 1) % PIPE_BUFFER_SIZE;
    pipe->count--;

    process_t *writer = dequeue_writer(pipe);

    spin_unlock_irqrestore(&pipe->lock, irq);

    buffer[read++] = c;

    if (writer) {
      process_wake(writer);
    }
  }

  return read;
}

static size_t pipe_write_data(pipe_t *pipe, const char *buffer, size_t count) {
  size_t written = 0;

  while (written < count) {
    irq_state_t irq = spin_lock_irqsave(&pipe->lock);

    while (pipe->count == PIPE_BUFFER_SIZE) {
      if (pipe->read_refs == 0) {
        spin_unlock_irqrestore(&pipe->lock, irq);
        return written;
      }

      process_t *proc = process_get_current();
      if (!proc) {
        spin_unlock_irqrestore(&pipe->lock, irq);
        return written;
      }

      if (!enqueue_writer(pipe, proc)) {
        spin_unlock_irqrestore(&pipe->lock, irq);
        process_yield();
        irq = spin_lock_irqsave(&pipe->lock);
        continue;
      }

      proc->state = PROCESS_STATE_BLOCKED;
      spin_unlock_irqrestore(&pipe->lock, irq);
      process_yield();
      irq = spin_lock_irqsave(&pipe->lock);
    }

    pipe->buffer[pipe->tail] = buffer[written++];
    pipe->tail = (pipe->tail + 1) % PIPE_BUFFER_SIZE;
    pipe->count++;

    process_t *reader = dequeue_reader(pipe);

    spin_unlock_irqrestore(&pipe->lock, irq);

    if (reader) {
      process_wake(reader);
    }
  }

  return written;
}

static uint32_t pipe_vfs_read(vfs_node_t *node, uint32_t offset, uint32_t size,
                              uint8_t *buffer) {
  (void)offset;
  pipe_endpoint_t *endpoint = endpoint_from_node(node);
  if (!endpoint || !buffer || size == 0 || endpoint->is_write) {
    return 0;
  }

  return (uint32_t)pipe_read_data(endpoint->pipe, (char *)buffer, size);
}

static uint32_t pipe_vfs_write(vfs_node_t *node, uint32_t offset, uint32_t size,
                               uint8_t *buffer) {
  (void)offset;
  pipe_endpoint_t *endpoint = endpoint_from_node(node);
  if (!endpoint || !buffer || size == 0 || !endpoint->is_write) {
    return 0;
  }

  return (uint32_t)pipe_write_data(endpoint->pipe, (const char *)buffer, size);
}

static void pipe_vfs_open(vfs_node_t *node, uint32_t flags) {
  (void)flags;
  pipe_endpoint_t *endpoint = endpoint_from_node(node);
  if (!endpoint) {
    return;
  }

  irq_state_t irq = spin_lock_irqsave(&endpoint->pipe->lock);
  if (endpoint->is_write) {
    endpoint->pipe->write_refs++;
  } else {
    endpoint->pipe->read_refs++;
  }
  spin_unlock_irqrestore(&endpoint->pipe->lock, irq);
}

static void pipe_wake_all(pipe_t *pipe, bool readers) {
  process_t *to_wake[PIPE_WAIT_QUEUE_CAPACITY];
  size_t count = 0;

  irq_state_t irq = spin_lock_irqsave(&pipe->lock);
  if (readers) {
    while (pipe->read_count > 0 && count < PIPE_WAIT_QUEUE_CAPACITY) {
      to_wake[count++] = dequeue_reader(pipe);
    }
  } else {
    while (pipe->write_count > 0 && count < PIPE_WAIT_QUEUE_CAPACITY) {
      to_wake[count++] = dequeue_writer(pipe);
    }
  }
  spin_unlock_irqrestore(&pipe->lock, irq);

  for (size_t i = 0; i < count; i++) {
    if (to_wake[i]) {
      process_wake(to_wake[i]);
    }
  }
}

static void pipe_destroy(pipe_t *pipe, pipe_endpoint_t *read_ep,
                         pipe_endpoint_t *write_ep) {
  if (read_ep) {
    kfree(read_ep);
  }
  if (write_ep) {
    kfree(write_ep);
  }
  kfree(pipe);
}

static void pipe_vfs_close(vfs_node_t *node) {
  pipe_endpoint_t *endpoint = endpoint_from_node(node);
  if (!endpoint) {
    return;
  }

  pipe_t *pipe = endpoint->pipe;
  bool free_pipe = false;

  irq_state_t irq = spin_lock_irqsave(&pipe->lock);
  if (endpoint->is_write) {
    if (pipe->write_refs > 0) {
      pipe->write_refs--;
    }
    if (pipe->write_refs == 0) {
      spin_unlock_irqrestore(&pipe->lock, irq);
      pipe_wake_all(pipe, true);
      irq = spin_lock_irqsave(&pipe->lock);
    }
  } else {
    if (pipe->read_refs > 0) {
      pipe->read_refs--;
    }
    if (pipe->read_refs == 0) {
      spin_unlock_irqrestore(&pipe->lock, irq);
      pipe_wake_all(pipe, false);
      irq = spin_lock_irqsave(&pipe->lock);
    }
  }

  if (pipe->read_refs == 0 && pipe->write_refs == 0) {
    free_pipe = true;
  }

  spin_unlock_irqrestore(&pipe->lock, irq);

  if (free_pipe) {
    pipe_destroy(pipe, endpoint->is_write ? NULL : endpoint,
                 endpoint->is_write ? endpoint : NULL);
  } else {
    if (endpoint->is_write) {
      kfree(endpoint);
    } else {
      kfree(endpoint);
    }
  }
}

int pipe_create(int *read_fd, int *write_fd) {
  if (!read_fd || !write_fd) {
    return -1;
  }

  pipe_t *pipe = kmalloc(sizeof(pipe_t));
  if (!pipe) {
    return -1;
  }
  memset(pipe, 0, sizeof(pipe_t));
  spinlock_init(&pipe->lock, "pipe");

  pipe_endpoint_t *read_ep = kmalloc(sizeof(pipe_endpoint_t));
  pipe_endpoint_t *write_ep = kmalloc(sizeof(pipe_endpoint_t));
  if (!read_ep || !write_ep) {
    if (read_ep)
      kfree(read_ep);
    if (write_ep)
      kfree(write_ep);
    kfree(pipe);
    return -1;
  }

  memset(read_ep, 0, sizeof(pipe_endpoint_t));
  memset(write_ep, 0, sizeof(pipe_endpoint_t));

  read_ep->pipe = pipe;
  read_ep->is_write = false;
  read_ep->node.type = VFS_PIPE;
  strcpy(read_ep->node.name, "pipe");
  read_ep->node.flags = VFS_READ;
  read_ep->node.read = pipe_vfs_read;
  read_ep->node.write = pipe_vfs_write;
  read_ep->node.open = pipe_vfs_open;
  read_ep->node.close = pipe_vfs_close;
  read_ep->node.ptr = read_ep;

  write_ep->pipe = pipe;
  write_ep->is_write = true;
  write_ep->node.type = VFS_PIPE;
  strcpy(write_ep->node.name, "pipe");
  write_ep->node.flags = VFS_WRITE;
  write_ep->node.read = pipe_vfs_read;
  write_ep->node.write = pipe_vfs_write;
  write_ep->node.open = pipe_vfs_open;
  write_ep->node.close = pipe_vfs_close;
  write_ep->node.ptr = write_ep;

  int read_handle = vfs_create_fd(&read_ep->node, VFS_READ);
  if (read_handle < 0) {
    kfree(read_ep);
    kfree(write_ep);
    kfree(pipe);
    return -1;
  }

  int write_handle = vfs_create_fd(&write_ep->node, VFS_WRITE);
  if (write_handle < 0) {
    vfs_close_fd(read_handle);
    kfree(write_ep);
    kfree(pipe);
    return -1;
  }

  *read_fd = read_handle;
  *write_fd = write_handle;
  return 0;
}
