#include "heap.h"
#include "console.h"
#include "libc.h"
#include "pmm.h"
#include "sync.h"
#include "vmm.h"
#include <stddef.h>
#include <stdint.h>

#define HEAP_START 0xFFFF900000000000
#define HEAP_INITIAL_SIZE (16 * 1024 * 1024)
#define HEAP_MAGIC 0xDEADBEEF
#define MIN_BLOCK_SIZE 32
#define ALIGNMENT 16

typedef struct heap_block {
  size_t size;
  uint32_t magic;
  uint32_t free;
  struct heap_block *next;
  struct heap_block *prev;
} heap_block_t;

static heap_block_t *heap_start = NULL;
static uint64_t heap_end = 0;
static size_t heap_size = 0;

// Synchronization for heap operations
static spinlock_t heap_lock = SPINLOCK_INIT("heap");

static void expand_heap(size_t amount) {
  size_t pages_needed = (amount + PAGE_SIZE - 1) / PAGE_SIZE;
  page_table_t *kernel_pagemap = vmm_get_kernel_pagemap();

  for (size_t i = 0; i < pages_needed; i++) {
    void *phys_page = pmm_alloc(1);
    if (phys_page == NULL) {
      kprint("HEAP: Failed to allocate physical page\n");
      return;
    }

    if (!vmm_map_page(kernel_pagemap, heap_end + (i * PAGE_SIZE),
                      (uint64_t)phys_page, VMM_PRESENT | VMM_WRITABLE)) {
      kprint("HEAP: Failed to map page\n");
      pmm_free(phys_page, 1);
      return;
    }
  }

  heap_end += pages_needed * PAGE_SIZE;
  heap_size += pages_needed * PAGE_SIZE;
}

void heap_init(void) {
  heap_start = (heap_block_t *)HEAP_START;
  heap_end = HEAP_START;
  heap_size = 0;

  expand_heap(HEAP_INITIAL_SIZE);

  heap_start->size = heap_size - sizeof(heap_block_t);
  heap_start->magic = HEAP_MAGIC;
  heap_start->free = 1;
  heap_start->next = NULL;
  heap_start->prev = NULL;

  kprint("HEAP: Initialized at 0x");
  kprint_hex((uint64_t)heap_start);
  kprint(" with ");
  kprint_hex(heap_size);
  kprint(" bytes\n");
}

static heap_block_t *find_free_block(size_t size) {
  heap_block_t *current = heap_start;
  while (current != NULL) {
    if (current->free && current->size >= size) {
      return current;
    }
    current = current->next;
  }
  return NULL;
}

static void split_block(heap_block_t *block, size_t size) {
  if (block->size >= size + sizeof(heap_block_t) + MIN_BLOCK_SIZE) {
    heap_block_t *new_block =
        (heap_block_t *)((uint8_t *)block + sizeof(heap_block_t) + size);
    new_block->size = block->size - size - sizeof(heap_block_t);
    new_block->magic = HEAP_MAGIC;
    new_block->free = 1;
    new_block->next = block->next;
    new_block->prev = block;

    if (block->next) {
      block->next->prev = new_block;
    }

    block->size = size;
    block->next = new_block;
  }
}

static void merge_free_blocks(heap_block_t *block) {
  if (block->next && block->next->free) {
    block->size += sizeof(heap_block_t) + block->next->size;
    block->next = block->next->next;
    if (block->next) {
      block->next->prev = block;
    }
  }

  if (block->prev && block->prev->free) {
    block->prev->size += sizeof(heap_block_t) + block->size;
    block->prev->next = block->next;
    if (block->next) {
      block->next->prev = block->prev;
    }
  }
}

void *kmalloc(size_t size) {
  if (size == 0) {
    return NULL;
  }

  size = (size + ALIGNMENT - 1) & ~(ALIGNMENT - 1);

  // Lock heap for allocation
  spin_lock(&heap_lock);

  heap_block_t *block = find_free_block(size);

  if (block == NULL) {
    size_t needed = size + sizeof(heap_block_t);
    size_t expand_amount = (needed > HEAP_INITIAL_SIZE / 4)
                               ? needed + PAGE_SIZE
                               : HEAP_INITIAL_SIZE / 4;
    expand_heap(expand_amount);

    heap_block_t *last = heap_start;
    while (last->next != NULL) {
      last = last->next;
    }

    if (last->free) {
      last->size += expand_amount;
    } else {
      heap_block_t *new_block =
          (heap_block_t *)((uint8_t *)last + sizeof(heap_block_t) + last->size);
      new_block->size = expand_amount - sizeof(heap_block_t);
      new_block->magic = HEAP_MAGIC;
      new_block->free = 1;
      new_block->next = NULL;
      new_block->prev = last;
      last->next = new_block;
    }

    block = find_free_block(size);
    if (block == NULL) {
      spin_unlock(&heap_lock);
      return NULL;
    }
  }

  split_block(block, size);
  block->free = 0;

  spin_unlock(&heap_lock);
  return (void *)((uint8_t *)block + sizeof(heap_block_t));
}

void kfree(void *ptr) {
  if (ptr == NULL) {
    return;
  }

  heap_block_t *block = (heap_block_t *)((uint8_t *)ptr - sizeof(heap_block_t));

  if (block->magic != HEAP_MAGIC) {
    kprint("HEAP: Invalid magic in kfree\n");
    return;
  }

  // Lock heap for deallocation
  spin_lock(&heap_lock);
  block->free = 1;
  merge_free_blocks(block);
  spin_unlock(&heap_lock);
}

void *kcalloc(size_t num, size_t size) {
  size_t total_size = num * size;
  void *ptr = kmalloc(total_size);
  if (ptr != NULL) {
    memset(ptr, 0, total_size);
  }
  return ptr;
}

void *krealloc(void *ptr, size_t size) {
  if (ptr == NULL) {
    return kmalloc(size);
  }

  if (size == 0) {
    kfree(ptr);
    return NULL;
  }

  heap_block_t *block = (heap_block_t *)((uint8_t *)ptr - sizeof(heap_block_t));

  if (block->magic != HEAP_MAGIC) {
    return NULL;
  }

  if (block->size >= size) {
    return ptr;
  }

  void *new_ptr = kmalloc(size);
  if (new_ptr != NULL) {
    memcpy(new_ptr, ptr, block->size);
    kfree(ptr);
  }

  return new_ptr;
}