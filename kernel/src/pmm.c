#include "pmm.h"
#include "console.h"
#include "libc.h"
#include "limine_requests.h"
#include <limine.h>
#include <stdbool.h>

static uint8_t *bitmap = NULL;
static size_t bitmap_size = 0;
static size_t total_pages = 0;
static size_t used_pages = 0;
static size_t last_index = 0;
static uint64_t hhdm_offset = 0;
static uint64_t highest_page_addr = 0;

static inline void bitmap_set(size_t index) {
  size_t byte_index = index / 8;
  size_t bit_index = index % 8;
  bitmap[byte_index] |= (1 << bit_index);
}

static inline void bitmap_clear(size_t index) {
  size_t byte_index = index / 8;
  size_t bit_index = index % 8;
  bitmap[byte_index] &= ~(1 << bit_index);
}

static inline bool bitmap_test(size_t index) {
  size_t byte_index = index / 8;
  size_t bit_index = index % 8;
  return (bitmap[byte_index] & (1 << bit_index)) != 0;
}

void pmm_init(void) {
  if (memmap_request.response == NULL ||
      memmap_request.response->entry_count == 0) {
    kprint("PMM: Failed to get memory map from bootloader\n");
    for (;;) {
      asm volatile("cli; hlt");
    }
  }

  if (hhdm_request.response == NULL) {
    kprint("PMM: Failed to get HHDM offset from bootloader\n");
    for (;;) {
      asm volatile("cli; hlt");
    }
  }

  hhdm_offset = hhdm_request.response->offset;

  struct limine_memmap_response *memmap = memmap_request.response;

  for (uint64_t i = 0; i < memmap->entry_count; i++) {
    struct limine_memmap_entry *entry = memmap->entries[i];
    if (entry->type == LIMINE_MEMMAP_USABLE) {
      uint64_t top = entry->base + entry->length;
      if (top > highest_page_addr) {
        highest_page_addr = top;
      }
    }
  }

  total_pages = (highest_page_addr + PAGE_SIZE - 1) / PAGE_SIZE;
  bitmap_size = (total_pages + 7) / 8;

  for (uint64_t i = 0; i < memmap->entry_count; i++) {
    struct limine_memmap_entry *entry = memmap->entries[i];
    if (entry->type == LIMINE_MEMMAP_USABLE) {
      if (entry->length >= bitmap_size) {
        bitmap = (uint8_t *)(entry->base + hhdm_offset);
        memset(bitmap, 0xFF, bitmap_size);

        entry->base += bitmap_size;
        entry->length -= bitmap_size;
        break;
      }
    }
  }

  if (bitmap == NULL) {
    kprint("PMM: Failed to allocate space for bitmap\n");
    for (;;) {
      asm volatile("cli; hlt");
    }
  }

  for (uint64_t i = 0; i < memmap->entry_count; i++) {
    struct limine_memmap_entry *entry = memmap->entries[i];
    if (entry->type == LIMINE_MEMMAP_USABLE ||
        entry->type == LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE) {
      for (uint64_t j = 0; j < entry->length; j += PAGE_SIZE) {
        bitmap_clear((entry->base + j) / PAGE_SIZE);
      }
    }
  }

  used_pages = 0;
  for (size_t i = 0; i < total_pages; i++) {
    if (bitmap_test(i)) {
      used_pages++;
    }
  }

  kprint("PMM: Initialized with ");
  kprint_hex(total_pages * PAGE_SIZE);
  kprint(" bytes total (");
  kprint_hex(total_pages);
  kprint(" pages)\n");
  kprint("PMM: ");
  kprint_hex((total_pages - used_pages) * PAGE_SIZE);
  kprint(" bytes free (");
  kprint_hex(total_pages - used_pages);
  kprint(" pages)\n");
  kprint("PMM: HHDM offset: 0x");
  kprint_hex(hhdm_offset);
  kprint("\n");
}

void *pmm_alloc(size_t pages) {
  if (pages == 0) {
    return NULL;
  }

  size_t consecutive = 0;
  size_t start_page = 0;

  for (size_t i = 0; i < total_pages; i++) {
    if (!bitmap_test(i)) {
      if (consecutive == 0) {
        start_page = i;
      }
      consecutive++;
      if (consecutive == pages) {
        for (size_t j = start_page; j < start_page + pages; j++) {
          bitmap_set(j);
        }
        used_pages += pages;
        last_index = start_page + pages;
        return (void *)(start_page * PAGE_SIZE);
      }
    } else {
      consecutive = 0;
    }
  }

  return NULL;
}

void *pmm_alloc_zero(size_t pages) {
  void *ptr = pmm_alloc(pages);
  if (ptr != NULL) {
    memset((void *)((uint64_t)ptr + hhdm_offset), 0, pages * PAGE_SIZE);
  }
  return ptr;
}

void pmm_free(void *ptr, size_t pages) {
  if (ptr == NULL || pages == 0) {
    return;
  }

  size_t page = (size_t)ptr / PAGE_SIZE;
  for (size_t i = 0; i < pages; i++) {
    if (page + i < total_pages && bitmap_test(page + i)) {
      bitmap_clear(page + i);
      used_pages--;
    }
  }
}

size_t pmm_get_free_pages(void) { return total_pages - used_pages; }

size_t pmm_get_total_pages(void) { return total_pages; }

size_t pmm_get_used_pages(void) { return used_pages; }