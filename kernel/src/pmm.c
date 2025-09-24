#include "pmm.h"
#include "console.h"
#include "libc.h"
#include "limine_requests.h"
#include "sync.h"
#include <limine.h>
#include <stdbool.h>
#include <stdint.h>

static uint8_t *bitmap = NULL;
static uint32_t *page_refcounts = NULL;
static size_t bitmap_size = 0;
static size_t total_pages = 0;
static size_t used_pages = 0;
static size_t last_index = 0;
static uint64_t hhdm_offset = 0;
static uint64_t highest_page_addr = 0;
static spinlock_t pmm_lock = SPINLOCK_INIT("pmm");

extern char __kernel_start[];
extern char __kernel_end[];

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

static uint32_t ref_inc_page(size_t page) {
  if (page >= total_pages) {
    return 0;
  }

  if (!bitmap_test(page)) {
    bitmap_set(page);
    used_pages++;
    if (page_refcounts) {
      page_refcounts[page] = 1;
      return 1;
    }
    return 1;
  }

  if (!page_refcounts) {
    return 1;
  }

  if (page_refcounts[page] == 0) {
    page_refcounts[page] = 1;
    return 1;
  }

  if (page_refcounts[page] < UINT32_MAX) {
    page_refcounts[page]++;
  }
  return page_refcounts[page];
}

static uint32_t ref_dec_page(size_t page) {
  if (page >= total_pages) {
    return 0;
  }

  if (!bitmap_test(page)) {
    if (page_refcounts) {
      page_refcounts[page] = 0;
    }
    return 0;
  }

  uint32_t count = 0;
  if (page_refcounts) {
    count = page_refcounts[page];
    if (count > 0) {
      count--;
      page_refcounts[page] = count;
    }
  } else {
    count = 1;
  }

  if (count > 0) {
    return count;
  }

  bitmap_clear(page);
  if (used_pages > 0) {
    used_pages--;
  }
  if (page_refcounts) {
    page_refcounts[page] = 0;
  }
  return 0;
}

static uint32_t ref_get_page(size_t page) {
  if (!page_refcounts || page >= total_pages) {
    return bitmap_test(page) ? 1 : 0;
  }
  return page_refcounts[page];
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

  size_t bitmap_aligned =
      (bitmap_size + sizeof(uint32_t) - 1) & ~(sizeof(uint32_t) - 1);
  size_t refcount_size = total_pages * sizeof(uint32_t);
  size_t metadata_size = bitmap_aligned + refcount_size;
  size_t metadata_bytes = (metadata_size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

  for (uint64_t i = 0; i < memmap->entry_count; i++) {
    struct limine_memmap_entry *entry = memmap->entries[i];
    if (entry->type == LIMINE_MEMMAP_USABLE &&
        entry->length >= metadata_bytes) {
      uint64_t metadata_phys = entry->base;
      bitmap = (uint8_t *)(metadata_phys + hhdm_offset);
      memset(bitmap, 0xFF, bitmap_size);
      if (bitmap_aligned > bitmap_size) {
        memset(bitmap + bitmap_size, 0, bitmap_aligned - bitmap_size);
      }

      page_refcounts =
          (uint32_t *)(metadata_phys + bitmap_aligned + hhdm_offset);
      memset(page_refcounts, 0, refcount_size);

      entry->base += metadata_bytes;
      entry->length -= metadata_bytes;
      break;
    }
  }

  if (bitmap == NULL || page_refcounts == NULL) {
    kprint("PMM: Failed to allocate space for metadata\n");
    for (;;) {
      asm volatile("cli; hlt");
    }
  }

  used_pages = total_pages;
  for (size_t i = 0; i < total_pages; i++) {
    page_refcounts[i] = 1;
  }

  for (uint64_t i = 0; i < memmap->entry_count; i++) {
    struct limine_memmap_entry *entry = memmap->entries[i];
    if (entry->type == LIMINE_MEMMAP_USABLE ||
        entry->type == LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE) {
      for (uint64_t j = 0; j < entry->length; j += PAGE_SIZE) {
        uint64_t page = (entry->base + j) / PAGE_SIZE;
        if (page >= total_pages || page == 0) {
          continue;
        }
        if (bitmap_test(page)) {
          bitmap_clear(page);
          if (used_pages > 0) {
            used_pages--;
          }
        }
        page_refcounts[page] = 0;
      }
    }
  }

  bitmap_set(0);
  page_refcounts[0] = 1;

  if (kernel_address_request.response != NULL &&
      kernel_file_request.response != NULL &&
      kernel_file_request.response->executable_file != NULL) {
    struct limine_executable_address_response *addr_resp =
        kernel_address_request.response;
    struct limine_file *kernel_file =
        kernel_file_request.response->executable_file;

    uint64_t kernel_phys_start =
        addr_resp->physical_base +
        ((uint64_t)__kernel_start - addr_resp->virtual_base);
    uint64_t kernel_size = (uint64_t)__kernel_end - (uint64_t)__kernel_start;
    pmm_mark_used_range(kernel_phys_start, kernel_size);
    kprint("PMM: reserved kernel phys 0x");
    kprint_hex(kernel_phys_start);
    kprint(" size 0x");
    kprint_hex(kernel_size);
    kprint("\n");

    if (kernel_file->address != NULL && kernel_file->size > 0) {
      uint64_t kernel_file_phys =
          (uint64_t)kernel_file->address >= hhdm_offset
              ? (uint64_t)kernel_file->address - hhdm_offset
              : (uint64_t)kernel_file->address;
      pmm_mark_used_range(kernel_file_phys, kernel_file->size);
      kprint("PMM: reserved kernel file 0x");
      kprint_hex(kernel_file_phys);
      kprint(" size 0x");
      kprint_hex(kernel_file->size);
      kprint("\n");
    }
  }

  if (module_request.response != NULL) {
    for (uint64_t i = 0; i < module_request.response->module_count; i++) {
      struct limine_file *mod = module_request.response->modules[i];
      if (!mod || mod->address == NULL || mod->size == 0) {
        continue;
      }
      uint64_t mod_phys = (uint64_t)mod->address >= hhdm_offset
                              ? (uint64_t)mod->address - hhdm_offset
                              : (uint64_t)mod->address;
      pmm_mark_used_range(mod_phys, mod->size);
      kprint("PMM: reserved module 0x");
      kprint_hex(mod_phys);
      kprint(" size 0x");
      kprint_hex(mod->size);
      kprint("\n");
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

  spin_lock(&pmm_lock);

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
          if (page_refcounts) {
            page_refcounts[j] = 1;
          }
        }
        used_pages += pages;
        last_index = start_page + pages;
        void *addr = (void *)(start_page * PAGE_SIZE);
        spin_unlock(&pmm_lock);
        return addr;
      }
    } else {
      consecutive = 0;
    }
  }

  kprint("PMM: alloc failed (pages: 0x");
  kprint_hex(pages);
  kprint(") free: 0x");
  kprint_hex(total_pages - used_pages);
  kprint(" used: 0x");
  kprint_hex(used_pages);
  kprint(" total: 0x");
  kprint_hex(total_pages);
  kprint("\n");
  spin_unlock(&pmm_lock);
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

  spin_lock(&pmm_lock);

  size_t page = (size_t)ptr / PAGE_SIZE;
  for (size_t i = 0; i < pages; i++) {
    size_t idx = page + i;
    if (idx < total_pages) {
      ref_dec_page(idx);
    }
  }

  spin_unlock(&pmm_lock);
}

size_t pmm_get_free_pages(void) { return total_pages - used_pages; }

size_t pmm_get_total_pages(void) { return total_pages; }

size_t pmm_get_used_pages(void) { return used_pages; }

void pmm_mark_used(uint64_t phys_addr) {
  size_t page = phys_addr / PAGE_SIZE;
  if (page >= total_pages) {
    return;
  }

  spin_lock(&pmm_lock);
  if (!bitmap_test(page)) {
    bitmap_set(page);
    used_pages++;
    if (page_refcounts) {
      page_refcounts[page] = 1;
    }
  } else if (page_refcounts && page_refcounts[page] == 0) {
    page_refcounts[page] = 1;
  }
  spin_unlock(&pmm_lock);
}

void pmm_mark_used_range(uint64_t phys_addr, size_t length) {
  if (length == 0) {
    return;
  }

  uint64_t end = phys_addr + length - 1;
  size_t start_page = phys_addr / PAGE_SIZE;
  size_t end_page = end / PAGE_SIZE;
  size_t count = end_page - start_page + 1;

  spin_lock(&pmm_lock);
  for (size_t i = 0; i < count; i++) {
    size_t page = start_page + i;
    if (page >= total_pages) {
      break;
    }
    if (!bitmap_test(page)) {
      bitmap_set(page);
      used_pages++;
      if (page_refcounts) {
        page_refcounts[page] = 1;
      }
    } else if (page_refcounts && page_refcounts[page] == 0) {
      page_refcounts[page] = 1;
    }
  }
  spin_unlock(&pmm_lock);
}

uint32_t pmm_ref_inc(uint64_t phys_addr) {
  size_t page = phys_addr / PAGE_SIZE;
  spin_lock(&pmm_lock);
  uint32_t count = ref_inc_page(page);
  spin_unlock(&pmm_lock);
  return count;
}

uint32_t pmm_ref_dec(uint64_t phys_addr) {
  size_t page = phys_addr / PAGE_SIZE;
  spin_lock(&pmm_lock);
  uint32_t count = ref_dec_page(page);
  spin_unlock(&pmm_lock);
  return count;
}

uint32_t pmm_ref_get(uint64_t phys_addr) {
  size_t page = phys_addr / PAGE_SIZE;
  spin_lock(&pmm_lock);
  uint32_t count = ref_get_page(page);
  spin_unlock(&pmm_lock);
  return count;
}
