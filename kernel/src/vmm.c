#include "vmm.h"
#include "console.h"
#include "libc.h"
#include "limine_requests.h"
#include "pmm.h"
#include <limine.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

static page_table_t kernel_pagemap;
static uint64_t hhdm_offset = 0;

static uint64_t *get_next_level(uint64_t *current_level, size_t index,
                                bool allocate, uint64_t flags) {
  uint64_t entry = current_level[index];

  if (!(entry & VMM_PRESENT)) {
    if (!allocate) {
      return NULL;
    }

    void *new_page = pmm_alloc_zero(1);
    if (new_page == NULL) {
      return NULL;
    }

    entry = (uint64_t)new_page | VMM_PRESENT | VMM_WRITABLE;
    if (flags & VMM_USER) {
      entry |= VMM_USER;
    }
    current_level[index] = entry;
  } else if ((flags & VMM_USER) && !(entry & VMM_USER)) {
    current_level[index] |= VMM_USER;
  }

  return (uint64_t *)((entry & 0x000FFFFFFFFFF000) + hhdm_offset);
}

void vmm_init(void) {
  if (hhdm_request.response == NULL) {
    kprint("VMM: Failed to get HHDM offset\n");
    for (;;) {
      asm volatile("cli; hlt");
    }
  }

  hhdm_offset = hhdm_request.response->offset;

  uint64_t cr3;
  asm volatile("mov %%cr3, %0" : "=r"(cr3));
  kernel_pagemap.pml4 = (uint64_t *)(cr3 + hhdm_offset);

  kprint("VMM: Initialized with kernel PML4 at 0x");
  kprint_hex(cr3);
  kprint("\n");
  kprint("VMM: Virtual PML4 address: 0x");
  kprint_hex((uint64_t)kernel_pagemap.pml4);
  kprint("\n");
}

page_table_t *vmm_new_pagemap(void) {
  page_table_t *pagemap =
      (page_table_t *)((uint64_t)pmm_alloc_zero(1) + hhdm_offset);
  if (pagemap == NULL) {
    return NULL;
  }

  void *pml4_phys = pmm_alloc_zero(1);
  if (pml4_phys == NULL) {
    pmm_free((void *)((uint64_t)pagemap - hhdm_offset), 1);
    return NULL;
  }

  pagemap->pml4 = (uint64_t *)((uint64_t)pml4_phys + hhdm_offset);

  for (size_t i = 256; i < 512; i++) {
    pagemap->pml4[i] = kernel_pagemap.pml4[i];
  }

  return pagemap;
}

static void free_table_level(uint64_t *table, int level) {
  if (!table) {
    return;
  }

  for (size_t i = 0; i < 512; i++) {
    uint64_t entry = table[i];
    if (!(entry & VMM_PRESENT)) {
      continue;
    }

    uint64_t phys = entry & 0x000FFFFFFFFFF000ULL;

    if (level > 1 && !(entry & VMM_HUGE_PAGE)) {
      uint64_t *next = (uint64_t *)(phys + hhdm_offset);
      free_table_level(next, level - 1);
      pmm_free((void *)phys, 1);
    } else {
      size_t page_count = 1;
      if (entry & VMM_HUGE_PAGE) {
        if (level == 2) {
          page_count = 512; // 2MiB page
        } else if (level == 3) {
          page_count = 512 * 512; // 1GiB page
        }
      }
      pmm_free((void *)phys, page_count);
    }

    table[i] = 0;
  }
}

void vmm_destroy_pagemap(page_table_t *pagemap) {
  if (!pagemap || pagemap == &kernel_pagemap || !pagemap->pml4) {
    return;
  }

  for (size_t i = 0; i < 256; i++) {
    uint64_t entry = pagemap->pml4[i];
    if (!(entry & VMM_PRESENT)) {
      continue;
    }

    uint64_t phys = entry & 0x000FFFFFFFFFF000ULL;
    uint64_t *next = (uint64_t *)(phys + hhdm_offset);
    free_table_level(next, 3);
    pmm_free((void *)phys, 1);
    pagemap->pml4[i] = 0;
  }

  void *pml4_phys = (void *)((uint64_t)pagemap->pml4 - hhdm_offset);
  pmm_free(pml4_phys, 1);
  pmm_free((void *)((uint64_t)pagemap - hhdm_offset), 1);
}

page_table_t *vmm_clone_user_pagemap(page_table_t *source) {
  if (!source || !source->pml4) {
    return NULL;
  }

  page_table_t *clone = vmm_new_pagemap();
  if (!clone) {
    return NULL;
  }

  const uint64_t phys_mask = 0x000FFFFFFFFFF000ULL;
  const uint64_t flags_mask = VMM_WRITABLE | VMM_USER | VMM_WRITE_THROUGH |
                              VMM_CACHE_DISABLE | VMM_GLOBAL | VMM_NO_EXECUTE;

  for (size_t pml4_index = 0; pml4_index < 256; pml4_index++) {
    uint64_t pml4_entry = source->pml4[pml4_index];
    if (!(pml4_entry & VMM_PRESENT)) {
      continue;
    }
    if (pml4_entry & VMM_HUGE_PAGE) {
      vmm_destroy_pagemap(clone);
      return NULL;
    }

    uint64_t *src_pdp = (uint64_t *)((pml4_entry & phys_mask) + hhdm_offset);

    for (size_t pdp_index = 0; pdp_index < 512; pdp_index++) {
      uint64_t pdp_entry = src_pdp[pdp_index];
      if (!(pdp_entry & VMM_PRESENT)) {
        continue;
      }
      if (pdp_entry & VMM_HUGE_PAGE) {
        vmm_destroy_pagemap(clone);
        return NULL;
      }

      uint64_t *src_pd = (uint64_t *)((pdp_entry & phys_mask) + hhdm_offset);

      for (size_t pd_index = 0; pd_index < 512; pd_index++) {
        uint64_t pd_entry = src_pd[pd_index];
        if (!(pd_entry & VMM_PRESENT)) {
          continue;
        }

        if (pd_entry & VMM_HUGE_PAGE) {
          vmm_destroy_pagemap(clone);
          return NULL;
        }

        uint64_t *src_pt = (uint64_t *)((pd_entry & phys_mask) + hhdm_offset);

        for (size_t pt_index = 0; pt_index < 512; pt_index++) {
          uint64_t pt_entry = src_pt[pt_index];
          if (!(pt_entry & VMM_PRESENT)) {
            continue;
          }

          if (pt_entry & VMM_HUGE_PAGE) {
            vmm_destroy_pagemap(clone);
            return NULL;
          }

          uint64_t virt =
              ((uint64_t)pml4_index << 39) | ((uint64_t)pdp_index << 30) |
              ((uint64_t)pd_index << 21) | ((uint64_t)pt_index << 12);

          uint64_t phys_src = pt_entry & phys_mask;

          void *phys_dst_ptr = pmm_alloc(1);
          if (!phys_dst_ptr) {
            vmm_destroy_pagemap(clone);
            return NULL;
          }

          uint64_t phys_dst = (uint64_t)phys_dst_ptr;
          memcpy((void *)(phys_dst + hhdm_offset),
                 (void *)(phys_src + hhdm_offset), PAGE_SIZE);

          uint64_t flags = (pt_entry & flags_mask) | VMM_PRESENT;

          if (!vmm_map_page(clone, virt, phys_dst, flags)) {
            pmm_free(phys_dst_ptr, 1);
            vmm_destroy_pagemap(clone);
            return NULL;
          }
        }
      }
    }
  }

  return clone;
}

void vmm_switch_pagemap(page_table_t *pagemap) {
  uint64_t cr3 = (uint64_t)pagemap->pml4 - hhdm_offset;
  asm volatile("mov %0, %%cr3" : : "r"(cr3) : "memory");
}

bool vmm_map_page(page_table_t *pagemap, uint64_t virt, uint64_t phys,
                  uint64_t flags) {
  size_t pml4_index = PML4_GET_INDEX(virt);
  size_t pdp_index = PDP_GET_INDEX(virt);
  size_t pd_index = PD_GET_INDEX(virt);
  size_t pt_index = PT_GET_INDEX(virt);

  uint64_t *pdp = get_next_level(pagemap->pml4, pml4_index, true, flags);
  if (pdp == NULL)
    return false;

  uint64_t *pd = get_next_level(pdp, pdp_index, true, flags);
  if (pd == NULL)
    return false;

  uint64_t *pt = get_next_level(pd, pd_index, true, flags);
  if (pt == NULL)
    return false;

  pt[pt_index] = phys | flags | VMM_PRESENT;

  asm volatile("invlpg (%0)" : : "r"(virt) : "memory");

  return true;
}

bool vmm_unmap_page(page_table_t *pagemap, uint64_t virt) {
  size_t pml4_index = PML4_GET_INDEX(virt);
  size_t pdp_index = PDP_GET_INDEX(virt);
  size_t pd_index = PD_GET_INDEX(virt);
  size_t pt_index = PT_GET_INDEX(virt);

  uint64_t *pdp = get_next_level(pagemap->pml4, pml4_index, false, 0);
  if (pdp == NULL)
    return false;

  uint64_t *pd = get_next_level(pdp, pdp_index, false, 0);
  if (pd == NULL)
    return false;

  uint64_t *pt = get_next_level(pd, pd_index, false, 0);
  if (pt == NULL)
    return false;

  if (!(pt[pt_index] & VMM_PRESENT)) {
    return false;
  }

  pt[pt_index] = 0;

  asm volatile("invlpg (%0)" : : "r"(virt) : "memory");

  return true;
}

uint64_t vmm_get_phys(page_table_t *pagemap, uint64_t virt) {
  size_t pml4_index = PML4_GET_INDEX(virt);
  size_t pdp_index = PDP_GET_INDEX(virt);
  size_t pd_index = PD_GET_INDEX(virt);
  size_t pt_index = PT_GET_INDEX(virt);

  uint64_t *pdp = get_next_level(pagemap->pml4, pml4_index, false, 0);
  if (pdp == NULL)
    return 0;

  uint64_t *pd = get_next_level(pdp, pdp_index, false, 0);
  if (pd == NULL)
    return 0;

  uint64_t *pt = get_next_level(pd, pd_index, false, 0);
  if (pt == NULL)
    return 0;

  if (!(pt[pt_index] & VMM_PRESENT)) {
    return 0;
  }

  return pt[pt_index] & 0x000FFFFFFFFFF000;
}

page_table_t *vmm_get_kernel_pagemap(void) { return &kernel_pagemap; }
