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
                                bool allocate) {
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
    current_level[index] = entry;
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

  uint64_t *pdp = get_next_level(pagemap->pml4, pml4_index, true);
  if (pdp == NULL)
    return false;

  uint64_t *pd = get_next_level(pdp, pdp_index, true);
  if (pd == NULL)
    return false;

  uint64_t *pt = get_next_level(pd, pd_index, true);
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

  uint64_t *pdp = get_next_level(pagemap->pml4, pml4_index, false);
  if (pdp == NULL)
    return false;

  uint64_t *pd = get_next_level(pdp, pdp_index, false);
  if (pd == NULL)
    return false;

  uint64_t *pt = get_next_level(pd, pd_index, false);
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

  uint64_t *pdp = get_next_level(pagemap->pml4, pml4_index, false);
  if (pdp == NULL)
    return 0;

  uint64_t *pd = get_next_level(pdp, pdp_index, false);
  if (pd == NULL)
    return 0;

  uint64_t *pt = get_next_level(pd, pd_index, false);
  if (pt == NULL)
    return 0;

  if (!(pt[pt_index] & VMM_PRESENT)) {
    return 0;
  }

  return pt[pt_index] & 0x000FFFFFFFFFF000;
}

page_table_t *vmm_get_kernel_pagemap(void) { return &kernel_pagemap; }