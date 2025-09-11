#ifndef VMM_H
#define VMM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VMM_PRESENT (1ULL << 0)
#define VMM_WRITABLE (1ULL << 1)
#define VMM_USER (1ULL << 2)
#define VMM_WRITE_THROUGH (1ULL << 3)
#define VMM_CACHE_DISABLE (1ULL << 4)
#define VMM_ACCESSED (1ULL << 5)
#define VMM_DIRTY (1ULL << 6)
#define VMM_HUGE_PAGE (1ULL << 7)
#define VMM_GLOBAL (1ULL << 8)
#define VMM_NO_EXECUTE (1ULL << 63)

#define PML4_GET_INDEX(addr) (((addr) >> 39) & 0x1FF)
#define PDP_GET_INDEX(addr) (((addr) >> 30) & 0x1FF)
#define PD_GET_INDEX(addr) (((addr) >> 21) & 0x1FF)
#define PT_GET_INDEX(addr) (((addr) >> 12) & 0x1FF)

typedef struct {
  uint64_t *pml4;
} page_table_t;

void vmm_init(void);
page_table_t *vmm_new_pagemap(void);
void vmm_switch_pagemap(page_table_t *pagemap);
bool vmm_map_page(page_table_t *pagemap, uint64_t virt, uint64_t phys,
                  uint64_t flags);
bool vmm_unmap_page(page_table_t *pagemap, uint64_t virt);
uint64_t vmm_get_phys(page_table_t *pagemap, uint64_t virt);
page_table_t *vmm_get_kernel_pagemap(void);

#endif