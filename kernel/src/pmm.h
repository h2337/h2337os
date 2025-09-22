#ifndef PMM_H
#define PMM_H

#include <stddef.h>
#include <stdint.h>

#define PAGE_SIZE 4096

void pmm_init(void);
void *pmm_alloc(size_t pages);
void *pmm_alloc_zero(size_t pages);
void pmm_free(void *ptr, size_t pages);
size_t pmm_get_free_pages(void);
size_t pmm_get_total_pages(void);
size_t pmm_get_used_pages(void);
void pmm_mark_used(uint64_t phys_addr);
void pmm_mark_used_range(uint64_t phys_addr, size_t length);

#endif
