#ifndef LIMINE_REQUESTS_H
#define LIMINE_REQUESTS_H

#include <limine.h>

extern volatile struct limine_framebuffer_request framebuffer_request;
extern volatile struct limine_memmap_request memmap_request;
extern volatile struct limine_hhdm_request hhdm_request;
extern volatile uint64_t limine_base_revision[3];

#endif