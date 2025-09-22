#include "limine_requests.h"
#include <limine.h>

__attribute__((used,
               section(".limine_requests"))) volatile LIMINE_BASE_REVISION(3);

__attribute__((
    used,
    section(".limine_requests"))) volatile struct limine_framebuffer_request
    framebuffer_request = {.id = LIMINE_FRAMEBUFFER_REQUEST, .revision = 0};

__attribute__((
    used, section(".limine_requests"))) volatile struct limine_memmap_request
    memmap_request = {.id = LIMINE_MEMMAP_REQUEST, .revision = 0};

__attribute__((used,
               section(".limine_requests"))) volatile struct limine_hhdm_request
    hhdm_request = {.id = LIMINE_HHDM_REQUEST, .revision = 0};

__attribute__((
    used, section(".limine_requests"))) volatile struct limine_module_request
    module_request = {.id = LIMINE_MODULE_REQUEST, .revision = 0};

__attribute__((
    used,
    section(
        ".limine_requests"))) volatile struct limine_executable_address_request
    kernel_address_request = {.id = LIMINE_EXECUTABLE_ADDRESS_REQUEST,
                              .revision = 0};

__attribute__((
    used,
    section(".limine_requests"))) volatile struct limine_executable_file_request
    kernel_file_request = {.id = LIMINE_EXECUTABLE_FILE_REQUEST, .revision = 0};

__attribute__((used, section(".limine_requests"))) volatile struct LIMINE_MP(
    request) smp_request = {.id = LIMINE_MP_REQUEST, .revision = 0, .flags = 0};

__attribute__((used, section(".limine_requests_"
                             "start"))) volatile LIMINE_REQUESTS_START_MARKER;

__attribute__((
    used, section(".limine_requests_end"))) volatile LIMINE_REQUESTS_END_MARKER;
