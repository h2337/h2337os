#include "elf.h"
#include "console.h"
#include "heap.h"
#include "libc.h"
#include "pmm.h"
#include "process.h"
#include "vfs.h"
#include "vmm.h"
#include <stddef.h>

extern void enter_usermode(void *entry_point, void *user_stack);

int elf_validate(const uint8_t *data) {
  if (!data)
    return 0;

  elf64_ehdr_t *ehdr = (elf64_ehdr_t *)data;

  if (*(uint32_t *)ehdr->e_ident != ELF_MAGIC) {
    return 0;
  }

  if (ehdr->e_ident[4] != ELF_CLASS_64) {
    return 0;
  }

  if (ehdr->e_ident[5] != ELF_DATA_2LSB) {
    return 0;
  }

  if (ehdr->e_ident[6] != ELF_VERSION_CURRENT) {
    return 0;
  }

  if (ehdr->e_machine != EM_X86_64) {
    return 0;
  }

  if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) {
    return 0;
  }

  return 1;
}

uint64_t elf_load(const uint8_t *data, uint64_t size) {
  if (!elf_validate(data)) {
    kprint("ELF: Invalid ELF header\n");
    return 0;
  }

  elf64_ehdr_t *ehdr = (elf64_ehdr_t *)data;
  elf64_phdr_t *phdr = (elf64_phdr_t *)(data + ehdr->e_phoff);

  uint64_t entry_point = ehdr->e_entry;

  if (ehdr->e_type == ET_DYN) {
    uint64_t base = 0x400000;
    entry_point += base;
  }

  page_table_t *current_pagemap = vmm_get_kernel_pagemap();

  for (uint16_t i = 0; i < ehdr->e_phnum; i++) {
    if (phdr[i].p_type != PT_LOAD)
      continue;

    // Debug output (commented out for cleaner execution)
    /*
    kprint("ELF: Loading segment ");
    kprint_hex(i);
    kprint("\n");
    kprint("  Virtual address: ");
    kprint_hex(phdr[i].p_vaddr);
    kprint("\n");
    kprint("  File offset: ");
    kprint_hex(phdr[i].p_offset);
    kprint("\n");
    kprint("  File size: ");
    kprint_hex(phdr[i].p_filesz);
    kprint("\n");
    kprint("  Memory size: ");
    kprint_hex(phdr[i].p_memsz);
    kprint("\n");
    */

    uint64_t vaddr = phdr[i].p_vaddr;
    if (ehdr->e_type == ET_DYN) {
      vaddr += 0x400000;
    }

    uint64_t pages_needed = (phdr[i].p_memsz + PAGE_SIZE - 1) / PAGE_SIZE;
    /*
    kprint("  Pages needed: ");
    kprint_hex(pages_needed);
    kprint("\n");
    */

    for (uint64_t j = 0; j < pages_needed; j++) {
      void *phys_ptr = pmm_alloc(1);
      if (!phys_ptr) {
        kprint("ELF: Failed to allocate physical page\n");
        return 0;
      }
      uint64_t phys = (uint64_t)phys_ptr;

      uint64_t flags = VMM_PRESENT | VMM_USER;
      if (phdr[i].p_flags & PF_W)
        flags |= VMM_WRITABLE;
      // Note: x86-64 doesn't have a separate execute bit for pages,
      // pages are executable by default unless NX bit is set.
      // We're not setting VMM_NO_EXECUTE for executable segments.

      if (!vmm_map_page(current_pagemap, vaddr + j * PAGE_SIZE, phys, flags)) {
        kprint("ELF: Failed to map page at ");
        kprint_hex(vaddr + j * PAGE_SIZE);
        kprint("\n");
        return 0;
      }
    }

    // Now we need to copy the data. Since we're in kernel space,
    // we need to access the physical memory directly or map it temporarily.
    // For now, let's map each page temporarily to copy the data.

    if (phdr[i].p_filesz > 0) {
      if (phdr[i].p_offset + phdr[i].p_filesz > size) {
        kprint("ELF: Segment extends beyond file\n");
        return 0;
      }

      // Copy data page by page
      uint64_t file_offset = phdr[i].p_offset;
      uint64_t virt_offset = 0;
      uint64_t bytes_to_copy = phdr[i].p_filesz;

      while (bytes_to_copy > 0) {
        uint64_t page_offset = virt_offset & 0xFFF;
        uint64_t copy_size = PAGE_SIZE - page_offset;
        if (copy_size > bytes_to_copy)
          copy_size = bytes_to_copy;

        // Get the physical address of this page
        uint64_t page_vaddr = vaddr + (virt_offset & ~0xFFF);
        uint64_t phys_addr = vmm_get_phys(current_pagemap, page_vaddr);

        if (!phys_addr) {
          kprint("ELF: Failed to get physical address for ");
          kprint_hex(page_vaddr);
          kprint("\n");
          return 0;
        }

        // Map the physical page temporarily at a high address
        uint64_t temp_vaddr = 0xFFFF900000000000 + phys_addr;
        if (!vmm_map_page(current_pagemap, temp_vaddr, phys_addr,
                          VMM_PRESENT | VMM_WRITABLE)) {
          kprint("ELF: Failed to create temporary mapping\n");
          return 0;
        }

        // Copy the data
        memcpy((void *)(temp_vaddr + page_offset), data + file_offset,
               copy_size);

        // Debug: Show first few bytes if this is the code segment (commented
        // out)
        /*
        if (virt_offset == 0 && i == 0) {
            kprint("  First bytes of segment: ");
            uint8_t *bytes = (uint8_t *)(temp_vaddr + page_offset);
            for (int k = 0; k < 16 && k < copy_size; k++) {
                kprint_hex(bytes[k]);
                kprint(" ");
            }
            kprint("\n");
        }
        */

        // Unmap the temporary mapping
        vmm_unmap_page(current_pagemap, temp_vaddr);

        file_offset += copy_size;
        virt_offset += copy_size;
        bytes_to_copy -= copy_size;
      }
    }

    // Zero out BSS section (memory beyond file size)
    if (phdr[i].p_memsz > phdr[i].p_filesz) {
      uint64_t zero_start = phdr[i].p_filesz;
      uint64_t zero_size = phdr[i].p_memsz - phdr[i].p_filesz;

      while (zero_size > 0) {
        uint64_t page_offset = zero_start & 0xFFF;
        uint64_t clear_size = PAGE_SIZE - page_offset;
        if (clear_size > zero_size)
          clear_size = zero_size;

        // Get the physical address of this page
        uint64_t page_vaddr = vaddr + (zero_start & ~0xFFF);
        uint64_t phys_addr = vmm_get_phys(current_pagemap, page_vaddr);

        if (!phys_addr) {
          kprint("ELF: Failed to get physical address for BSS at ");
          kprint_hex(page_vaddr);
          kprint("\n");
          return 0;
        }

        // Map the physical page temporarily
        uint64_t temp_vaddr = 0xFFFF900000000000 + phys_addr;
        if (!vmm_map_page(current_pagemap, temp_vaddr, phys_addr,
                          VMM_PRESENT | VMM_WRITABLE)) {
          kprint("ELF: Failed to create temporary mapping for BSS\n");
          return 0;
        }

        // Zero the memory
        memset((void *)(temp_vaddr + page_offset), 0, clear_size);

        // Unmap the temporary mapping
        vmm_unmap_page(current_pagemap, temp_vaddr);

        zero_start += clear_size;
        zero_size -= clear_size;
      }
    }
  }

  return entry_point;
}

int elf_exec(const char *path, char *const argv[], char *const envp[]) {
  vfs_node_t *file = vfs_open(path, VFS_READ);
  if (!file) {
    return -1;
  }

  if (file->type & VFS_DIRECTORY) {
    vfs_close(file);
    return -1;
  }

  uint8_t *buffer = kmalloc(file->size);
  if (!buffer) {
    kprint("ELF: Failed to allocate buffer\n");
    vfs_close(file);
    return -1;
  }

  uint32_t bytes_read = vfs_read(file, 0, file->size, buffer);
  vfs_close(file);

  if (bytes_read != file->size) {
    kprint("ELF: Failed to read complete file\n");
    kfree(buffer);
    return -1;
  }

  if (!elf_validate(buffer)) {
    kprint("ELF: Invalid ELF file\n");
    kfree(buffer);
    return -1;
  }

  process_t *current = process_get_current();
  if (!current) {
    kfree(buffer);
    return -1;
  }

  uint64_t user_stack = 0x7FFFFFFFE000;
  void *stack_phys_ptr = pmm_alloc(1);
  if (!stack_phys_ptr) {
    kfree(buffer);
    return -1;
  }
  uint64_t stack_phys = (uint64_t)stack_phys_ptr;

  page_table_t *current_pagemap = vmm_get_kernel_pagemap();
  if (!vmm_map_page(current_pagemap, user_stack, stack_phys,
                    VMM_PRESENT | VMM_WRITABLE | VMM_USER)) {
    kprint("ELF: Failed to map user stack\n");
    pmm_free(stack_phys_ptr, 1);
    kfree(buffer);
    return -1;
  }

  // Map the stack temporarily to set it up
  uint64_t temp_stack_vaddr = 0xFFFF900001000000;
  if (!vmm_map_page(current_pagemap, temp_stack_vaddr, stack_phys,
                    VMM_PRESENT | VMM_WRITABLE)) {
    kprint("ELF: Failed to create temporary stack mapping\n");
    pmm_free(stack_phys_ptr, 1);
    kfree(buffer);
    return -1;
  }

  // Set up stack at the temporary mapping
  uint64_t rsp = temp_stack_vaddr + PAGE_SIZE;

  int argc = 0;
  if (argv) {
    while (argv[argc])
      argc++;
  }

  // Build argv array on stack
  if (argc > 0) {
    // First, copy all strings to stack
    char *string_area = (char *)(rsp - 1024); // Reserve space for strings
    char *string_ptr = string_area;
    uint64_t *argv_array =
        (uint64_t *)(string_area - (argc + 1) * sizeof(uint64_t));

    for (int i = 0; i < argc; i++) {
      size_t len = strlen(argv[i]) + 1;
      memcpy(string_ptr, argv[i], len);
      // Calculate the user-space address for this string
      argv_array[i] =
          user_stack + PAGE_SIZE - 1024 + (string_ptr - string_area);
      string_ptr += len;
    }
    argv_array[argc] = 0;

    // Set up initial stack with argc and argv
    rsp = (uint64_t)argv_array;
    rsp -= sizeof(uint64_t);
    *(uint64_t *)rsp = user_stack + PAGE_SIZE - 1024 -
                       (argc + 1) * sizeof(uint64_t); // argv in user space

    rsp -= sizeof(uint64_t);
    *(uint64_t *)rsp = argc;
  } else {
    rsp -= sizeof(uint64_t);
    *(uint64_t *)rsp = 0; // argv
    rsp -= sizeof(uint64_t);
    *(uint64_t *)rsp = 0; // argc
  }

  // Align stack
  rsp &= ~0xF;

  // Calculate the actual user RSP
  uint64_t user_rsp = user_stack + (rsp - temp_stack_vaddr);

  // Unmap the temporary stack mapping
  vmm_unmap_page(current_pagemap, temp_stack_vaddr);

  uint64_t entry_point = elf_load(buffer, bytes_read);
  kfree(buffer);

  if (!entry_point) {
    kprint("ELF: Failed to load ELF segments\n");
    return -1;
  }

  strncpy(current->name, path, 63);
  current->name[63] = '\0';

  current->context.rip = entry_point;
  current->context.rsp = user_rsp;
  current->context.cs = 0x23; // User code segment
  current->context.ss = 0x1B; // User data segment
  current->context.rflags = 0x202;

  current->brk = (void *)0x10000000;
  current->brk_start = current->brk;

  (void)envp;

  // Actually jump to user mode and execute the program
  enter_usermode((void *)entry_point, (void *)user_rsp);

  // We'll only get here when the program exits via syscall

  return 0;
}