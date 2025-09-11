#ifndef ELF_H
#define ELF_H

#include <stdint.h>

#define ELF_MAGIC 0x464C457F
#define ELF_CLASS_64 2
#define ELF_DATA_2LSB 1
#define ELF_VERSION_CURRENT 1
#define ELF_OSABI_SYSV 0

#define ET_EXEC 2
#define ET_DYN 3

#define EM_X86_64 62

#define PT_NULL 0
#define PT_LOAD 1
#define PT_DYNAMIC 2
#define PT_INTERP 3
#define PT_NOTE 4

#define PF_X 1
#define PF_W 2
#define PF_R 4

typedef struct {
  uint8_t e_ident[16];
  uint16_t e_type;
  uint16_t e_machine;
  uint32_t e_version;
  uint64_t e_entry;
  uint64_t e_phoff;
  uint64_t e_shoff;
  uint32_t e_flags;
  uint16_t e_ehsize;
  uint16_t e_phentsize;
  uint16_t e_phnum;
  uint16_t e_shentsize;
  uint16_t e_shnum;
  uint16_t e_shstrndx;
} __attribute__((packed)) elf64_ehdr_t;

typedef struct {
  uint32_t p_type;
  uint32_t p_flags;
  uint64_t p_offset;
  uint64_t p_vaddr;
  uint64_t p_paddr;
  uint64_t p_filesz;
  uint64_t p_memsz;
  uint64_t p_align;
} __attribute__((packed)) elf64_phdr_t;

int elf_validate(const uint8_t *data);
uint64_t elf_load(const uint8_t *data, uint64_t size);
int elf_exec(const char *path, char *const argv[], char *const envp[]);

#endif