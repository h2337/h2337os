#include "syscall.h"
#include "console.h"
#include "idt.h"
#include "process.h"
#include <stddef.h>

extern void syscall_entry(void);

static uint64_t sys_exit(int exit_code) {
  kprint("Process exiting with code: ");
  kprint_hex(exit_code);
  kprint("\n");

  // The assembly code will handle the actual exit
  return 0;
}

static uint64_t sys_write(int fd, const char *buf, size_t count) {
  if (fd == 1 || fd == 2) {
    for (size_t i = 0; i < count; i++) {
      kputchar(buf[i]);
    }
    return count;
  }
  return -1;
}

static uint64_t sys_read(int fd, char *buf, size_t count) {
  (void)fd;
  (void)buf;
  (void)count;
  return -1;
}

static uint64_t sys_open(const char *path, int flags, int mode) {
  (void)path;
  (void)flags;
  (void)mode;
  return -1;
}

static uint64_t sys_close(int fd) {
  (void)fd;
  return -1;
}

uint64_t syscall_handler(uint64_t syscall_number, uint64_t arg1, uint64_t arg2,
                         uint64_t arg3, uint64_t arg4, uint64_t arg5) {
  (void)arg4;
  (void)arg5;

  switch (syscall_number) {
  case SYSCALL_EXIT:
    return sys_exit((int)arg1);
  case SYSCALL_WRITE:
    return sys_write((int)arg1, (const char *)arg2, (size_t)arg3);
  case SYSCALL_READ:
    return sys_read((int)arg1, (char *)arg2, (size_t)arg3);
  case SYSCALL_OPEN:
    return sys_open((const char *)arg1, (int)arg2, (int)arg3);
  case SYSCALL_CLOSE:
    return sys_close((int)arg1);
  default:
    kprint("Unknown syscall: ");
    kprint_hex(syscall_number);
    kprint("\n");
    return -1;
  }
}

void syscall_init(void) {
  idt_set_gate(0x80, (uint64_t)syscall_entry, 0x08, 0xEE);

  kprint("Syscall handler initialized at interrupt 0x80\n");
}