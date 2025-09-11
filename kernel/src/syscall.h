#ifndef SYSCALL_H
#define SYSCALL_H

#include <stdint.h>

#define SYSCALL_EXIT 0
#define SYSCALL_WRITE 1
#define SYSCALL_READ 2
#define SYSCALL_OPEN 3
#define SYSCALL_CLOSE 4
#define SYSCALL_FORK 5
#define SYSCALL_EXECVE 6
#define SYSCALL_WAITPID 7
#define SYSCALL_GETPID 8
#define SYSCALL_GETPPID 9
#define SYSCALL_BRK 10
#define SYSCALL_MMAP 11
#define SYSCALL_MUNMAP 12
#define SYSCALL_TIME 13
#define SYSCALL_GETCWD 14
#define SYSCALL_CHDIR 15
#define SYSCALL_STAT 16
#define SYSCALL_FSTAT 17
#define SYSCALL_LSEEK 18
#define SYSCALL_IOCTL 19
#define SYSCALL_DUP 20
#define SYSCALL_DUP2 21
#define SYSCALL_PIPE 22
#define SYSCALL_MKDIR 23
#define SYSCALL_RMDIR 24
#define SYSCALL_UNLINK 25

void syscall_init(void);
uint64_t syscall_handler(uint64_t syscall_number, uint64_t arg1, uint64_t arg2,
                         uint64_t arg3, uint64_t arg4, uint64_t arg5);

#endif