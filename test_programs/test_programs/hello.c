void _start() {
    const char msg[] = "Hello from ELF binary!\n";
    long syscall_num = 1;
    long fd = 1;
    long len = sizeof(msg) - 1;
    
    __asm__ volatile(
        "mov $0x80, %%eax\n"
        "mov %0, %%rdi\n"
        "mov %1, %%rsi\n"
        "mov %2, %%rdx\n"
        "mov %3, %%rcx\n"
        "int $0x80\n"
        :
        : "r"(syscall_num), "r"(fd), "r"(msg), "r"(len)
        : "rax", "rdi", "rsi", "rdx", "rcx"
    );
    
    syscall_num = 0;
    long exit_code = 0;
    
    __asm__ volatile(
        "mov $0x80, %%eax\n"
        "mov %0, %%rdi\n"
        "mov %1, %%rsi\n"
        "int $0x80\n"
        :
        : "r"(syscall_num), "r"(exit_code)
        : "rax", "rdi", "rsi"
    );
    
    while(1);
}
