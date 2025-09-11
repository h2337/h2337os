void _start() {
    const char msg[] = "Hello from ELF binary!\n";
    
    // Write syscall - syscall number 1 in rax, fd in rdi, buffer in rsi, count in rdx
    __asm__ volatile(
        "mov $1, %%rax\n"      // syscall number for write
        "mov $1, %%rdi\n"      // fd = stdout
        "mov %0, %%rsi\n"      // buffer
        "mov %1, %%rdx\n"      // count
        "int $0x80\n"
        :
        : "r"(msg), "r"((long)(sizeof(msg) - 1))
        : "rax", "rdi", "rsi", "rdx"
    );
    
    // Exit syscall - syscall number 0 in rax, exit code in rdi
    __asm__ volatile(
        "mov $0, %%rax\n"      // syscall number for exit
        "mov $0, %%rdi\n"      // exit code
        "int $0x80\n"
        :
        :
        : "rax", "rdi"
    );
    
    while(1);
}