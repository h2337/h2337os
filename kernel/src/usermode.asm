[BITS 64]

global enter_usermode
global usermode_exit_return

section .bss
kernel_rsp: resq 1

section .text

enter_usermode:
    ; rdi = entry point
    ; rsi = user stack
    
    ; Save kernel stack pointer
    mov [kernel_rsp], rsp
    
    ; Switch to user stack and prepare for iretq
    mov rcx, rdi            ; Save entry point
    mov rsp, rsi            ; Switch to user stack
    
    ; Load user segments
    mov ax, 0x23
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    
    ; Build iretq stack frame
    push 0x23               ; SS
    push rsi                ; RSP
    pushfq
    pop rax
    or rax, 0x200           ; Enable interrupts
    push rax                ; RFLAGS
    push 0x1B               ; CS
    push rcx                ; RIP
    
    ; Enter user mode
    iretq

usermode_exit_return:
    ; This is called from the syscall handler when exit is requested
    ; Restore kernel segments
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    
    ; Restore kernel stack
    mov rsp, [kernel_rsp]
    
    ; Make sure interrupts are enabled
    sti
    
    ; Return to the caller of enter_usermode
    ret