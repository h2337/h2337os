bits 64
section .text

global context_switch

; void context_switch(context_t *old, context_t *new)
; RDI = old context pointer
; RSI = new context pointer
context_switch:
    ; Save old context if provided
    test rdi, rdi
    jz .load_new
    
    ; Save all general purpose registers
    mov [rdi + 0x00], r15
    mov [rdi + 0x08], r14
    mov [rdi + 0x10], r13
    mov [rdi + 0x18], r12
    mov [rdi + 0x20], r11
    mov [rdi + 0x28], r10
    mov [rdi + 0x30], r9
    mov [rdi + 0x38], r8
    mov [rdi + 0x40], rbp
    ; Save original RDI and RSI
    mov rax, rdi
    mov [rdi + 0x48], rax
    mov rax, rsi  
    mov [rdi + 0x50], rax
    mov [rdi + 0x58], rdx
    mov [rdi + 0x60], rcx
    mov [rdi + 0x68], rbx
    
    ; Save return address (where we'll return to after switch)
    mov rax, [rsp]
    mov [rdi + 0x78], rax
    
    ; Save stack pointer (pointing after return address)
    lea rax, [rsp + 8]
    mov [rdi + 0x90], rax
    
    ; Save RFLAGS
    pushfq
    pop qword [rdi + 0x88]

.load_new:
    ; Load new context if provided
    test rsi, rsi
    jz .done
    
    ; Load stack pointer
    mov rsp, [rsi + 0x90]
    
    ; Load RFLAGS
    push qword [rsi + 0x88]
    popfq
    
    ; Load general purpose registers
    mov r15, [rsi + 0x00]
    mov r14, [rsi + 0x08]
    mov r13, [rsi + 0x10]
    mov r12, [rsi + 0x18]
    mov r11, [rsi + 0x20]
    mov r10, [rsi + 0x28]
    mov r9,  [rsi + 0x30]
    mov r8,  [rsi + 0x38]
    mov rbp, [rsi + 0x40]
    mov rdi, [rsi + 0x48]
    mov rdx, [rsi + 0x58]
    mov rcx, [rsi + 0x60]
    mov rbx, [rsi + 0x68]
    
    ; Push return address onto stack
    push qword [rsi + 0x78]
    
    ; Load RSI last
    mov rsi, [rsi + 0x50]
    
    ; Return to the saved RIP
    ret

.done:
    ret