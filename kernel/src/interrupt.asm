[BITS 64]

extern exception_handler

%macro SAVE_REGS 0
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
%endmacro

%macro RESTORE_REGS 0
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
%endmacro

%macro ISR_NOERRCODE 1
global isr%1
isr%1:
    push qword 0
    push qword %1
    SAVE_REGS
    mov rdi, rsp
    call exception_handler
    RESTORE_REGS
    add rsp, 16
    iretq
%endmacro

%macro ISR_ERRCODE 1
global isr%1
isr%1:
    push qword %1
    SAVE_REGS
    mov rdi, rsp
    call exception_handler
    RESTORE_REGS
    add rsp, 16
    iretq
%endmacro

ISR_NOERRCODE 0
ISR_NOERRCODE 1
ISR_NOERRCODE 2
ISR_NOERRCODE 3
ISR_NOERRCODE 4
ISR_NOERRCODE 5
ISR_NOERRCODE 6
ISR_NOERRCODE 7
ISR_ERRCODE   8
ISR_NOERRCODE 9
ISR_ERRCODE   10
ISR_ERRCODE   11
ISR_ERRCODE   12
ISR_ERRCODE   13
ISR_ERRCODE   14
ISR_NOERRCODE 15
ISR_NOERRCODE 16
ISR_ERRCODE   17
ISR_NOERRCODE 18
ISR_NOERRCODE 19
ISR_NOERRCODE 20
ISR_NOERRCODE 21
ISR_NOERRCODE 22
ISR_NOERRCODE 23
ISR_NOERRCODE 24
ISR_NOERRCODE 25
ISR_NOERRCODE 26
ISR_NOERRCODE 27
ISR_NOERRCODE 28
ISR_NOERRCODE 29
ISR_ERRCODE   30
ISR_NOERRCODE 31

; IRQ handlers
ISR_NOERRCODE 32  ; IRQ0 - Timer
ISR_NOERRCODE 33  ; IRQ1 - Keyboard
ISR_NOERRCODE 34  ; IRQ2
ISR_NOERRCODE 35  ; IRQ3
ISR_NOERRCODE 36  ; IRQ4
ISR_NOERRCODE 37  ; IRQ5
ISR_NOERRCODE 38  ; IRQ6
ISR_NOERRCODE 39  ; IRQ7
ISR_NOERRCODE 40  ; IRQ8
ISR_NOERRCODE 41  ; IRQ9
ISR_NOERRCODE 42  ; IRQ10
ISR_NOERRCODE 43  ; IRQ11
ISR_NOERRCODE 44  ; IRQ12
ISR_NOERRCODE 45  ; IRQ13
ISR_NOERRCODE 46  ; IRQ14
ISR_NOERRCODE 47  ; IRQ15