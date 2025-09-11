[BITS 64]

global syscall_entry
extern syscall_handler
extern usermode_exit_return

section .text

syscall_entry:
    ; Save all registers
    push r15
    push r14
    push r13
    push r12
    push r11
    push r10
    push r9
    push r8
    push rbp
    push rdi
    push rsi
    push rdx
    push rcx
    push rbx
    push rax
    
    ; Set kernel data segments
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    
    ; Prepare arguments for C handler
    mov rdi, rax            ; syscall number
    mov rsi, rdi            ; arg1 (was in rdi before push)
    mov rdx, rsi            ; arg2 (was in rsi before push) 
    mov rcx, rdx            ; arg3 (was in rdx before push)
    mov r8, rcx             ; arg4 (was in rcx before push)
    mov r9, r8              ; arg5 (was in r8 before push)
    
    ; Get the actual register values from stack
    mov rdi, [rsp]          ; syscall number (original rax)
    mov rsi, [rsp + 5*8]    ; arg1 (original rdi)
    mov rdx, [rsp + 4*8]    ; arg2 (original rsi)
    mov rcx, [rsp + 3*8]    ; arg3 (original rdx)
    mov r8, [rsp + 2*8]     ; arg4 (original rcx)
    mov r9, [rsp + 7*8]     ; arg5 (original r8)
    
    ; Call C handler
    call syscall_handler
    
    ; Check if this was an exit syscall (syscall number 0)
    cmp qword [rsp], 0
    je .handle_exit
    
    ; Normal syscall return
    ; Save return value
    mov [rsp], rax
    
    ; Restore user data segments
    mov ax, 0x23
    mov ds, ax
    mov es, ax
    
    ; Restore all registers
    pop rax
    pop rbx
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    pop rbp
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15
    
    ; Return to user mode
    iretq

.handle_exit:
    ; Clean up stack (remove saved registers and interrupt frame)
    add rsp, 15*8           ; Remove saved registers
    add rsp, 5*8            ; Remove interrupt frame
    
    ; Jump to usermode exit handler
    jmp usermode_exit_return