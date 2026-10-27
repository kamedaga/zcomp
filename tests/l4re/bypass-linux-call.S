.text
/* Linux側は明確な境界へ収束させ、native IPCとの比較で確実にshim入口を使う。 */
.global linux_call
.type linux_call, @function
linux_call:
    mov %rdi, %rax
    mov %rsi, %rdi
    mov %rdx, %rsi
    mov %rcx, %rdx
    mov %r8, %r10
    .rept 256
    nop
    .endr
    syscall
    ret
.size linux_call, .-linux_call
.section .note.GNU-stack,"",@progbits
