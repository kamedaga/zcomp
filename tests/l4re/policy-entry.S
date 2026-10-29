.text
.global _start
.type _start, @function
_start:
    xor %ebp, %ebp
    mov (%rsp), %rdi
    lea 8(%rsp), %rsi
    and $-16, %rsp
    call policy_main
    mov %eax, %edi
    mov $60, %eax
    syscall
    ud2
.size _start, .-_start
.section .note.GNU-stack,"",@progbits
