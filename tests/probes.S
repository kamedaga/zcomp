.text
.globl probe_syscall6
.type probe_syscall6,@function
probe_syscall6:
    mov %rdi, %rax
    mov %rsi, %rdi
    mov %rdx, %rsi
    mov %rcx, %rdx
    mov %r8, %r10
    mov %r9, %r8
    mov 8(%rsp), %r9
    .rept 32
    nop
    .endr
.globl probe_site
probe_site:
    syscall
    ret
.size probe_syscall6, .-probe_syscall6

.globl probe_registers
.type probe_registers,@function
probe_registers:
    push %rbx
    push %rbp
    push %r12
    push %r13
    push %r14
    push %r15
    mov $1, %rdi
    mov $2, %rsi
    mov $3, %rdx
    mov $4, %r10
    mov $5, %r8
    mov $6, %r9
    mov $7, %rbx
    mov $8, %rbp
    mov $9, %r12
    mov $10, %r13
    mov $11, %r14
    mov $12, %r15
    pcmpeqb %xmm0, %xmm0
    pcmpeqb %xmm15, %xmm15
    mov $39, %eax
    .rept 32
    nop
    .endr
.globl probe_regs_site
probe_regs_site:
    syscall
    cmp $1, %rdi
    jne .Lbad
    cmp $2, %rsi
    jne .Lbad
    cmp $3, %rdx
    jne .Lbad
    cmp $4, %r10
    jne .Lbad
    cmp $5, %r8
    jne .Lbad
    cmp $6, %r9
    jne .Lbad
    cmp $7, %rbx
    jne .Lbad
    cmp $8, %rbp
    jne .Lbad
    cmp $9, %r12
    jne .Lbad
    cmp $10, %r13
    jne .Lbad
    cmp $11, %r14
    jne .Lbad
    cmp $12, %r15
    jne .Lbad
    pmovmskb %xmm0, %eax
    cmp $65535, %eax
    jne .Lbad
    pmovmskb %xmm15, %eax
    cmp $65535, %eax
    jne .Lbad
    xor %eax, %eax
    jmp .Ldone
.Lbad:
    mov $1, %eax
.Ldone:
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbp
    pop %rbx
    ret
.size probe_registers, .-probe_registers

/* 静的な直線デコードではmovabsの即値に見える場所へ実際には分岐する。
 * 命令境界の収束は、すべての実行入口を発見した証明にはならない。 */
.globl probe_overlapping
.type probe_overlapping,@function
probe_overlapping:
    mov $39, %eax
    jmp probe_overlapping_site
    .rept 256
    nop
    .endr
    .byte 0x48, 0xb8
.globl probe_overlapping_site
probe_overlapping_site:
    syscall
    ret
    .byte 0, 0, 0, 0, 0
.size probe_overlapping, .-probe_overlapping

.section .note.GNU-stack,"",@progbits
