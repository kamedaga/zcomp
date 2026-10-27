.text
/* probe_clone(nr, arg1, arg2, child_tid, context)は親だけが呼び出し元へ戻る。
 * 新スタックに戻り番地はなく、共有スタックでも子が親のCフレームへreturnしては
 * いけないため、子はレジスタ検査後に専用処理へ進む。 */
.globl probe_clone
.type probe_clone,@function
probe_clone:
    push %rbx
    push %rbp
    push %r12
    push %r13
    push %r14
    push %r15
    mov %rdi, %rax
    mov %rsi, %rdi
    mov %rdx, %rsi
    xor %edx, %edx
    mov %rcx, %r10
    mov %r8, %r9
    /* 共有スタック型では引数でtopを渡さず、syscall直前のRSPを期待値にする。
     * 子がこの下の領域を再利用しても、親のレジスタ・RSPの復帰を検査できる。 */
    cmpq $0, (%r9)
    jne .Lclone_top_set
    mov %rsp, (%r9)
.Lclone_top_set:
    xor %r8d, %r8d
    mov $7, %ebx
    mov $8, %ebp
    mov $9, %r12d
    mov $10, %r13d
    mov $11, %r14d
    mov $12, %r15d
    pcmpeqb %xmm0, %xmm0
    pcmpeqb %xmm15, %xmm15
    pushfq
    pop %r11
    mov %r11, 32(%r9)
    .rept 32
    nop
    .endr
.globl clone_probe_site
clone_probe_site:
    syscall
.Lclone_continuation:
    /* cmpなどでフラグを変える前にRFLAGSを取り出し、実際のフラグとr11のコピーを
     * 両方検査する。raxも退避し、親子の戻り値を検査処理で壊さない。 */
    pushfq
    push %rax
    mov 8(%rsp), %rax
    cmp 32(%r9), %rax
    pop %rax
    lea 8(%rsp), %rsp
    jne .Lclone_bad
    cmp 32(%r9), %r11
    jne .Lclone_bad
    cmp $7, %rbx
    jne .Lclone_bad
    cmp $8, %rbp
    jne .Lclone_bad
    cmp $9, %r12
    jne .Lclone_bad
    cmp $10, %r13
    jne .Lclone_bad
    cmp $11, %r14
    jne .Lclone_bad
    cmp $12, %r15
    jne .Lclone_bad
    cmp 8(%r9), %rdi
    jne .Lclone_bad
    cmp 16(%r9), %rsi
    jne .Lclone_bad
    test %rdx, %rdx
    jnz .Lclone_bad
    cmp 24(%r9), %r10
    jne .Lclone_bad
    test %r8, %r8
    jnz .Lclone_bad
    lea .Lclone_continuation(%rip), %r11
    cmp %r11, %rcx
    jne .Lclone_bad
    pmovmskb %xmm0, %r11d
    cmp $65535, %r11d
    jne .Lclone_bad
    pmovmskb %xmm15, %r11d
    cmp $65535, %r11d
    jne .Lclone_bad
    test %rax, %rax
    jnz .Lclone_parent
    cmp (%r9), %rsp
    jne .Lclone_bad
    mov %r9, %rdi
    /* 子のスタックにCの呼び出しフレームはまだないため、ABIの整列条件を満たしてから呼ぶ。 */
    and $-16, %rsp
    call clone_probe_child
    ud2
.Lclone_bad:
    test %rax, %rax
    jnz .Lclone_bad_parent
    mov $117, %edi
    mov $60, %eax
    syscall
    ud2
.Lclone_bad_parent:
    mov $-4096, %rax
.Lclone_parent:
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbp
    pop %rbx
    ret
.size probe_clone, .-probe_clone

/* 小さい親stackでもC用の4 KiB領域を押し込まないことを、下側のguardで検査する。
 * 子はCへ入らず終了し、親だけ元のC stackへ戻る。 */
.globl probe_clone_small_stack
.type probe_clone_small_stack,@function
probe_clone_small_stack:
    push %rbx
    mov %rsp, %rbx
    mov %rdi, %rsp
    mov $0x4111, %edi          /* CLONE_VM | CLONE_VFORK | SIGCHLD */
    xor %esi, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    xor %r9d, %r9d
    mov $56, %eax
    .rept 32
    nop
    .endr
    syscall
    test %rax, %rax
    jz .Lsmall_stack_child
    mov %rbx, %rsp
    pop %rbx
    ret
.Lsmall_stack_child:
    mov $60, %eax
    xor %edi, %edi
    syscall
    ud2
.size probe_clone_small_stack, .-probe_clone_small_stack
.section .note.GNU-stack,"",@progbits
