.text
/* FiascoのIPCはr15も壊す。guest libcのcallee-saved契約まで壊さずに迂回だけを調べる。 */
.global native_call
.type native_call, @function
native_call:
    push %r15
    mov %rdi, %rdx
    /* CALL=SEND|RECV。Linux番号ではなく、L4の宛先・tag・timeout配置を使う。 */
    or $3, %rdx
    mov %rsi, %rax
    xor %esi, %esi
    xor %r8d, %r8d
    call .Lnative_instruction
    pop %r15
    ret
.size native_call, .-native_call

/* DSOのdata symbolを公開するとCOPY relocation先を検査しかねない。実際の命令番地を返す。 */
.global native_instruction_address
.type native_instruction_address, @function
native_instruction_address:
    lea .Lnative_instruction(%rip), %rax
    ret
.size native_instruction_address, .-native_instruction_address

/* 全16ストリームがmovの即値と判定する位置へ、実行時だけ分岐する。
 * 走査器に例外を足さず、coveredとして残ったsyscallをnative IPCに使う。 */
    .rept 256
    nop
    .endr
.Lnative_container:
    mov $0x00c3050f, %eax
    ret
.set .Lnative_instruction, .Lnative_container + 1
.section .note.GNU-stack,"",@progbits
