#include "clone_frame.h"
.text
.Lnative_begin:
/* hidden: 外部のDSOから呼ばれず、PLTも経由しないようにする。 */
.hidden zcomp_fill_trampoline
.globl zcomp_fill_trampoline
.type zcomp_fill_trampoline,@function
zcomp_fill_trampoline:
    /* 0〜511番はどこに着地してもNOPで末尾まで滑る。 */
    mov $512, %ecx
    mov $0x90, %al
    cld
    rep stosb
    /* rep stosb後のrdiはNOP列の直後 (512番の着地点) を指す。
     * jmp *0(%rip); .quad entry を使う。レジスタもスタックも汚さず、
     * 64ビットの任意番地へ飛べるため。 */
    movw $0x25ff, (%rdi)
    movl $0, 2(%rdi)
    mov %rsi, 6(%rdi)
    ret
.size zcomp_fill_trampoline, .-zcomp_fill_trampoline

/* 関数呼び出しABIの引数をsyscall ABIへ並べ替える。第4引数はrcxではなく
 * r10 (rcxはsyscall命令が復帰先で上書きするため)。第6引数はスタック上にある。 */
.hidden zcomp_raw_syscall
.globl zcomp_raw_syscall
.type zcomp_raw_syscall,@function
zcomp_raw_syscall:
    mov %rdi, %rax
    mov %rsi, %rdi
    mov %rdx, %rsi
    mov %rcx, %rdx
    mov %r8, %r10
    mov %r9, %r8
    mov 8(%rsp), %r9
    syscall
    ret
.size zcomp_raw_syscall, .-zcomp_raw_syscall

/* selector=NULLなら、許可したnative範囲の外を常にSIGSYSへ送る。
 * 許可/不許可を共有変数で切り替えないため、別threadやvforkの子との競合がない。 */
.macro setup_guard
    mov $157, %eax             /* SYS_prctl */
    mov $59, %edi              /* PR_SET_SYSCALL_USER_DISPATCH */
    mov $1, %esi               /* PR_SYS_DISPATCH_ON */
    lea .Lnative_begin(%rip), %rdx
    mov $(.Lnative_end - .Lnative_begin), %r10d
    xor %r8d, %r8d             /* selector=NULL */
    syscall
.endm

/* push順の逆。struct zcomp_regs の並びと一致させる。 */
.macro restore_regs
    pop %rax
    pop %rdi
    pop %rsi
    pop %rdx
    pop %r10
    pop %r8
    pop %r9
    pop %rbx
    pop %rbp
    pop %r12
    pop %r13
    pop %r14
    pop %r15
    pop %rcx
    pop %r11
    popfq
.endm

/* detourの入口にはcallの戻り番地が存在しない。先にred zoneと復帰先用の
 * 16バイトを避け、通常のsyscallだけを既存のC dispatcherへ渡す。 */
.hidden zcomp_detour_entry
.globl zcomp_detour_entry
.type zcomp_detour_entry,@function
zcomp_detour_entry:
    lea -144(%rsp), %rsp
    pushfq
    push %r11
    push %rcx
    push %r15
    push %r14
    push %r13
    push %r12
    push %rbp
    push %rbx
    push %r9
    push %r8
    push %r10
    push %rdx
    push %rsi
    push %rdi
    push %rax
    mov %rsp, %r12
    cmp 16(%rcx), %rax
    jne .Ldetour_failed
    cmp $512, %rax
    ja .Ldetour_counted
    lea zcomp_detour_counts(%rip), %rdx
    lock incq (%rdx,%rax,8)
.Ldetour_counted:
    mov 8(%rcx), %rax
    mov %rax, 128(%r12)        /* descriptorのepilogue。元のred zone外に置く */
    mov (%rcx), %rax
    mov %rax, 104(%r12)        /* rcxはstubではなく、本来のsyscallの次を示す */
    mov 120(%r12), %rax
    mov %rax, 112(%r12)
    mov %r12, %rdi
    and $-16, %rsp
    cld
    call zcomp_dispatch
    mov %rax, (%r12)
    mov %r12, %rsp
    restore_regs
    /* まだrspを元へ戻さない。復帰先をsignal frameに壊されない位置から読む。 */
    jmp *(%rsp)
.size zcomp_detour_entry, .-zcomp_detour_entry
.hidden zcomp_detour_counts
.Ldetour_failed:
    /* 静的に読んだ番号と違う経路を実行した場合、別のsyscallを誤転送しない。 */
    mov $1, %eax
    mov $2, %edi
    lea .Ldetour_error(%rip), %rsi
    mov $(.Ldetour_error_end - .Ldetour_error), %edx
    syscall
    mov $231, %eax
    mov $159, %edi
    syscall
    ud2
.Ldetour_error:
    .ascii "zcomp: Detour syscall-number assumption failed.\n"
.Ldetour_error_end:

.hidden zcomp_dispatch
.hidden zcomp_note_sigreturn
.hidden zcomp_prepare_clone
.hidden zcomp_note_clone_result
.hidden zcomp_counts
.hidden zcomp_guard_enable
.hidden zcomp_entry
.globl zcomp_entry
.type zcomp_entry,@function
zcomp_entry:
    /* call *%rax の戻り番地が、呼び出し元red zoneの上端8バイトを既に壊している。
     * ここで128バイト空けるのは、残りを自分のフレームから守るだけ。
     * red zoneを引数に使うコードの修正にはならない。 */
    lea -128(%rsp), %rsp
    /* 呼び出し元から見て、syscall前後で変わるのはrax/rcx/r11だけにするため、
     * フラグを含む一般レジスタをすべて保存する。ベクトル/FPUはCのビルド
     * フラグで触らないことを保証し、保存しない。 */
    pushfq
    push %r11
    push %rcx
    push %r15
    push %r14
    push %r13
    push %r12
    push %rbp
    push %rbx
    push %r9
    push %r8
    push %r10
    push %rdx
    push %rsi
    push %rdi
    push %rax

    mov %rsp, %r12              /* 呼び出し先保存なのでCの呼び出し後も残る。元のr12は保存済み */
    mov %rsp, %rdi
    and $-16, %rsp              /* 呼び出し元のrspは整列していない可能性がある。C ABIの16バイト整列 */
    cld                         /* C ABIはDF=0を前提とする。呼び出し元のフラグは保存済み */
    cmp $15, %rax               /* rt_sigreturnはCを経由して戻れない */
    je .Lsigreturn
    cmp $56, %rax               /* cloneは子の新スタックから戻るため、通常のC転送を避ける */
    je .Lclone
    cmp $435, %rax              /* clone3も子のスタック切り替えに対応する専用経路へ送る */
    je .Lclone
    cmp $58, %rax               /* vforkの親は子が再利用したスタックから直接は復帰できない */
    je .Lclone
    call zcomp_dispatch
.Lfinish:
    mov %rax, (%r12)

    /* 本物のsyscallがrcx/r11に残す値 (復帰先RIP/RFLAGS) を再現する。 */
    mov 256(%r12), %rax         /* 戻り番地 = 書き換えたsyscallの次の命令 (保存領域128 + 退避128) */
    mov %rax, 104(%r12)
    mov 120(%r12), %rax
    mov %rax, 112(%r12)
    mov %r12, %rsp
    restore_regs
    lea 128(%rsp), %rsp
    ret

.Lclone:
    /* Cに入る前に別stackを確保する。ここまでは既存の264バイトの退避だけを使い、
     * 小さいgoroutine stackの下へ4 KiBの作業領域を押し出さない。TLSも変更しない。 */
    lea zcomp_counts(%rip), %rdx
    lock incq (%rdx,%rax,8)
    mov zcomp_page_size(%rip), %r15
    imul $ZCOMP_CLONE_MAP_PAGES, %r15
    xor %edi, %edi
    mov %r15, %rsi
    mov $3, %edx               /* PROT_READ | PROT_WRITE */
    mov $0x22, %r10d           /* MAP_PRIVATE | MAP_ANONYMOUS */
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    cmp $-4095, %rax
    jae .Lclone_alloc_error
    mov %rax, %r13             /* C呼出しとsyscallを越えて専用写像の所有者を保持する */
    mov zcomp_page_size(%rip), %rsi
    lea (%r13,%rsi,ZCOMP_CLONE_DATA_PAGES), %rdi
    xor %edx, %edx             /* metadataとC用stackの間をPROT_NONEにする */
    mov $10, %eax
    syscall
    test %rax, %rax
    js .Lclone_guard_error

    mov %r12, %rsi
    mov %r13, %rdi
    mov $16, %ecx
    rep movsq
    mov 256(%r12), %rax
    mov %rax, ZCOMP_CLONE_CONTINUATION(%r13)
    mov %r12, ZCOMP_CLONE_ORIGINAL(%r13)
    lea (%r13,%r15), %rsp
    mov %r13, %rdi
    lea ZCOMP_CLONE_CALL(%r13), %rsi
    call zcomp_prepare_clone
    test %rax, %rax
    js .Lclone_result
    mov ZCOMP_CLONE_CHILD(%r13), %rbx
    mov ZCOMP_CLONE_FLAGS(%r13), %rbp
    mov ZCOMP_CLONE_ARG1(%r13), %rdi
    mov ZCOMP_CLONE_ARG2(%r13), %rsi
    mov (%r13), %rax
    mov 24(%r13), %rdx
    mov 32(%r13), %r10
    mov 40(%r13), %r8
    mov 48(%r13), %r9
    syscall
    test %rax, %rax
    jnz .Lclone_result

    /* clone/vforkもSUDを継承しない。小さい新stack上でCを呼ばずに再設定し、
     * 共有写像の解放とゲスト再開より先に、未捕捉の発行を止める。 */
    setup_guard
    test %rax, %rax
    js .Lguard_failed
    xor %eax, %eax

    /* CLONE_VMの親は先に写像を解放できるため、新stackの子はmetadataを読まない。
     * 共有の有無と子フレームの位置は、カーネルが保存したレジスタだけで判断する。 */
    test %rbx, %rbx
    jz .Lclone_child_same_stack
    mov %rsp, %r12
    test $0x100, %ebp          /* CLONE_VM */
    jnz .Lfinish
    /* 非共有の子には専用写像もコピーされるので、子自身のコピーを回収する。 */
    movq $0, (%r12)
    jmp .Lclone_unmap
.Lclone_child_same_stack:
    test $0x100, %ebp
    jz .Lclone_restore
    /* stack共有はVFORKの場合だけ許可済み。親の保存情報は残したままゲストへ戻る。 */
    mov ZCOMP_CLONE_ORIGINAL(%r13), %r12
    jmp .Lfinish
.Lclone_result:
    mov %rax, %rsi
    mov (%r13), %rdi
    mov %rax, (%r13)
    call zcomp_note_clone_result
    mov (%r13), %rax
.Lclone_restore:
    /* vforkの子が再利用したゲストframeも、私有コピーから完全に復元する。
     * 非共有の子の戻り値0も、このコピーへ反映してから自身の写像を回収する。 */
    mov %rax, (%r13)
    mov ZCOMP_CLONE_ORIGINAL(%r13), %r12
    mov %r13, %rsi
    mov %r12, %rdi
    mov $16, %ecx
    rep movsq
    mov ZCOMP_CLONE_CONTINUATION(%r13), %rax
    mov %rax, 256(%r12)
.Lclone_unmap:
    /* 解放するstack上では実行しない。ゲスト側へ戻った後はC呼出しも行わない。 */
    mov %r12, %rsp
    mov %r13, %rdi
    mov %r15, %rsi
    mov $11, %eax
    syscall
    mov (%r12), %rax
    jmp .Lfinish
.Lclone_guard_error:
    mov %rax, %rbx
    mov %r13, %rdi
    mov %r15, %rsi
    mov $11, %eax
    syscall
    mov %rbx, %rax
.Lclone_alloc_error:
    /* 専用stackを得られない時はCのログも呼ばず、生のerrnoで安全に復帰する。
     * 捕捉カウンタは確保前に更新してあるため、失敗しても捕捉自体は観測できる。 */
    jmp .Lfinish

/* rt_sigreturnはカーネルが現在のrspからシグナルフレームを読むため、
 * rspを元に戻してから、除外したこの場所のsyscallで発行する。
 * 成功時は戻らないので、Cのディスパッチャを経由できない。 */
.Lsigreturn:
    call zcomp_note_sigreturn
    mov %r12, %rsp
    restore_regs
    lea 136(%rsp), %rsp         /* 退避128 + 戻り番地8 = シグナルフレームを指す元のrsp */
    syscall
    ud2                         /* 失敗時にフレームの壊れた状態で走り続けないよう即停止 */
.size zcomp_entry, .-zcomp_entry

.globl zcomp_guard_enable
.type zcomp_guard_enable,@function
zcomp_guard_enable:
    /* 初期化側は対応kernelかを判定するため、生のerrnoを受け取る。 */
    setup_guard
    ret
.size zcomp_guard_enable, .-zcomp_guard_enable
.Lguard_failed:
    /* 子の初期化に失敗しても、未検査のまま再開しない。TLSやC stackは不要。 */
    mov $1, %eax
    mov $2, %edi
    lea .Lguard_error(%rip), %rsi
    mov $(.Lguard_error_end - .Lguard_error), %edx
    syscall
    mov $231, %eax
    mov $159, %edi
    syscall
    ud2
.Lguard_error:
    .ascii "zcomp: Cannot restore the unhooked-syscall guard in the child.\n"
.Lguard_error_end:
.Lnative_end:
/* 実行可能スタックを要求しないことをリンカに示す。 */
.section .note.GNU-stack,"",@progbits
