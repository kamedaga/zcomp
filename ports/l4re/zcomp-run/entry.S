#include "entry_context.h"
.text
/* 基点がGDTに収まるときは両方向をselectorで切り替える。
 * API経路へ戻る際は実際のselectorも0にする。MSRだけ更新すると、次の
 * context switchで古いGDT基点が復元されてしまうため。 */
.macro load_tls context, base, selector
    cmpw $0, ZCOMP_CTX_GUEST_FS_SELECTOR(\context)
    je .Ltls_kernel\@
    movw \selector(\context), %ax
    mov %ax, %fs
    jmp .Ltls_ready\@
.Ltls_kernel\@:
    xor %eax, %eax
    mov %ax, %fs
    mov \base(\context), %rdi
    call zcomp_set_fs
    test %rax, %rax
    js .Ltls_error
.Ltls_ready\@:
.endm

.globl zcomp_check_trampoline
.type zcomp_check_trampoline,@function
zcomp_check_trampoline:
    /* CのNULL参照は未定義動作なので、0番地の確認はアセンブリで行う。 */
    xor %eax, %eax
    cmpb $0x90, 0
    jne .Lchecked
    cmpw $0x25ff, 512
    jne .Lchecked
    cmp %rdi, 518
    jne .Lchecked
    mov $1, %eax
.Lchecked:
    ret
.size zcomp_check_trampoline, .-zcomp_check_trampoline

.globl zcomp_enter
.type zcomp_enter,@function
zcomp_enter:
    push %rbx
    push %rbp
    push %r12
    push %r13
    push %r14
    push %r15
    mov %rsp, ZCOMP_CTX_NATIVE_RSP(%rdi)
    fxsave64 ZCOMP_CTX_NATIVE_FX(%rdi)
    /* L4Re側のTCBはFS:0に自身の基点を持つ。ゲストとTCBを共有しない。 */
    mov %fs:0, %rax
    mov %rax, ZCOMP_CTX_NATIVE_FS(%rdi)
    mov %rsi, %r12
    mov %rdx, %r13
    mov %rdi, %rbx
    movq $0, ZCOMP_CTX_GUEST_FS(%rdi)
    /* C関数の呼出し境界を16バイトに揃え、ゲスト初期化前はFS=0とする。 */
    sub $8, %rsp
    load_tls %rbx, ZCOMP_CTX_GUEST_FS, ZCOMP_CTX_GUEST_FS_SELECTOR
    add $8, %rsp
    mov %r12, %rax
    mov %r13, %rsp
    /* LinuxのエントリポイントはC関数ではないため、戻り番地を積まずに移る。 */
    xor %edx, %edx
    jmp *%rax
.size zcomp_enter, .-zcomp_enter

.globl zcomp_resume
.type zcomp_resume,@function
zcomp_resume:
    /* 保存元は子のCRT。親のnativeスタックやTLSへ戻る経路は作らない。 */
    push %rbx
    push %rbp
    push %r12
    push %r13
    push %r14
    push %r15
    mov %rsp, ZCOMP_CTX_NATIVE_RSP(%rdi)
    fxsave64 ZCOMP_CTX_NATIVE_FX(%rdi)
    mov %fs:0, %rax
    mov %rax, ZCOMP_CTX_NATIVE_FS(%rdi)
    mov %rdi, %r13
    mov ZCOMP_CTX_GUEST_RSP(%r13), %rax
    mov %rax, %gs:ZCOMP_ANCHOR_RSP
    sub $8, %rsp
    load_tls %r13, ZCOMP_CTX_GUEST_FS, ZCOMP_CTX_GUEST_FS_SELECTOR
    add $8, %rsp
    lea ZCOMP_CTX_STACK_END-640(%r13), %rsp
    fxrstor64 (%rsp)
    add $512, %rsp
    jmp .Lrestore_registers
.size zcomp_resume, .-zcomp_resume

.globl zcomp_entry
.type zcomp_entry,@function
zcomp_entry:
    /* callが既にred zoneの上端8バイトを壊している。この制約はスタック切替では解消しない。 */
    /* GSの入口領域はnative Threadごとに独立している。ゲストのFSや共有変数に依存しない。
     * scratchもゲストスタックへpushせず、既知のred zone制約を広げない。 */
    mov %rax, %gs:ZCOMP_ANCHOR_RAX
    mov %rsp, %gs:ZCOMP_ANCHOR_RSP
    mov %gs:ZCOMP_ANCHOR_CONTEXT, %rsp
    mov %gs:ZCOMP_ANCHOR_RAX, %rax
    mov %rax, ZCOMP_CTX_SAVED_RAX(%rsp)
    mov %gs:ZCOMP_ANCHOR_RSP, %rax
    mov %rax, ZCOMP_CTX_GUEST_RSP(%rsp)
    mov %rsp, %rax
    lea ZCOMP_CTX_STACK_END(%rsp), %rsp
    pushfq
    /* PIDだけならguest FSのまま返せる。判定で変わるフラグも専用スタックで退避する。
     * 通知・終了待ちでPIDが0なら、配送と後始末のある通常経路を必ず通す。 */
    cmpq $39, ZCOMP_CTX_SAVED_RAX(%rax)
    jne .Ldispatch
    mov %gs:ZCOMP_ANCHOR_PID, %rax
    test %rax, %rax
    jz .Ldispatch
    /* 統計はThread専用領域へ貯め、通常経路で集計する。共有counterのlockを持ち込まない。 */
    incq %gs:ZCOMP_ANCHOR_CACHED_CALLS
    mov (%rsp), %r11
    popfq
    mov %gs:ZCOMP_ANCHOR_RSP, %rsp
    mov (%rsp), %rcx
    ret
.Ldispatch:
    mov %gs:ZCOMP_ANCHOR_CONTEXT, %rax
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
    push ZCOMP_CTX_SAVED_RAX(%rax)
    mov %rsp, %r12
    mov %rax, %r13
    /* libcやIPCの補助処理がSSEを使っても、対象のx87/XMM状態を壊さないため。 */
    sub $512, %rsp
    fxsave64 (%rsp)
    cld
    /* レジスタとフラグの保存後、TLSに依存するC++へ入る前に基点を戻す。 */
    load_tls %r13, ZCOMP_CTX_NATIVE_FS, ZCOMP_CTX_NATIVE_FS_SELECTOR
    mov %r12, %rdi
    mov ZCOMP_CTX_THREAD(%r13), %rsi
    call zcomp_l4_dispatch
    mov %rax, (%r12)
    /* ARCH_SET_FSが更新した新しい基点も、ゲストへの復帰時にだけ適用する。 */
    load_tls %r13, ZCOMP_CTX_GUEST_FS, ZCOMP_CTX_GUEST_FS_SELECTOR
    fxrstor64 (%rsp)
    mov ZCOMP_CTX_GUEST_RSP(%r13), %rax
    mov %rax, %gs:ZCOMP_ANCHOR_RSP
    mov (%rax), %rax
    mov %rax, 104(%r12)
    mov 120(%r12), %rax
    mov %rax, 112(%r12)
    mov %r12, %rsp
.Lrestore_registers:
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
    /* 全GPRの復元後も、スレッド専用のGS領域ならscratchレジスタなしでRSPを戻せる。 */
    mov %gs:ZCOMP_ANCHOR_RSP, %rsp
    ret
.size zcomp_entry, .-zcomp_entry

.globl zcomp_finish
.type zcomp_finish,@function
zcomp_finish:
    mov %rdi, %rax
    mov %gs:ZCOMP_ANCHOR_CONTEXT, %rdx
    fxrstor64 ZCOMP_CTX_NATIVE_FX(%rdx)
    mov ZCOMP_CTX_NATIVE_RSP(%rdx), %rsp
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbp
    pop %rbx
    ret
.size zcomp_finish, .-zcomp_finish

.globl zcomp_park
.type zcomp_park,@function
zcomp_park:
    /* ex_regsで戻せるよう、GPR・フラグ・スタック・TLSを一切変更せず待つ。 */
    jmp zcomp_park
.size zcomp_park, .-zcomp_park

.globl zcomp_abort
.type zcomp_abort,@function
zcomp_abort:
    /* ゲスト実行中からだけ移される。破棄するguestスタックやguest TLSでC++を呼ばない。 */
    cld
    mov %gs:ZCOMP_ANCHOR_CONTEXT, %r13
    lea ZCOMP_CTX_STACK_END(%r13), %rsp
    load_tls %r13, ZCOMP_CTX_NATIVE_FS, ZCOMP_CTX_NATIVE_FS_SELECTOR
    fxrstor64 ZCOMP_CTX_NATIVE_FX(%r13)
    mov ZCOMP_CTX_THREAD(%r13), %rdi
    call zcomp_abort_thread
    ud2
.size zcomp_abort, .-zcomp_abort

.Ltls_error:
    /* TLSの状態が不明なまま診断用libcやゲストを動かさず、明示的に停止する。 */
    ud2
    jmp .Ltls_error

.section .note.GNU-stack,"",@progbits
