#ifndef ZCOMP_HOOK_H
#define ZCOMP_HOOK_H

#include <stddef.h>
#include <stdint.h>
#include <linux/sched.h>
#include "clone_frame.h"

#define ZCOMP_EXPORT __attribute__((visibility("default")))
/* NOP列512バイト + 直後のjmpで、0〜512番だけが入口に着地する。 */
enum { ZCOMP_SYSCALL_LIMIT = 512 };
/* 未捕捉syscallの診断終了を、アプリ自身の通常の失敗と区別する。 */
enum { ZCOMP_GUARD_STATUS = 159 };

/* trampoline.S のpush順と一致させる。結果を書き戻すのはraxだけ。
 * rcx/r11は本物のsyscallと同じ値 (復帰先RIP/RFLAGS) を再現するために持つ。 */
struct zcomp_regs {
    uint64_t rax, rdi, rsi, rdx, r10, r8, r9;
    uint64_t rbx, rbp, r12, r13, r14, r15, rcx, r11, flags;
};
/* アセンブリ側はオフセットを即値で参照するため、ずれをコンパイル時に検出する。 */
_Static_assert(sizeof(struct zcomp_regs) == 128, "レジスタ保存領域のサイズがアセンブリと一致する必要がある");
_Static_assert(offsetof(struct zcomp_regs, flags) == 120, "フラグの保存位置がアセンブリと一致する必要がある");

long zcomp_raw_syscall(long nr, long a1, long a2, long a3,
                       long a4, long a5, long a6);
long zcomp_dispatch(const struct zcomp_regs *regs);
void zcomp_entry(void);
void zcomp_detour_entry(void);
void zcomp_fill_trampoline(uintptr_t address, uintptr_t entry);
void zcomp_guard_prepare(void);
void zcomp_guard_start(void);
long zcomp_guard_enable(void);
void zcomp_note_sigreturn(void);
/* 引数の私有コピーは専用写像に置く。ゲストstackに4 KiBの余裕があるとは限らない。 */
struct zcomp_clone_call {
    uint64_t arg1, arg2, child_frame, flags;
    union {
        struct clone_args clone;
        unsigned char bytes[4096];
    } args;
};
_Static_assert(sizeof(struct zcomp_clone_call) == 4128, "子作成の作業領域がアセンブリの予約サイズと一致する必要がある");
_Static_assert(offsetof(struct zcomp_clone_call, child_frame) == 16,
               "子の保存領域を指す欄の位置がアセンブリと一致する必要がある");
/* vforkの子はゲストstackを再利用するため、親の完全な復元情報も専用写像に残す。
 * 同じTask内の子との隔離境界ではなく、フレームの寿命を管理するためのもの。 */
struct zcomp_clone_frame {
    struct zcomp_regs regs;
    uint64_t continuation;
    struct zcomp_regs *original;
    struct zcomp_clone_call call;
};
_Static_assert(offsetof(struct zcomp_clone_frame, continuation) == ZCOMP_CLONE_CONTINUATION &&
               offsetof(struct zcomp_clone_frame, original) == ZCOMP_CLONE_ORIGINAL &&
               offsetof(struct zcomp_clone_frame, call) == ZCOMP_CLONE_CALL &&
               offsetof(struct zcomp_clone_frame, call.arg1) == ZCOMP_CLONE_ARG1 &&
               offsetof(struct zcomp_clone_frame, call.arg2) == ZCOMP_CLONE_ARG2 &&
               offsetof(struct zcomp_clone_frame, call.child_frame) == ZCOMP_CLONE_CHILD &&
               offsetof(struct zcomp_clone_frame, call.flags) == ZCOMP_CLONE_FLAGS,
               "clone専用領域の配置がアセンブリと一致する必要がある");
_Static_assert(sizeof(struct zcomp_clone_frame) <= ZCOMP_CLONE_DATA_PAGES * 4096,
               "amd64の最小ページサイズでも復元情報がguardの手前に収まる必要がある");
long zcomp_prepare_clone(const struct zcomp_regs *regs,
                         struct zcomp_clone_call *call);
void zcomp_note_clone_result(long nr, long result);
extern int zcomp_trace;
/* exec先の作業ディレクトリに依存しないよう、書き換え前に絶対パスを確定する。 */
extern char zcomp_preload_path[4096];
extern size_t zcomp_page_size;
long zcomp_copy_user(void *local, uint64_t remote, size_t size, int writing);
long zcomp_exec(const struct zcomp_regs *regs);

/* 診断用。プロセス内の累計捕捉回数であり、syscallの網羅率を示すAPIではない
 * (書き換えなかった命令は数えられない)。rt_sigreturnはCを経由して戻れない
 * ため、専用のカウンタで数える。 */
ZCOMP_EXPORT uint64_t zcomp_hook_count(unsigned nr);
ZCOMP_EXPORT uint64_t zcomp_detour_count(unsigned nr);

#endif
