#include "hook.h"

#include <errno.h>
#include <stdatomic.h>
#include <linux/sched.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/syscall.h>

int zcomp_trace;
/* 複数スレッドから同時に捕捉されるため、カウンタは原子的に更新する。 */
/* 専用領域の確保が失敗した場合も数えるため、入口アセンブリと共有する。公開APIにはしない。 */
_Atomic uint64_t zcomp_counts[ZCOMP_SYSCALL_LIMIT + 1];
/* 計画上の適用数ではなく、jmp型を実行した証拠を通常の捕捉と分ける。 */
_Atomic uint64_t zcomp_detour_counts[ZCOMP_SYSCALL_LIMIT + 1];
/* ロックフリーでないとlibatomicの呼び出しになり、捕捉経路でlibcに入ってしまう。 */
_Static_assert(ATOMIC_LLONG_LOCK_FREE == 2, "捕捉経路からランタイムを呼ばないよう、カウンタはロックフリーである必要がある");

ZCOMP_EXPORT uint64_t zcomp_hook_count(unsigned nr)
{
    /* 診断値なので順序保証は不要。。 */
    return nr <= ZCOMP_SYSCALL_LIMIT
        ? atomic_load_explicit(&zcomp_counts[nr], memory_order_relaxed) : 0;
}

ZCOMP_EXPORT uint64_t zcomp_detour_count(unsigned nr)
{
    return nr <= ZCOMP_SYSCALL_LIMIT
        ? atomic_load_explicit(&zcomp_detour_counts[nr], memory_order_relaxed) : 0;
}

void zcomp_note_sigreturn(void)
{
    atomic_fetch_add_explicit(&zcomp_counts[SYS_rt_sigreturn], 1, memory_order_relaxed);
}

/* snprintfはlibc内部で状態やロックを使い得るため、自前で10進変換する。 */
static char *decimal(char *out, long value)
{
    char digits[20];
    unsigned n = 0;
    unsigned long v = (unsigned long)value;
    if (value < 0) {
        *out++ = '-';
        /* -valueはLONG_MINで桁あふれするため、符号なしで反転する。 */
        v = 0UL - v;
    }
    do {
        digits[n++] = (char)('0' + v % 10);
        v /= 10;
    } while (v);
    while (n)
        *out++ = digits[--n];
    return out;
}

static void trace(long nr, long result)
{
    char line[80];
    char *out = line;
    const char prefix[] = "[zcomp] nr=";
    for (size_t i = 0; i < sizeof(prefix) - 1; ++i)
        *out++ = prefix[i];
    out = decimal(out, nr);
    *out++ = ' '; *out++ = '-'; *out++ = '>'; *out++ = ' ';
    out = decimal(out, result);
    *out++ = '\n';
    /* このsyscall命令は除外したDSO内にあるので、再び捕捉されない。
     * この経路ではlibc・TLS・ヒープ・errno変換を使わない。 */
    zcomp_raw_syscall(SYS_write, 2, (long)line, out - line, 0, 0, 0);
}

/* 不正なポインタを直接参照するとフック自体が落ちるため、自プロセス宛の
 * process_vm_*でコピーし、読み書きできない領域は-EFAULTとして返す。
 * libc・TLS・シグナルハンドラを使わずに済むが、ホスト側でこのsyscallが
 * 許可されている必要がある。禁止されている場合は、そのエラーを返す。 */
long zcomp_copy_user(void *local, uint64_t remote, size_t size, int writing)
{
    struct iovec local_vec = {local, size};
    struct iovec remote_vec = {(void *)(uintptr_t)remote, size};
    long pid = zcomp_raw_syscall(SYS_getpid, 0, 0, 0, 0, 0, 0);
    long result = zcomp_raw_syscall(writing ? SYS_process_vm_writev
                                          : SYS_process_vm_readv,
        pid, (long)&local_vec, 1, (long)&remote_vec, 1, 0);
    return result < 0 ? result : (result == (long)size ? 0 : -EFAULT);
}

long zcomp_prepare_clone(const struct zcomp_regs *r, struct zcomp_clone_call *call)
{
    call->arg1 = r->rdi;
    call->arg2 = r->rsi;
    call->child_frame = 0;
    call->flags = 0;
    uint64_t flags = r->rdi, top = r->rsi;
    if (r->rax == SYS_vfork) {
        flags = CLONE_VM | CLONE_VFORK;
        top = 0;
    } else if (r->rax == SYS_clone3) {
        /* 最小サイズ未満ではカーネルが子を作らず拒否するため、引数を読まずに
         * その判定へ渡す。私有コピーに収まらないサイズは-E2BIGで拒否する。 */
        if (r->rsi < CLONE_ARGS_SIZE_VER0)
            return 0;
        if (r->rsi > sizeof(call->args))
            return -E2BIG;
        long error = zcomp_copy_user(call->args.bytes, r->rdi, r->rsi, 0);
        if (error)
            return error;
        struct clone_args *args = &call->args.clone;
        flags = args->flags;
        if (args->stack) {
            if (args->stack_size < 264 ||
                args->stack > UINT64_MAX - args->stack_size)
                return -EINVAL;
            top = args->stack + args->stack_size;
            args->stack_size -= 264;
        } else {
            top = 0;
        }
        call->arg1 = (uintptr_t)args;
    }
    call->flags = flags;
    if (!top) {
        if (!(flags & CLONE_VM))
            return 0;
        /* 親が並行して走る共有スタックには安全な復帰を保証できない。
         * VFORKなら子のexit/execまで親が待機するため、親だけの退避先を確保できる。 */
        if (!(flags & CLONE_VFORK))
            return -ENOSYS;
        /* 親の復元情報は入口が専用領域へ保存済み。子はそこを解放せずゲストへ戻る。 */
        return 0;
    }
    if (top < 264)
        return -EFAULT;

    /* 親が先に復帰してスタックを再利用しても子が戻れるよう、保存内容を子側へコピーする。
     * 共通の復帰処理を使うため、zcomp_entryと同じ配置にする
     * (レジスタ128バイト + 退避領域128バイト + 継続先8バイト)。
     * 子作成後の子側では、親のフレームを参照する復元やトレースを行わない。 */
    uint64_t frame[33];
    const uint64_t *saved = (const uint64_t *)r;
    for (unsigned i = 0; i < 16; ++i)
        frame[i] = saved[i];
    for (unsigned i = 16; i < 32; ++i)
        frame[i] = 0;
    frame[32] = ((const struct zcomp_clone_frame *)r)->continuation;
    long error = zcomp_copy_user(frame, top - sizeof(frame), sizeof(frame), 1);
    if (error)
        return error;
    call->child_frame = top - sizeof(frame);
    if (r->rax == SYS_clone)
        call->arg2 = call->child_frame;
    return 0;
}

void zcomp_note_clone_result(long nr, long result)
{
    if (zcomp_trace)
        trace(nr, result);
}

long zcomp_dispatch(const struct zcomp_regs *r)
{
    const long nr = (long)r->rax;
    /* 符号なし比較で、負の番号も範囲外として一度に弾く。 */
    if ((unsigned long)nr <= ZCOMP_SYSCALL_LIMIT)
        atomic_fetch_add_explicit(&zcomp_counts[nr], 1, memory_order_relaxed);

    long result;
    switch (nr) {
    /* 子側の復帰で親のCフレームを使えないため、子生成は入口の専用経路へ送る。
     * 誤ってここへ来ても、通常のC転送関数からは発行しない。 */
    case SYS_clone:
    case SYS_clone3:
    case SYS_vfork:
        result = -ENOSYS;
        break;
    case SYS_execve:
    case SYS_execveat:
        result = zcomp_exec(r);
        break;
    case SYS_fork:
        result = zcomp_raw_syscall(nr, r->rdi, r->rsi, r->rdx,
                                   r->r10, r->r8, r->r9);
        /* SUDはforkの子へ継承されない。子のゲストコードを再開する前に設定する。 */
        if (!result)
            zcomp_guard_start();
        break;
    default:
        /* 戻り値は生の -errno のまま返す。 */
        result = zcomp_raw_syscall(nr, r->rdi, r->rsi, r->rdx,
                                   r->r10, r->r8, r->r9);
        break;
    }
    if (zcomp_trace)
        trace(nr, result);
    return result;
}
