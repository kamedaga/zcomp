#define _GNU_SOURCE
#include "hook.h"

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

struct child_context {
    uint64_t top, arg1, arg2, child_tid, flags;
    _Atomic int ran;
    _Atomic int tid;
    unsigned mode;
    long exec_error;
};
extern long probe_clone(long, long, long, long, struct child_context *);
extern long probe_clone_small_stack(void *);
extern unsigned char clone_probe_site[];
extern long probe_syscall6(long, long, long, long, long, long, long);
static uint64_t (*count)(unsigned);
static int hooked;
static _Atomic int worker_calls;
static _Thread_local unsigned tls_value = 17;
static volatile sig_atomic_t parent_signal;
static long (*unhooked_call)(void);

static void disable_clone3(void)
{
    /* ホストに依存せずpthreadのcloneへのフォールバックを検査できるよう、
     * このテストプロセスだけでclone3をENOSYSにする。 */
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone3, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {
        .len = sizeof(filter) / sizeof(filter[0]), .filter = filter};
    assert(probe_syscall6(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0) == 0);
    assert(probe_syscall6(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                          0, (long)&program, 0, 0, 0) == 0);
}

void clone_probe_child(struct child_context *ctx)
{
    if (ctx->mode == 7) {
        /* 親だけSUD有効という実装を通さず、子の最初の未書換え発行を検査する。 */
        assert(unhooked_call() > 0);
        _exit(0);
    }
    if (ctx->mode) {
        /* 子のC呼出しと大きなローカル領域で、親のフック用スタックを実際に
         * 上書きする。たまたま保存領域が残るだけの実装を通さないため。 */
        volatile unsigned char scratch[16384];
        for (unsigned i = 0; i < sizeof(scratch); ++i)
            scratch[i] = (unsigned char)i;
        assert(scratch[4096] == 0 && scratch[16383] == 255);
    }
    long tid = probe_syscall6(SYS_gettid, 0, 0, 0, 0, 0, 0);
    assert(tid > 0);
    atomic_store(&ctx->ran, 1);
    if (ctx->mode == 2 || ctx->mode == 3) {
        char *args[] = {"clone_test", "--vfork-image", hooked ? "--hooked" : "--native", NULL};
        char *env[] = {NULL};
        const char *path = ctx->mode == 2 ? "/proc/self/zcomp-missing" : "/proc/self/exe";
        ctx->exec_error = probe_syscall6(SYS_execve, (long)path, (long)args,
                                        (long)env, 0, 0, 0);
        assert(ctx->mode == 2 && ctx->exec_error == -ENOENT);
    }
    if (ctx->mode == 4) {
        struct child_context nested = {.mode = 1};
        long pid = probe_clone(SYS_vfork, 0, 0, 0, &nested);
        assert(pid > 0 && atomic_load(&nested.ran));
        int status;
        assert(probe_syscall6(SYS_wait4, pid, (long)&status, 0, 0, 0, 0) == pid);
        assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    if (ctx->mode == 5) {
        long parent = probe_syscall6(SYS_getppid, 0, 0, 0, 0, 0, 0);
        assert(probe_syscall6(SYS_kill, parent, SIGUSR1, 0, 0, 0, 0) == 0);
    }
    if (ctx->mode == 6) {
        /* exit syscallだけでなく、カーネルによる異常終了でも親が再開できる必要がある。 */
        probe_syscall6(SYS_kill, tid, SIGKILL, 0, 0, 0, 0);
        assert(!"Child must terminate on SIGKILL");
    }
    /* スタックを切り替えた子から通常のフック経路へ進めることを確認して終了する。
     * CLONE_CHILD_CLEARTIDによる終了通知は、後段のpthread_joinで検査する。 */
    probe_syscall6(SYS_exit, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}

static void *worker(void *arg)
{
    unsigned value = (unsigned)(uintptr_t)arg;
    assert(tls_value == 17);
    tls_value = value;
    for (unsigned i = 0; i < 100; ++i) {
        assert(probe_syscall6(SYS_gettid, 0, 0, 0, 0, 0, 0) > 0);
        atomic_fetch_add(&worker_calls, 1);
    }
    /* 別スレッドが同時にvforkしても退避先を共有せず、親TLSも変更しないことを検査する。 */
    struct child_context ctx = {.mode = 2};
    long pid = probe_clone(SYS_vfork, 0, 0, 0, &ctx);
    assert(pid > 0 && atomic_load(&ctx.ran) && ctx.exec_error == -ENOENT);
    int status;
    assert(waitpid((pid_t)pid, &status, 0) == pid);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(tls_value == value);
    return arg;
}

static void wait_child(long pid)
{
    int status;
    assert(waitpid((pid_t)pid, &status, 0) == pid);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void *unhooked_worker(void *unused)
{
    (void)unused;
    assert(unhooked_call() > 0);
    return NULL;
}

static void guard_cases(void)
{
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    unsigned char *code = mmap(NULL, page, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(code != MAP_FAILED);
    const unsigned char getpid_code[] = {0xb8, 39, 0, 0, 0, 0x0f, 0x05, 0xc3};
    memcpy(code, getpid_code, sizeof getpid_code);
    assert(mprotect(code, page, PROT_READ | PROT_EXEC) == 0);
    unhooked_call = (long (*)(void))code;
    for (unsigned kind = 0; kind < 4; ++kind) {
        struct child_context ctx = {.mode = 7};
        struct clone_args args = {.exit_signal = SIGCHLD};
        long pid;
        if (kind == 0) {
            pid = fork();
            if (!pid) clone_probe_child(&ctx);
        } else if (kind == 1) {
            pid = probe_clone(SYS_vfork, 0, 0, 0, &ctx);
        } else if (kind == 2) {
            ctx.arg1 = SIGCHLD;
            pid = probe_clone(SYS_clone, ctx.arg1, 0, 0, &ctx);
        } else {
            ctx.arg1 = (uintptr_t)&args;
            ctx.arg2 = sizeof args;
            pid = probe_clone(SYS_clone3, ctx.arg1, ctx.arg2, 0, &ctx);
            if (pid == -ENOSYS) continue;
        }
        assert(pid > 0);
        int status;
        assert(waitpid((pid_t)pid, &status, 0) == pid);
        assert(WIFEXITED(status) && WEXITSTATUS(status) == (hooked ? ZCOMP_GUARD_STATUS : 0));
    }
    // CLONE_THREADの停止はthread group全体を終了するため、専用の子で検査する。
    pid_t pid = fork();
    assert(pid >= 0);
    if (!pid) {
        pthread_t thread;
        assert(pthread_create(&thread, NULL, unhooked_worker, NULL) == 0);
        assert(pthread_join(thread, NULL) == 0);
        _exit(0);
    }
    int status;
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == (hooked ? ZCOMP_GUARD_STATUS : 0));
    assert(munmap(code, page) == 0);
    puts(hooked ? "Guard: verified fork, clone, clone3, vfork, and pthread child enforcement"
                : "Native Linux: verified child and pthread direct syscalls");
}

static void on_parent_signal(int signal_number)
{
    parent_signal = signal_number;
}

static void vfork_cases(void)
{
    struct sigaction action = {.sa_handler = on_parent_signal};
    struct sigaction previous;
    assert(sigemptyset(&action.sa_mask) == 0);
    assert(sigaction(SIGUSR1, &action, &previous) == 0);
    for (unsigned variant = 0; variant < 3; ++variant) {
        long nr = variant == 0 ? SYS_vfork : variant == 1 ? SYS_clone : SYS_clone3;
        if (variant == 2 && probe_syscall6(SYS_clone3, 0, 0, 0, 0, 0, 0) == -ENOSYS)
            continue;
        struct clone_args args = {.flags = CLONE_VM | CLONE_VFORK, .exit_signal = SIGCHLD};
        uint64_t arg1 = variant == 2 ? (uintptr_t)&args : variant == 1 ? CLONE_VM | CLONE_VFORK | SIGCHLD : 0;
        uint64_t arg2 = variant == 2 ? sizeof(args) : 0;
        for (unsigned mode = 1; mode <= 6; ++mode) {
            struct child_context ctx = {.arg1 = arg1, .arg2 = arg2, .mode = mode};
            parent_signal = 0;
            uint64_t before = hooked ? count((unsigned)nr) : 0;
            long pid = probe_clone(nr, arg1, arg2, 0, &ctx);
            assert(pid > 0);
            /* 親が子の終了・execより先に戻っていないことも、共有メモリで確認する。 */
            assert(atomic_load(&ctx.ran));
            if (mode == 6) {
                int status;
                assert(waitpid((pid_t)pid, &status, 0) == pid);
                assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
            } else {
                wait_child(pid);
            }
            if (mode == 2)
                assert(ctx.exec_error == -ENOENT);
            if (mode == 5)
                assert(parent_signal == SIGUSR1);
            if (hooked)
                assert(count((unsigned)nr) >= before + 1);
        }
    }
    assert(sigaction(SIGUSR1, &previous, NULL) == 0);
    /* 同時に走る共有スタックは今回も対象外。実際に生成して壊す試験はしない。 */
    if (hooked)
        assert(probe_syscall6(SYS_clone, CLONE_VM | SIGCHLD, 0, 0, 0, 0, 0) == -ENOSYS);
    puts("vfork: verified shared stacks, exit/SIGKILL, exec success/failure, nesting, and parent signal");
}

static unsigned long mapped_pages(void)
{
    char text[128];
    long fd = probe_syscall6(SYS_openat, AT_FDCWD, (long)"/proc/self/statm", O_RDONLY, 0, 0, 0);
    assert(fd >= 0);
    long size = probe_syscall6(SYS_read, fd, (long)text, sizeof(text), 0, 0, 0);
    assert(size > 0);
    assert(probe_syscall6(SYS_close, fd, 0, 0, 0, 0, 0) == 0);
    unsigned long pages = 0;
    for (long i = 0; i < size && text[i] >= '0' && text[i] <= '9'; ++i)
        pages = pages * 10 + (unsigned)(text[i] - '0');
    return pages;
}

static void vfork_kernel_failure(void)
{
    long pid = probe_syscall6(SYS_fork, 0, 0, 0, 0, 0, 0);
    assert(pid >= 0);
    if (!pid) {
        /* 子を作った後では試せない拒否経路を、隔離したテストプロセスで固定する。
         * mmap・munmapは許可し、カーネルが生成を拒否しても正常に戻ることを要求する。 */
        struct sock_filter filter[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_vfork, 1, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EAGAIN),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        };
        struct sock_fprog program = {.len = sizeof(filter) / sizeof(filter[0]), .filter = filter};
        assert(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
        assert(probe_syscall6(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, (long)&program, 0, 0, 0) == 0);
        unsigned long before = mapped_pages();
        for (unsigned i = 0; i < 64; ++i) {
            struct child_context ctx = {0};
            assert(probe_clone(SYS_vfork, 0, 0, 0, &ctx) == -EAGAIN);
            ctx = (struct child_context){.arg1 = CLONE_VM | CLONE_VFORK | SIGCHLD};
            assert(probe_clone(SYS_clone, ctx.arg1, 0, 0, &ctx) == -EAGAIN);
        }
        /* 1回ごとの退避ページを拒否経路で残すと、VMAが結合されても総ページ数は増える。 */
        assert(mapped_pages() == before);
        _exit(0);
    }
    wait_child(pid);
}

static void raw_clone_cases(void)
{
    const size_t size = 65536;
    void *stack = mmap(NULL, size + 8192, PROT_NONE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(stack != MAP_FAILED);
    char *base = (char *)stack + 4096;
    assert(mprotect(base, size, PROT_READ | PROT_WRITE) == 0);
    /* CLONE_VMだけを新スタック対応の条件にすると非共有の場合を取りこぼすため、
     * 共有・非共有の両方を検査する。子TIDの設定と、CLONE_VFORKで親が停止する場合も含める。 */
    const unsigned flags[] = {SIGCHLD,
        CLONE_VM | CLONE_CHILD_SETTID | SIGCHLD,
        CLONE_VM | CLONE_VFORK | SIGCHLD};
    for (unsigned i = 0; i < sizeof(flags) / sizeof(flags[0]); ++i) {
        struct child_context ctx = {.top = (uintptr_t)(base + size),
            .arg1 = flags[i], .arg2 = (uintptr_t)(base + size)};
        ctx.child_tid = (uintptr_t)&ctx.tid;
        uint64_t before = hooked ? count(SYS_clone) : 0;
        long pid = probe_clone(SYS_clone, ctx.arg1, ctx.arg2, ctx.child_tid, &ctx);
        assert(pid > 0);
        wait_child(pid);
        if (flags[i] & CLONE_VM) {
            assert(atomic_load(&ctx.ran) == 1);
            if (flags[i] & CLONE_CHILD_SETTID)
                assert(atomic_load(&ctx.tid) == pid);
        }
        if (hooked)
            assert(count(SYS_clone) == before + 1);
    }

    /* 新スタックを指定しないfork相当では、コピーされた親の保存フレームから
     * 復帰する必要があるため、新スタックの経路とは別に検査する。 */
    uint64_t before = hooked ? count(SYS_clone) : 0;
    long pid = probe_syscall6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
    assert(pid >= 0);
    if (!pid) {
        assert(probe_syscall6(SYS_getpid, 0, 0, 0, 0, 0, 0) > 0);
        _exit(0);
    }
    wait_child(pid);
    if (hooked)
        assert(count(SYS_clone) == before + 1);

    errno = EDOM;
    assert(probe_syscall6(SYS_clone, CLONE_SIGHAND | SIGCHLD,
                          (long)(base + size), 0, 0, 0, 0) == -EINVAL);
    if (hooked)
        assert(probe_syscall6(SYS_clone, CLONE_VM | SIGCHLD,
                              1, 0, 0, 0, 0) == -EFAULT);
    assert(errno == EDOM);
    assert(munmap(stack, size + 8192) == 0);
}

static void small_parent_stack(void)
{
    const size_t page = (size_t)sysconf(_SC_PAGESIZE);
    char *area = mmap(NULL, 2 * page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(area != MAP_FAILED);
    assert(mprotect(area + page, page, PROT_READ | PROT_WRITE) == 0);
    /* Goの失敗と同じく、syscall時の余裕を2 KiBに制限する。stack拡大による回避はしない。 */
    unsigned long before = mapped_pages();
    for (unsigned i = 0; i < 32; ++i) {
        long pid = probe_clone_small_stack(area + page + 2048);
        assert(pid > 0);
        wait_child(pid);
    }
    assert(mapped_pages() == before);
    assert(munmap(area, 2 * page) == 0);
}

static void clone_workspace_failure(void)
{
    if (!hooked)
        return;
    const unsigned denied[] = {SYS_mmap, SYS_mprotect};
    for (unsigned i = 0; i < sizeof(denied) / sizeof(denied[0]); ++i) {
        long pid = probe_syscall6(SYS_fork, 0, 0, 0, 0, 0, 0);
        assert(pid >= 0);
        if (!pid) {
            /* 子だけに制約を掛け、C用stackを得られない経路とguard設定失敗の回収を確認する。 */
            struct sock_filter filter[] = {
                BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
                BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, denied[i], 0, 1),
                BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOMEM),
                BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            };
            struct sock_fprog program = {.len = sizeof(filter) / sizeof(filter[0]), .filter = filter};
            assert(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
            assert(probe_syscall6(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, (long)&program, 0, 0, 0) == 0);
            unsigned long pages = mapped_pages();
            uint64_t before = count(SYS_clone) + count(SYS_vfork);
            for (unsigned j = 0; j < 32; ++j) {
                assert(probe_syscall6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0) == -ENOMEM);
                assert(probe_syscall6(SYS_vfork, 0, 0, 0, 0, 0, 0) == -ENOMEM);
            }
            assert(count(SYS_clone) + count(SYS_vfork) == before + 64);
            assert(mapped_pages() == pages);
            _exit(0);
        }
        wait_child(pid);
    }
}

static void clone3_cases(void)
{
    /* Dockerのseccompなどがclone3をENOSYSにする場合があるため、子を作らない
     * 不正サイズの要求で利用可否を調べる。ENOSYSを子作成の成功として数えない。 */
    uint64_t before = hooked ? count(SYS_clone3) : 0;
    long available = probe_syscall6(SYS_clone3, 0, 0, 0, 0, 0, 0);
    if (hooked)
        assert(count(SYS_clone3) == before + 1);
    if (available == -ENOSYS) {
        puts("clone3: unavailable on this host (child creation not tested)");
        return;
    }
    assert(available == -EINVAL);
    const size_t size = 65536;
    void *stack = mmap(NULL, size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(stack != MAP_FAILED);
    struct clone_args *readonly_args = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(readonly_args != MAP_FAILED);
    for (unsigned variant = 0; variant < 4; ++variant) {
        unsigned shared = variant & 1;
        size_t arg_size = variant < 2 ? CLONE_ARGS_SIZE_VER0 : sizeof(*readonly_args);
        struct clone_args args = {.flags = shared ? CLONE_VM : 0,
            .exit_signal = SIGCHLD, .stack = (uintptr_t)stack, .stack_size = size};
        struct clone_args snapshot = args;
        assert(mprotect(readonly_args, 4096, PROT_READ | PROT_WRITE) == 0);
        *readonly_args = args;
        assert(mprotect(readonly_args, 4096, PROT_READ) == 0);
        struct child_context ctx = {.top = (uintptr_t)stack + size,
            .arg1 = (uintptr_t)readonly_args, .arg2 = arg_size};
        before = hooked ? count(SYS_clone3) : 0;
        long pid = probe_clone(SYS_clone3, ctx.arg1, ctx.arg2, 0, &ctx);
        assert(pid > 0);
        wait_child(pid);
        assert(!memcmp(readonly_args, &snapshot, sizeof(args)));
        if (shared)
            assert(atomic_load(&ctx.ran) == 1);
        if (hooked)
            assert(count(SYS_clone3) == before + 1);
    }
    assert(munmap(readonly_args, 4096) == 0);
    struct clone_args args = {.exit_signal = SIGCHLD};
    long pid = probe_syscall6(SYS_clone3, (long)&args, sizeof(args), 0, 0, 0, 0);
    assert(pid >= 0);
    if (!pid)
        _exit(0);
    wait_child(pid);
    assert(probe_syscall6(SYS_clone3, -1, sizeof(args), 0, 0, 0, 0) == -EFAULT);
    assert(probe_syscall6(SYS_clone3, (long)&args, 8, 0, 0, 0, 0) == -EINVAL);
    assert(probe_syscall6(SYS_clone3, (long)&args, 4097, 0, 0, 0, 0) == -E2BIG);
    assert(munmap(stack, size) == 0);
    puts("clone3: verified registers, flags, new and copied stacks, and 64/88-byte read-only arguments");
}

int main(int argc, char **argv)
{
    int image = argc > 1 && !strcmp(argv[1], "--vfork-image");
    hooked = argc > (image ? 2 : 1) && !strcmp(argv[image ? 2 : 1], "--hooked");
    count = (uint64_t (*)(unsigned))dlsym(RTLD_DEFAULT, "zcomp_hook_count");
    assert(!hooked || count);
    assert(clone_probe_site[0] == (hooked ? 0xff : 0x0f));
    assert(clone_probe_site[1] == (hooked ? 0xd0 : 0x05));
    if (image) {
        uint64_t before = hooked ? count(SYS_getpid) : 0;
        assert(probe_syscall6(SYS_getpid, 0, 0, 0, 0, 0, 0) > 0);
        if (hooked)
            assert(count(SYS_getpid) == before + 1);
        return 0;
    }
    if (argc > 2 && !strcmp(argv[2], "--no-clone3"))
        disable_clone3();
    raw_clone_cases();
    small_parent_stack();
    clone_workspace_failure();
    clone3_cases();
    vfork_cases();
    vfork_kernel_failure();
    /* 子の実行中に親のフレームが再利用される状況を作るため、複数スレッドの作成を繰り返す。
     * 独立したTLSと、child-cleartidのfutex通知でjoinが完了することも検査する。 */
    uint64_t before = hooked ? count(SYS_clone) + count(SYS_clone3) : 0;
    uint64_t before_tid = hooked ? count(SYS_gettid) : 0;
    for (unsigned round = 0; round < 8; ++round) {
        pthread_t threads[8];
        for (unsigned i = 0; i < 8; ++i)
            assert(pthread_create(&threads[i], NULL, worker,
                                  (void *)(uintptr_t)(i + 100)) == 0);
        for (unsigned i = 0; i < 8; ++i) {
            void *result;
            assert(pthread_join(threads[i], &result) == 0);
            assert(result == (void *)(uintptr_t)(i + 100));
        }
    }
    assert(tls_value == 17);
    assert(atomic_load(&worker_calls) == 6400);
    if (hooked) {
        assert(count(SYS_clone) + count(SYS_clone3) >= before + 64);
        assert(count(SYS_gettid) >= before_tid + 6400);
    }
    puts(hooked ? "clone: verified intercepted child creation, registers, TLS, and join with 64 threads"
                : "clone: verified native child creation, registers, TLS, and join with 64 threads");
    guard_cases();
    return 0;
}
