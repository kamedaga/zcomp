#include "hook.h"

#include <errno.h>
#include <signal.h>
#include <sys/syscall.h>

static void stop(const char *message, size_t size, int status)
{
    zcomp_raw_syscall(SYS_write, 2, (long)message, size, 0, 0, 0);
    zcomp_raw_syscall(SYS_exit_group, status, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}

static char *number(char *out, unsigned long value, unsigned base)
{
    const char digits[] = "0123456789abcdef";
    char reverse[32];
    unsigned used = 0;
    do {
        reverse[used++] = digits[value % base];
        value /= base;
    } while (value);
    while (used)
        *out++ = reverse[--used];
    return out;
}

static void blocked(int signal_number, siginfo_t *info, void *context)
{
    (void)signal_number;
    (void)context;
    // 未捕捉を互換処理へ転送すると成功に見えるため、記録した後は必ず終了する。
    // signal中にlibc・TLS・mallocへ再入せず、許可されたnative発行点だけを使う。
    char line[128];
    char *out = line;
    const char prefix[] = "zcomp: blocked unhooked syscall nr=";
    for (size_t i = 0; i < sizeof(prefix) - 1; ++i)
        *out++ = prefix[i];
    out = number(out, (unsigned)info->si_syscall, 10);
    const char middle[] = " ip=0x";
    for (size_t i = 0; i < sizeof(middle) - 1; ++i)
        *out++ = middle[i];
    out = number(out, (uintptr_t)info->si_call_addr, 16);
    *out++ = '\n';
    stop(line, (size_t)(out - line), ZCOMP_GUARD_STATUS);
}

void zcomp_guard_prepare(void)
{
    // まだlibcを書き換えていない初期化段階で、停止理由を残すhandlerを用意する。
    // アプリがSIGSYSの扱いを変更しても、SUDが拒否したsyscall自体は実行されない。
    struct sigaction action = {0};
    action.sa_sigaction = blocked;
    action.sa_flags = SA_SIGINFO | SA_ONSTACK;
    if (sigemptyset(&action.sa_mask) || sigaction(SIGSYS, &action, 0)) {
        const char message[] = "zcomp: Cannot install the unhooked-syscall guard handler.\n";
        stop(message, sizeof(message) - 1, 1);
    }
}

void zcomp_guard_start(void)
{
    long result = zcomp_guard_enable();
    if (result < 0) {
        // 非対応kernelでも素通りへ退避しない。検査できない実行を成功扱いさせない。
        const char message[] = "zcomp: Cannot enable Syscall User Dispatch; interception is not verified.\n";
        stop(message, sizeof(message) - 1,
             result == -EINVAL || result == -ENOSYS ? 77 : 1);
    }
    const char message[] = "zcomp: guard=sud scope=post-init\n";
    zcomp_raw_syscall(SYS_write, 2, (long)message, sizeof(message) - 1, 0, 0, 0);
}
