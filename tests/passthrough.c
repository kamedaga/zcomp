#define _GNU_SOURCE
#include "hook.h"

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern long probe_syscall6(long, long, long, long, long, long, long);
extern int probe_registers(void);
extern long probe_overlapping(void);
extern unsigned char probe_site[], probe_regs_site[];

static volatile sig_atomic_t signalled;
static void handler(int signal_number) { signalled = signal_number; }

static void check_patch(const unsigned char *site, int hooked)
{
    assert(site[0] == (hooked ? 0xff : 0x0f));
    assert(site[1] == (hooked ? 0xd0 : 0x05));
}

static void check_unhooked(long (*operation)(void), int hooked)
{
    /* 以前は素通りで成功した例を、guard有効時には実行前の停止として検査する。 */
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        long expected = getpid();
        assert(operation() == expected);
        _exit(0);
    }
    int status;
    assert(waitpid(child, &status, 0) == child);
    if (hooked)
        assert(WIFEXITED(status) && WEXITSTATUS(status) == ZCOMP_GUARD_STATUS);
    else
        assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void check_vdso(int hooked, uint64_t (*count)(unsigned))
{
    void *handle = dlopen("linux-vdso.so.1", RTLD_NOW | RTLD_LOCAL);
    assert(handle);
    int (*clock_time)(clockid_t, struct timespec *) = dlsym(handle, "__vdso_clock_gettime");
    int (*clock_res)(clockid_t, struct timespec *) = dlsym(handle, "__vdso_clock_getres");
    assert(clock_time && clock_res);
    struct timespec value;
    /* CPU時間のclockはvDSOの共有データだけで処理できない。KVMでもfallbackを
     * 必ず通し、時刻取得が成功しただけでは捕捉成功に数えない。 */
    uint64_t before = hooked ? count(SYS_clock_gettime) : 0;
    assert(clock_time(CLOCK_PROCESS_CPUTIME_ID, &value) == 0);
    assert(value.tv_sec >= 0 && value.tv_nsec >= 0 && value.tv_nsec < 1000000000);
    if (hooked) assert(count(SYS_clock_gettime) == before + 1);
    before = hooked ? count(SYS_clock_getres) : 0;
    assert(clock_res(CLOCK_PROCESS_CPUTIME_ID, &value) == 0);
    if (hooked) assert(count(SYS_clock_getres) == before + 1);

    ssize_t (*random_bytes)(void *, size_t, unsigned, void *, size_t)
        = dlsym(handle, "__vdso_getrandom");
    if (random_bytes) {
        unsigned char bytes[16];
        before = hooked ? count(SYS_getrandom) : 0;
        /* private RNG stateを渡さず、kernelの乱数取得へfallbackさせる。
         * 乱数の値ではなく、取得サイズとフック計数を検査する。 */
        assert(random_bytes(bytes, sizeof bytes, 0, NULL, 0) == sizeof bytes);
        if (hooked) assert(count(SYS_getrandom) == before + 1);
    }
    assert(dlclose(handle) == 0);
    puts(hooked ? "vDSO: verified intercepted clock and available random syscall fallbacks"
                : "vDSO: verified native clock and available random syscall fallbacks");
}

int main(int argc, char **argv)
{
    int hooked = argc > 1 && !strcmp(argv[1], "--hooked");
    uint64_t (*count)(unsigned) = (uint64_t (*)(unsigned))
        dlsym(RTLD_DEFAULT, "zcomp_hook_count");
    if (hooked)
        assert(count);
    check_patch(probe_site, hooked);
    check_patch(probe_regs_site, hooked);

    uint64_t before = hooked ? count(SYS_getpid) : 0;
    long pid = probe_syscall6(SYS_getpid, 0, 0, 0, 0, 0, 0);
    assert(pid > 0);
    if (hooked)
        assert(count(SYS_getpid) == before + 1);
    assert(pid == getpid());
    assert(probe_registers() == 0);
    check_vdso(hooked, count);
    check_unhooked(probe_overlapping, hooked);

    /* 生のsyscallの契約を保つため、負のerrnoをそのまま返し、libcのerrnoを変更しないことを検査する。 */
    errno = EDOM;
    assert(probe_syscall6(SYS_write, -1, (long)"x", 1, 0, 0, 0) == -EBADF);
    assert(errno == EDOM);

    struct utsname expected, actual;
    assert(uname(&expected) == 0);
    assert(probe_syscall6(SYS_uname, (long)&actual, 0, 0, 0, 0, 0) == 0);
    assert(!strcmp(expected.sysname, actual.sysname));
    assert(!strcmp(expected.release, actual.release));

    /* r10とrcxの取り違えや第6引数の欠落を検出するため、6引数のmmapで
     * ファイルの先頭以外をマップする。 */
    long page = sysconf(_SC_PAGESIZE);
    int fd = (int)probe_syscall6(SYS_memfd_create, (long)"zcomp-test", 0, 0, 0, 0, 0);
    assert(fd >= 0);
    assert(ftruncate(fd, page * 2) == 0);
    assert(pwrite(fd, "offset-ok", 10, page) == 10);
    before = hooked ? count(SYS_mmap) : 0;
    long mapping = probe_syscall6(SYS_mmap, 0, page, PROT_READ, MAP_PRIVATE, fd, page);
    assert((unsigned long)mapping < (unsigned long)-4095);
    if (hooked)
        assert(count(SYS_mmap) == before + 1);
    assert(!memcmp((void *)mapping, "offset-ok", 10));
    assert(probe_syscall6(SYS_munmap, mapping, page, 0, 0, 0, 0) == 0);
    assert(close(fd) == 0);

    struct sigaction action = {0};
    action.sa_handler = handler;
    assert(sigemptyset(&action.sa_mask) == 0);
    assert(sigaction(SIGUSR1, &action, NULL) == 0);
    before = hooked ? count(SYS_rt_sigreturn) : 0;
    assert(probe_syscall6(SYS_kill, pid, SIGUSR1, 0, 0, 0, 0) == 0);
    assert(signalled == SIGUSR1);
    if (hooked) {
        assert(count(SYS_rt_sigreturn) == before + 1);
        /* 0番地はトランポリンとして読めるため、不正ポインタの検査には-1を使う。 */
        assert(probe_syscall6(SYS_execve, -1, 0, 0, 0, 0, 0) == -EFAULT);
    }
    puts(hooked ? "Passthrough: verified interception, arguments, errors, registers, and signal return"
                : "Native Linux: verified arguments, errors, registers, and signals");
    return 0;
}
