#define _GNU_SOURCE
#include "hook.h"

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

extern long probe_syscall6(long, long, long, long, long, long, long);
extern unsigned char probe_site[];
extern char **environ;

static uint64_t (*count)(unsigned);

static void guard_image(void)
{
    /* execでSUDが解除された後、新imageの初期化が再設定したことを実発行で確認する。 */
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    unsigned char *code = mmap(NULL, page, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(code != MAP_FAILED);
    const unsigned char direct[] = {0xb8, 39, 0, 0, 0, 0x0f, 0x05, 0xc3};
    memcpy(code, direct, sizeof direct);
    assert(mprotect(code, page, PROT_READ | PROT_EXEC) == 0);
    assert(((long (*)(void))code)() == getpid());
    assert(munmap(code, page) == 0);
}

static void check_guard_exec(int hooked, const char *self)
{
    pid_t pid = fork();
    assert(pid >= 0);
    if (!pid) {
        char *args[] = {(char *)self, "--guard-image", NULL};
        char *empty[] = {NULL};
        probe_syscall6(SYS_execve, (long)self, (long)args, (long)empty, 0, 0, 0);
        _exit(111);
    }
    int status;
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == (hooked ? ZCOMP_GUARD_STATUS : 0));
}

static void check_capture(int hooked)
{
    count = (uint64_t (*)(unsigned))dlsym(RTLD_DEFAULT, "zcomp_hook_count");
    assert((count != NULL) == hooked);
    assert(probe_site[0] == (hooked ? 0xff : 0x0f));
    assert(probe_site[1] == (hooked ? 0xd0 : 0x05));
    uint64_t before = hooked ? count(SYS_getpid) : 0;
    long pid = probe_syscall6(SYS_getpid, 0, 0, 0, 0, 0, 0);
    if (hooked)
        assert(count(SYS_getpid) == before + 1);
    assert(pid == getpid());
}

static void check_preload(const char *path)
{
    const char *list = getenv("LD_PRELOAD");
    assert(list);
    size_t n = strlen(path);
    unsigned matches = 0;
    while (*list) {
        if (*list == ':' || *list == ' ') {
            ++list;
            continue;
        }
        const char *start = list;
        while (*list && *list != ':' && *list != ' ')
            ++list;
        matches += (size_t)(list - start) == n && !memcmp(start, path, n);
    }
    assert(matches == 1);
}

static void image(int argc, char **argv)
{
    assert(argc == 8);
    int hooked = !strcmp(argv[2], "--hooked");
    check_capture(hooked);
    assert(getpid() == (pid_t)strtol(argv[7], NULL, 10));
    int mode = atoi(argv[4]);
    if (mode == 3 || mode == 4) {
        assert(getenv("MARKER") && !strcmp(getenv("MARKER"), "kept"));
    } else if (mode != 0) {
        assert(!getenv("MARKER"));
    }
    if (hooked)
        check_preload(argv[5]);
    if (mode == 3) {
        int (*extra)(void) = (int (*)(void))dlsym(RTLD_DEFAULT, "zcomp_test_preload");
        assert(extra && extra() == 19);
        assert(getenv("ZCOMP_TRACE") && !strcmp(getenv("ZCOMP_TRACE"), "0"));
    }
    int remaining = atoi(argv[3]);
    if (remaining) {
        char next[16];
        snprintf(next, sizeof(next), "%d", remaining - 1);
        argv[3] = next;
        /* 前の環境に依存しない再注入を、2回目以降のexecでも要求する。 */
        char *env[] = {NULL};
        probe_syscall6(SYS_execve, (long)argv[0], (long)argv, (long)env, 0, 0, 0);
        assert(!"Chained exec must succeed without returning");
    }
}

static void run_image(int hooked, const char *self, const char *lib,
                       const char *extra, int mode, int chain)
{
    /* execの失敗処理や環境の構築を、共有スタックの制約から独立して検査する。 */
    long pid = probe_syscall6(SYS_fork, 0, 0, 0, 0, 0, 0);
    assert(pid >= 0);
    if (!pid) {
        char mode_text[16], chain_text[16], pid_text[32];
        snprintf(mode_text, sizeof(mode_text), "%d", mode);
        snprintf(chain_text, sizeof(chain_text), "%d", chain);
        snprintf(pid_text, sizeof(pid_text), "%ld", (long)getpid());
        char *args[] = {(char *)self, "--image", hooked ? "--hooked" : "--native",
                        chain_text, mode_text, (char *)lib, (char *)extra, pid_text, NULL};
        char preload[16384];
        /* 自分の重複を除きつつ、既存の別DSOをロードし続けることを検査する。 */
        snprintf(preload, sizeof(preload), "LD_PRELOAD=%s:%s:%s",
                 extra, hooked ? lib : extra, hooked ? lib : extra);
        char *explicit_env[] = {"MARKER=kept", preload, "ZCOMP_TRACE=0", NULL};
        char *empty_env[] = {NULL};
        char **env = mode == 0 ? environ : empty_env;
        if (mode == 2)
            env = NULL;
        if (mode == 3)
            env = explicit_env;
        if (mode == 4) {
            long page = sysconf(_SC_PAGESIZE);
            char *guard = mmap(NULL, page * 2, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            assert(guard != MAP_FAILED);
            assert(mprotect(guard + page, page, PROT_NONE) == 0);
            char *entry = guard + page - sizeof("MARKER=kept");
            memcpy(entry, "MARKER=kept", sizeof("MARKER=kept"));
            assert(mprotect(guard, page, PROT_READ) == 0);
            explicit_env[0] = entry;
            explicit_env[1] = NULL;
            env = explicit_env;
        }
        long result;
        if (mode == 5) {
            int fd = open(self, O_PATH | O_CLOEXEC);
            assert(fd >= 0);
            result = probe_syscall6(SYS_execveat, fd, (long)"", (long)args,
                                    (long)env, AT_EMPTY_PATH, 0);
        } else if (mode == 6) {
            /* FD相対のパスを維持する経路も、AT_EMPTY_PATHとは別に検査する。 */
            char directory[4096];
            assert(strlen(self) < sizeof(directory));
            strcpy(directory, self);
            char *name = strrchr(directory, '/');
            assert(name);
            *name++ = 0;
            int fd = open(directory, O_PATH | O_DIRECTORY | O_CLOEXEC);
            assert(fd >= 0);
            result = probe_syscall6(SYS_execveat, fd, (long)name, (long)args,
                                    (long)env, 0, 0);
        } else {
            result = probe_syscall6(SYS_execve, (long)self, (long)args,
                                    (long)env, 0, 0, 0);
        }
        fprintf(stderr, "Exec test: cannot enter the new image (mode=%d result=%ld).\n",
                mode, result);
        _exit(1);
    }
    int status;
    assert(waitpid((pid_t)pid, &status, 0) == pid);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void failures(int hooked, const char *self)
{
    long page = sysconf(_SC_PAGESIZE);
    char **env = mmap(NULL, page, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(env != MAP_FAILED);
    env[0] = "MARKER=kept";
    env[1] = NULL;
    assert(mprotect(env, page, PROT_READ) == 0);
    char *args[] = {(char *)self, NULL};
    uint64_t before = hooked ? count(SYS_execve) : 0;
    errno = EDOM;
    assert(probe_syscall6(SYS_execve, (long)"/proc/self/zcomp-missing",
                          (long)args, (long)env, 0, 0, 0) == -ENOENT);
    assert(errno == EDOM);
    assert(env[0] && !strcmp(env[0], "MARKER=kept") && !env[1]);
    if (hooked)
        assert(count(SYS_execve) == before + 1);
    assert(probe_syscall6(SYS_execve, (long)self, -1, (long)env, 0, 0, 0) == -EFAULT);
    assert(probe_syscall6(SYS_execve, (long)self, (long)args, -1, 0, 0, 0) == -EFAULT);
    assert(probe_syscall6(SYS_execve, (long)"/proc/self", (long)args,
                          (long)env, 0, 0, 0) == -EACCES);
    assert(probe_syscall6(SYS_execveat, -1, (long)"", (long)args,
                          (long)env, AT_EMPTY_PATH, 0) == -EBADF);
    assert(probe_syscall6(SYS_execveat, AT_FDCWD, (long)self, (long)args,
                          (long)env, -1, 0) == -EINVAL);
    void *guard = mmap(NULL, page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(guard != MAP_FAILED);
    char *bad_env[] = {guard, NULL};
    assert(probe_syscall6(SYS_execve, (long)self, (long)args,
                          (long)bad_env, 0, 0, 0) == -EFAULT);
    char *huge = mmap(NULL, 128 * 1024, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(huge != MAP_FAILED);
    memset(huge, 'x', 128 * 1024);
    char *huge_env[] = {huge, NULL};
    assert(probe_syscall6(SYS_execve, (long)self, (long)args,
                          (long)huge_env, 0, 0, 0) == -E2BIG);
    assert(munmap(huge, 128 * 1024) == 0);
    assert(munmap(guard, page) == 0);
    assert(munmap(env, page) == 0);
    /* 失敗したexecで既存のフックや復帰経路を壊していないことを検査する。 */
    check_capture(hooked);
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "--guard-image")) {
        guard_image();
        return 0;
    }
    if (argc > 1 && !strcmp(argv[1], "--image")) {
        image(argc, argv);
        return 0;
    }
    assert(argc == 4);
    int hooked = !strcmp(argv[1], "--hooked");
    char self[4096];
    assert(realpath(argv[0], self));
    check_capture(hooked);
    failures(hooked, self);
    for (int mode = 0; mode <= 6; ++mode)
        run_image(hooked, self, argv[2], argv[3], mode, 0);
    run_image(hooked, self, argv[2], argv[3], 1, 2);
    check_guard_exec(hooked, self);
    puts(hooked ? "Exec: verified reinjection, chained exec, existing preload, empty environment, execveat, and interception after failure"
                : "Native Linux: verified exec, environment, execveat, and errors");
    return 0;
}
