#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>

static long call(long number, long a, long b, long c, long d, long e, long f)
{
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = f;
    __asm__ volatile("syscall" : "+a"(number) : "D"(a), "S"(b), "d"(c),
                     "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "cc", "memory");
    return number;
}

static int equal(char const *a, char const *b)
{
    while (*a && *a == *b) { ++a; ++b; }
    return *a == *b;
}

static int check(char const *operation, long expected)
{
    if (equal(operation, "output")) {
        // 出力を拒否する試験自身がputs等で成功通知できることを前提にしない。
        return call(SYS_write, 1, (long)"policy output\n", 14, 0, 0, 0) == (expected ? expected : 14);
    }
    if (equal(operation, "files")) {
        long fd = call(SYS_openat, AT_FDCWD, (long)"public.txt", O_RDONLY, 0, 0, 0);
        if (expected) return fd == expected;
        char bytes[8];
        if (fd < 3 || call(SYS_read, fd, (long)bytes, sizeof(bytes), 0, 0, 0) != 8) return 0;
        for (unsigned i = 0; i < sizeof(bytes); ++i)
            if (bytes[i] != "public!\n"[i]) return 0;
        return call(SYS_close, fd, 0, 0, 0, 0, 0) == 0;
    }
    if (equal(operation, "memory")) {
        long address = call(SYS_mmap, 0, 128 * 1024, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (expected) return address == expected;
        if (address <= 0) return 0;
        unsigned char *bytes = (void *)address;
        if (bytes[0] || bytes[128 * 1024 - 1]) return 0;
        bytes[0] = 42;
        return call(SYS_munmap, address, 128 * 1024, 0, 0, 0, 0) == 0;
    }
    if (equal(operation, "process")) {
        long child = call(SYS_fork, 0, 0, 0, 0, 0, 0);
        if (expected) return child == expected;
        if (!child) {
            call(SYS_exit, 23, 0, 0, 0, 0, 0);
            __builtin_trap();
        }
        int status = 0;
        return child > 0 && call(SYS_wait4, child, (long)&status, 0, 0, 0, 0) == child
               && status == (23 << 8);
    }
    return 0;
}

int policy_main(long argc, char const *const *argv)
{
    // CRTのメモリ確保やTLS初期化を混ぜず、権限を変えても同じELFから同じsyscallを発行する。
    if (argc != 3) return 2;
    long expected;
    if (equal(argv[2], "EACCES")) expected = -EACCES;
    else if (equal(argv[2], "ENOMEM")) expected = -ENOMEM;
    else if (equal(argv[2], "success")) expected = 0;
    else return 2;
    if (equal(argv[1], "all"))
        return expected || !check("output", 0) || !check("files", 0)
               || !check("memory", 0) || !check("process", 0);
    return !check(argv[1], expected);
}
