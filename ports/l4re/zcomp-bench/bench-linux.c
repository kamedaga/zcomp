#define _GNU_SOURCE
#include "bench_measure.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <string.h>

static int file;
static unsigned char buffer[4096];
static struct stat metadata;

static inline long raw_call(long number, long a, long b, long c, long d, long e, long f)
{
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = f;
    // libcのキャッシュやvDSOを測らず、書換え対象となるLinux syscall命令を必ず通す。
    __asm__ volatile("syscall" : "+a"(number) : "D"(a), "S"(b), "d"(c),
                     "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "cc", "memory");
    return number;
}

static void call_getpid(uint64_t n)
{
    uint64_t total = 0;
    for (uint64_t i = 0; i < n; ++i) {
        long pid = raw_call(SYS_getpid, 0, 0, 0, 0, 0, 0);
        bench_require(pid > 0, "getpid"); total += pid;
    }
    bench_sink = total;
}
static void call_enosys(uint64_t n)
{
    // 0番地trampolineの対応範囲内で、両実装とも未実装である番号を検査する。
    for (uint64_t i = 0; i < n; ++i)
        bench_require(raw_call(511, 0, 0, 0, 0, 0, 0) == -ENOSYS, "ENOSYS");
}
static void call_write_zero(uint64_t n)
{
    for (uint64_t i = 0; i < n; ++i)
        bench_require(raw_call(SYS_write, 1, (long)buffer, 0, 0, 0, 0) == 0, "write zero");
}
static void call_pread(uint64_t n)
{
    for (uint64_t i = 0; i < n; ++i)
        bench_require(raw_call(SYS_pread64, file, (long)buffer, 8, 0, 0, 0) == 8, "pread 8 bytes");
    bench_require(!memcmp(buffer, "public!\n", 8), "pread contents");
    bench_sink = buffer[0];
}
static void call_fstat(uint64_t n)
{
    for (uint64_t i = 0; i < n; ++i)
        bench_require(raw_call(SYS_fstat, file, (long)&metadata, 0, 0, 0, 0) == 0, "fstat");
    bench_require(metadata.st_size >= 8, "file size");
}
static void call_open_close(uint64_t n)
{
    for (uint64_t i = 0; i < n; ++i) {
        long fd = raw_call(SYS_openat, AT_FDCWD, (long)"public.txt", O_RDONLY, 0, 0, 0);
        bench_require(fd >= 3, "openat");
        bench_require(raw_call(SYS_close, fd, 0, 0, 0, 0, 0) == 0, "close");
    }
}
static void call_map_unmap(uint64_t n)
{
    for (uint64_t i = 0; i < n; ++i) {
        long address = raw_call(SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        bench_require(address > 0, "mmap");
        // Linuxの遅延割当とL4Reの明示的確保を、未接触ページのまま比べない。
        *(volatile unsigned char *)address = 42;
        bench_require(raw_call(SYS_munmap, address, 4096, 0, 0, 0, 0) == 0, "munmap");
    }
}

static void check_reused_protection(void)
{
    long address = raw_call(SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    bench_require(address > 0, "reused protection initial allocation");
    memset((void *)address, 0xa5, 4096);
    bench_require(raw_call(SYS_munmap, address, 4096, 0, 0, 0, 0) == 0, "reused protection initial detach");
    bench_require(raw_call(SYS_pread64, file, address, 1, 0, 0, 0) == -EFAULT, "detached page is inaccessible");
    address = raw_call(SYS_mmap, 0, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    bench_require(address > 0, "reused protection guard allocation");
    bench_require(raw_call(SYS_pread64, file, address, 1, 0, 0, 0) == -EFAULT, "reused guard rejects writes");
    bench_require(raw_call(SYS_mprotect, address, 4096, PROT_READ, 0, 0, 0) == 0, "reused page read-only");
    // 再利用前の内容が消えていることと、RW aliasがguestの保護を迂回しないことを計測前に確かめる。
    for (unsigned i = 0; i < 4096; ++i)
        bench_require(((volatile unsigned char *)address)[i] == 0, "reused page is fully zeroed");
    bench_require(raw_call(SYS_pread64, file, address, 1, 0, 0, 0) == -EFAULT, "read-only reused page rejects writes");
    bench_require(raw_call(SYS_mprotect, address, 4096, PROT_READ | PROT_WRITE, 0, 0, 0) == 0,
                  "reused page writable");
    bench_require(raw_call(SYS_pread64, file, address, 8, 0, 0, 0) == 8
                  && !memcmp((void *)address, "public!\n", 8), "reused page accepts writes after mprotect");
    bench_require(raw_call(SYS_munmap, address, 4096, 0, 0, 0, 0) == 0, "reused protection final detach");
}
int main(void)
{
    file = raw_call(SYS_openat, AT_FDCWD, (long)"public.txt", O_RDONLY, 0, 0, 0);
    bench_require(file >= 3, "fixture open");
    check_reused_protection();
    // メモリ経路が速くなった後も、100 ms以上のguest区間でTSC校正を独立して照合する。
    bench_run("integer", 300000000, bench_integer);
    bench_run("getpid", 20000, call_getpid);
    bench_run("enosys", 20000, call_enosys);
    bench_run("write_zero", 20000, call_write_zero);
    bench_run("pread8", 20000, call_pread);
    bench_run("fstat", 20000, call_fstat);
    bench_run("open_close", 1000, call_open_close);
    bench_run("map_touch_unmap", 250, call_map_unmap);
    bench_require(raw_call(SYS_close, file, 0, 0, 0, 0, 0) == 0, "fixture close");
    bench_report("linux");
    return 0;
}
