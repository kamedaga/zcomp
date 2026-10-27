#include <unistd.h>
static _Thread_local int library_tls = 11;
static int ready;
__attribute__((constructor)) static void initialize(void) { ready = 1; }

int zcomp_library_probe(int value)
{
    int previous = library_tls;
    library_tls = value;
    return ready ? previous : -1;
}

long zcomp_library_getpid(void)
{
    // libcへの呼出しではなく、追加DSO自身のRX写像にあるsyscallも書換えられることを確かめる。
    long result = 39;
    __asm__ volatile("syscall" : "+a"(result) : : "rcx", "r11", "memory");
    return result;
}
