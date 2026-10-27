#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <unistd.h>
#include <elf.h>

extern void _start(void);
extern Elf64_Dyn _DYNAMIC[];
extern int zcomp_library_probe(int);
extern long zcomp_library_getpid(void);
static _Thread_local int main_tls = 7;
static int ready;
static int *volatile relocated_ready = &ready;
__attribute__((constructor)) static void initialize(void) { ready = 1; }
static void require(int ok, char const *step)
{
    if (!ok) { fprintf(stderr, "FAIL: dynamic hello %s (errno=%d)\n", step, errno); _exit(1); }
}

static uintptr_t check_auxv(void)
{
    uintptr_t phdr_address = getauxval(AT_PHDR);
    size_t count = getauxval(AT_PHNUM);
    require(getauxval(AT_PHENT) == sizeof(Elf64_Phdr) && count > 0 && count <= 64 && phdr_address,
            "main program headers");
    Elf64_Phdr const *phdr = (void const *)phdr_address;
    uintptr_t bias = 0;
    int found = 0;
    size_t alignment = 4096;
    for (size_t i = 0; i < count; ++i) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            bias = (uintptr_t)_DYNAMIC - phdr[i].p_vaddr;
            found = 1;
        }
        if (phdr[i].p_type == PT_LOAD && phdr[i].p_align > alignment) alignment = phdr[i].p_align;
    }
    require(found && bias % alignment == 0 && relocated_ready == &ready && *relocated_ready == 1,
            "load bias, alignment, and main relocation");
    require(getauxval(AT_ENTRY) == (uintptr_t)&_start, "relocated main entry");
    int header_found = 0;
    for (size_t i = 0; i < count; ++i)
        if (phdr[i].p_type == PT_LOAD && phdr[i].p_offset == 0) {
            Elf64_Ehdr const *header = (void const *)(bias + phdr[i].p_vaddr);
            require(!memcmp(header->e_ident, ELFMAG, SELFMAG)
                    && (uintptr_t)header + header->e_phoff == phdr_address
                    && bias + header->e_entry == getauxval(AT_ENTRY), "relocated main ELF headers");
            require(header->e_type == ET_EXEC ? bias == 0 : header->e_type == ET_DYN && bias != 0,
                    "main ELF type and load bias");
            header_found = 1;
        }
    require(header_found, "mapped main ELF header");
    Elf64_Ehdr const *interpreter = (void const *)getauxval(AT_BASE);
    require(interpreter && !memcmp(interpreter->e_ident, ELFMAG, SELFMAG)
            && interpreter->e_type == ET_DYN, "interpreter auxv base");
    return bias;
}

static void check_image_reservations(uintptr_t main_bias)
{
    size_t size = 32 * 1024;
    unsigned char *memory = mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    require(memory != MAP_FAILED, "allocation around ELF reservations");
    uintptr_t bases[] = {main_bias, getauxval(AT_BASE)};
    Elf64_Ehdr const *interpreter = (void const *)bases[1];
    Elf64_Phdr const *tables[] = {(void const *)getauxval(AT_PHDR),
                                 (void const *)(bases[1] + interpreter->e_phoff)};
    size_t counts[] = {getauxval(AT_PHNUM), interpreter->e_phnum};
    for (unsigned image = 0; image < 2; ++image) {
        uintptr_t first = UINTPTR_MAX, last = 0;
        for (size_t i = 0; i < counts[image]; ++i) {
            Elf64_Phdr const *p = &tables[image][i];
            if (p->p_type != PT_LOAD) continue;
            uintptr_t begin = (bases[image] + p->p_vaddr) & ~(uintptr_t)4095;
            uintptr_t end = (bases[image] + p->p_vaddr + p->p_memsz + 4095) & ~(uintptr_t)4095;
            if (begin < first) first = begin;
            if (end > last) last = end;
        }
        // 大きいalignmentで生じるimage内部の穴も、一般のmmapに再利用させない。
        require((uintptr_t)memory + size <= first || (uintptr_t)memory >= last, "mmap avoided ELF footprint");
    }
    memory[0] = 0x5a; memory[size - 1] = 0x6b;
    require(memory[0] == 0x5a && munmap(memory, size) == 0, "release allocation around ELF images");
}

int main(int argc, char **argv)
{
    int native = argc == 2 && !strcmp(argv[1], "native");
    uintptr_t main_bias = check_auxv();
    require(ready && main_tls == 7 && zcomp_library_probe(19) == 11, "constructors and TLS templates");
    require(zcomp_library_getpid() == getpid(), "raw syscall in shared library");
    if (!native) {
        check_image_reservations(main_bias);
        require(open("/rom/zcomp-run", O_RDONLY) == -1 && errno == ENOENT, "no startup ROM fallback");
        require(open("/lib/../rom/zcomp-run", O_RDONLY) == -1 && errno == EACCES, "parent traversal rejected");
        int fd = openat(-1, "//lib/./libzcomp-example.so", O_RDONLY);
        require(fd >= 3, "absolute path ignores directory fd");
        char magic[4];
        require(read(fd, magic, sizeof(magic)) == 4 && !memcmp(magic, ELFMAG, 4), "published library path");
        require(close(fd) == 0, "library close");
    }
    // 新しいmain/interpreter配置も既存forkで複製し、guest TLSや再配置済みDSOを壊さない。
    pid_t child = fork();
    require(child >= 0, "fork dynamic process");
    if (!child) {
        check_auxv();
        require(main_tls == 7 && zcomp_library_probe(23) == 19, "child dynamic TLS");
        require(zcomp_library_getpid() == getpid(), "child shared-library syscall");
        main_tls = 17;
        _exit(0);
    }
    int status;
    require(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
            "reap dynamic child");
    require(main_tls == 7 && zcomp_library_probe(29) == 19, "parent TLS remained private");
    puts("Hello World! (dynamic musl -> interpreter -> zpoline -> L4Re)");
    puts("PASS: Dynamic musl auxv, relocation, constructors, TLS, shared-library syscall, and fork.");
    return 0;
}
