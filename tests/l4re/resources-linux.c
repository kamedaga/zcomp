#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

enum { Page = 4096 };
static void require(int ok, char const *step)
{
    if (!ok) { fprintf(stderr, "FAIL: resources %s (errno=%d)\n", step, errno); exit(1); }
}

int main(void)
{
    int fd = open("public.txt", O_RDONLY);
    char bytes[8];
    struct stat metadata;
    require(fd >= 3 && fstat(fd, &metadata) == 0 && metadata.st_size == 8, "open and fstat");
    require(read(fd, bytes, 3) == 3 && !memcmp(bytes, "pub", 3), "read");
    require(pread(fd, bytes, 8, 0) == 8 && !memcmp(bytes, "public!\n", 8)
            && lseek(fd, 0, SEEK_CUR) == 3, "pread preserves position");
    unsigned char *file = mmap(0, Page, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    require(file != MAP_FAILED && !memcmp(file, "public!\n", 8) && file[8] == 0, "private file mapping");
    require(close(fd) == 0, "close mapped file");
    file[0] = 'X';
    fd = open("public.txt", O_RDONLY);
    require(fd >= 3 && pread(fd, bytes, 8, 0) == 8 && bytes[0] == 'p', "private contents and mapping lifetime");
    require(munmap(file, Page) == 0, "unmap private file");

    unsigned char *memory = mmap(0, 3 * Page, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    require(memory != MAP_FAILED && memory[0] == 0 && memory[3 * Page - 1] == 0, "anonymous zeroing");
    memory[0] = 0x51;
    memory[2 * Page] = 0x72;
    require(mprotect(memory + Page, Page, PROT_READ) == 0, "partial mprotect");
    require(pread(fd, memory + Page, 1, 0) == -1 && errno == EFAULT, "read-only destination rejected");
    require(munmap(memory + Page, Page) == 0, "partial munmap");
    require(pread(fd, memory + Page, 1, 0) == -1 && errno == EFAULT, "unmapped destination rejected");
    require(mmap(memory + Page, Page, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == memory + Page, "fixed replacement");
    require(memory[Page] == 0 && memory[0] == 0x51 && memory[2 * Page] == 0x72, "neighbor contents retained");
    require(munmap(memory, 3 * Page) == 0 && close(fd) == 0, "release resources");
    puts("PASS: File operations, private mappings, zeroing, partial protection, and unmapping.");
    return 0;
}
