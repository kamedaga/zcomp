#ifndef ZCOMP_ELF_IMAGE_H
#define ZCOMP_ELF_IMAGE_H

#include <elf.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum { ZCOMP_MAX_SEGMENTS = 16, ZCOMP_MAX_INTERPRETER = 256 };
struct zcomp_elf_image {
    Elf64_Ehdr header;
    Elf64_Phdr segments[ZCOMP_MAX_SEGMENTS];
    size_t count;
    uint64_t phdr_address;
    uint64_t first_page, last_page, alignment;
    Elf64_Phdr dynamic;
    char interpreter[ZCOMP_MAX_INTERPRETER];
};

/* 検査をホストでも実行できるよう、L4Reへの依存とメモリへの配置を分離する。 */
const char *zcomp_elf_validate(const void *bytes, size_t size,
                              struct zcomp_elf_image *image);

/* zcomp_elf_validate成功後にだけ使う。外部interpreterなしで起動を試せる範囲へ絞る。 */
const char *zcomp_elf_validate_static_pie(const void *bytes,
                                         const struct zcomp_elf_image *image);

#ifdef __cplusplus
}
#endif
#endif
