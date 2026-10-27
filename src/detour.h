#ifndef ZCOMP_DETOUR_H
#define ZCOMP_DETOUR_H

#include <stddef.h>
#include <stdint.h>

enum { ZCOMP_DETOUR_SLOT = 96 };

/* 個別ELFの番地表ではなく、元の命令列から得た適用条件だけを保持する。 */
struct zcomp_detour {
    uint8_t *stub;
    unsigned length;
    unsigned nr;
};

enum zcomp_detour_result {
    ZCOMP_DETOUR_OK,
    ZCOMP_DETOUR_NUMBER,
    ZCOMP_DETOUR_SPECIAL,
    ZCOMP_DETOUR_INSTRUCTION,
    ZCOMP_DETOUR_BRANCH,
};

enum zcomp_detour_result zcomp_detour_analyze(const uint8_t *code, size_t size,
                                             size_t at, const uint8_t *targets,
                                             struct zcomp_detour *out);
void zcomp_detour_targets(const uint8_t *code, size_t size, uint8_t *targets);
int zcomp_detour_emit(uint8_t *stub, const uint8_t *site,
                      const struct zcomp_detour *plan, uintptr_t entry);

#endif
