#include "detour.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static enum zcomp_detour_result analyze(uint8_t *code, size_t size, size_t at,
                                       struct zcomp_detour *plan)
{
    uint8_t targets[128] = {0};
    assert(size <= sizeof(targets));
    zcomp_detour_targets(code, size, targets);
    return zcomp_detour_analyze(code, size, at, targets, plan);
}

int main(void)
{
    struct zcomp_detour plan;
    uint8_t epoll[] = {0xb8, 233, 0, 0, 0, 0xbe, 1, 0, 0, 0,
                      0x0f, 0x05, 0x48, 0x89, 0xc2, 0x31, 0xc0};
    assert(analyze(epoll, sizeof(epoll), 10, &plan) == ZCOMP_DETOUR_OK);
    assert(plan.length == 5 && plan.nr == 233);
    uint8_t buffer[256];
    memcpy(buffer, epoll, sizeof(epoll));
    assert(!zcomp_detour_emit(buffer + 96, buffer + 10, &plan, 0x12345678));
    assert(!memcmp(buffer + 96 + 56, epoll + 12, 3));
    uint8_t write[] = {0xb8, 1, 0, 0, 0, 0xba, 8, 0, 0, 0,
                      0x0f, 0x05, 0x48, 0x3d, 1, 0xf0, 0xff, 0xff};
    assert(analyze(write, sizeof(write), 10, &plan) == ZCOMP_DETOUR_OK);
    assert(plan.length == 8 && plan.nr == 1);
    /* 途中へ分岐する命令、RIP相対参照、stack操作、特殊番号を受け入れない。 */
    uint8_t branch[] = {0xb8, 1, 0, 0, 0, 0x0f, 0x05, 0x48, 0x89, 0xc2, 0xeb, 0xfb};
    assert(analyze(branch, sizeof(branch), 5, &plan) == ZCOMP_DETOUR_BRANCH);
    uint8_t memory[] = {0xb8, 1, 0, 0, 0, 0x0f, 0x05, 0x48, 0x8b, 0x05, 0, 0, 0, 0};
    assert(analyze(memory, sizeof(memory), 5, &plan) == ZCOMP_DETOUR_INSTRUCTION);
    uint8_t stack[] = {0xb8, 1, 0, 0, 0, 0x0f, 0x05, 0x48, 0x83, 0xc4, 8};
    assert(analyze(stack, sizeof(stack), 5, &plan) == ZCOMP_DETOUR_INSTRUCTION);
    epoll[1] = 56;
    assert(analyze(epoll, sizeof(epoll), 10, &plan) == ZCOMP_DETOUR_SPECIAL);
    epoll[0] = 0x90;
    assert(analyze(epoll, sizeof(epoll), 10, &plan) == ZCOMP_DETOUR_NUMBER);
    puts("PASS: Detour planning and relocation checks passed.");
    return 0;
}
