#define _GNU_SOURCE
#include "hook.h"
#include "scan.h"
#include "detour.h"

#include <errno.h>
#include <dlfcn.h>
#include <link.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

char zcomp_preload_path[4096];
size_t zcomp_page_size;

/* 走査と書き換えを分けるため、書き換え予定地点をいったん計画として集める。 */
struct segment {
    uint8_t *base;
    size_t size;
    int prot;
    size_t first, count;
};
struct patch_plan {
    struct segment *segments;
    size_t nsegments, segcap;
    uint8_t **sites;
    struct zcomp_detour *detours;
    size_t nsites, sitecap;
    struct zcomp_scan_stats total;
    int failed;
};

static int32_t jump_distance(uintptr_t next, uintptr_t target)
{
    return (int32_t)((int64_t)target - (int64_t)next);
}

static int near_range(uintptr_t from, uintptr_t to, size_t size)
{
    int64_t distance = (int64_t)to - (int64_t)from;
    return size < INT32_MAX && distance >= INT32_MIN + (int64_t)size &&
           distance <= INT32_MAX - (int64_t)size;
}

static int prepare_detours(struct patch_plan *p, size_t page_size)
{
    p->detours = calloc(p->nsites ? p->nsites : 1, sizeof(*p->detours));
    if (!p->detours)
        return -1;
    size_t reasons[5] = {0};
    for (size_t s = 0; s < p->nsegments; ++s) {
        const struct segment *seg = &p->segments[s];
        if (!seg->count)
            continue;
        uint8_t *targets = calloc(seg->size, 1);
        if (!targets)
            return -1;
        zcomp_detour_targets(seg->base, seg->size, targets);
        size_t count = 0, last_end = 0;
        for (size_t j = 0; j < seg->count; ++j) {
            size_t index = seg->first + j;
            size_t at = (size_t)(p->sites[index] - seg->base);
            struct zcomp_detour *plan = &p->detours[index];
            enum zcomp_detour_result result = zcomp_detour_analyze(
                seg->base, seg->size, at, targets, plan);
            /* 別の採用syscallを飲み込む範囲や、先のdetourとの重複も適用しない。 */
            if (result == ZCOMP_DETOUR_OK && (at < last_end ||
                (j + 1 < seg->count && p->sites[index + 1] < p->sites[index] + plan->length)))
                result = ZCOMP_DETOUR_INSTRUCTION;
            ++reasons[result];
            if (result != ZCOMP_DETOUR_OK) {
                plan->length = 0;
                continue;
            }
            last_end = at + plan->length;
            ++count;
        }
        free(targets);
        if (!count)
            continue;
        if (count > (SIZE_MAX - page_size) / ZCOMP_DETOUR_SLOT)
            return -1;
        size_t bytes = (count * ZCOMP_DETOUR_SLOT + page_size - 1) & ~(page_size - 1);
        uint8_t *slab = NULL;
        /* 近傍の既存写像は絶対に置換しない。到達可能な空きがなければ初期化を中止する。 */
        uintptr_t center = (uintptr_t)seg->base & ~(page_size - 1);
        for (unsigned step = 1; step <= 120 && !slab; ++step) {
            int64_t delta = (int64_t)((step + 1) / 2) * 16 * 1024 * 1024;
            int64_t candidate = (int64_t)center + ((step & 1) ? delta : -delta);
            if (candidate <= 0)
                continue;
            long mapped = zcomp_raw_syscall(SYS_mmap, candidate, bytes,
                PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                -1, 0);
            if (mapped < 0)
                continue;
            if (mapped != candidate || !near_range((uintptr_t)seg->base,
                    (uintptr_t)mapped, bytes + seg->size)) {
                zcomp_raw_syscall(SYS_munmap, mapped, bytes, 0, 0, 0, 0);
                continue;
            }
            slab = (uint8_t *)mapped;
        }
        if (!slab)
            return -1;
        size_t slot = 0;
        for (size_t j = 0; j < seg->count; ++j) {
            size_t index = seg->first + j;
            struct zcomp_detour *plan = &p->detours[index];
            if (!plan->length)
                continue;
            plan->stub = slab + slot++ * ZCOMP_DETOUR_SLOT;
            if (zcomp_detour_emit(plan->stub, p->sites[index], plan,
                                  (uintptr_t)zcomp_detour_entry))
                return -1;
        }
        if (zcomp_raw_syscall(SYS_mprotect, (long)slab, bytes, PROT_READ | PROT_EXEC,
                              0, 0, 0) < 0)
            return -1;
    }
    fprintf(stderr, "zcomp: detour sites=%zu number=%zu special=%zu instruction=%zu branch=%zu\n",
            reasons[0], reasons[1], reasons[2], reasons[3], reasons[4]);
    return 0;
}

static void fatal(const char *message, int status)
{
    /* libcの書き換え後でも使えるよう、strlenやlibcのwriteは使わない。 */
    size_t len = 0;
    while (message[len])
        ++len;
    zcomp_raw_syscall(SYS_write, 2, (long)message, len, 0, 0, 0);
    zcomp_raw_syscall(SYS_exit_group, status, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}

static int grow(void **ptr, size_t *capacity, size_t count, size_t item_size)
{
    if (count < *capacity)
        return 0;
    size_t next = *capacity ? *capacity * 2 : 32;
    /* 倍化と要素サイズの乗算、どちらの桁あふれも失敗として扱う。 */
    if (next < *capacity || next > SIZE_MAX / item_size)
        return -1;
    void *allocation = realloc(*ptr, next * item_size);
    if (!allocation)
        return -1;
    *ptr = allocation;
    *capacity = next;
    return 0;
}

struct collect_context { struct patch_plan *plan; uint8_t *base; };

static int collect_site(size_t offset, enum zcomp_site_kind kind, void *opaque)
{
    struct collect_context *ctx = opaque;
    struct patch_plan *p = ctx->plan;
    /* 包含・曖昧・解読不能な候補は書き換えない。誤った書き換えは命令列を
     * 壊すが、見送った候補はLinux上でそのまま実行されるだけで済むため。 */
    if (kind != ZCOMP_SITE_ACCEPT)
        return 0;
    if (grow((void **)&p->sites, &p->sitecap, p->nsites, sizeof(*p->sites)))
        return -1;
    p->sites[p->nsites++] = ctx->base + offset;
    return 0;
}

static int collect_object(struct dl_phdr_info *info, size_t size, void *opaque)
{
    (void)size;
    struct patch_plan *p = opaque;
    /* このDSO全体を除外する。転送用のsyscallと静的リンクしたデコーダを含み、
     * 書き換えると捕捉が無限に再帰するため。 */
    for (ElfW(Half) i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
        uintptr_t from = info->dlpi_addr + ph->p_vaddr;
        if (ph->p_type == PT_LOAD && (uintptr_t)zcomp_entry >= from &&
            (uintptr_t)zcomp_entry - from < ph->p_memsz)
            return 0;
    }
    /* vDSOも必要時には本物のsyscallを発行するため、通常の実行領域と同じく
     * 走査・書換えする。元の番地を保ち、vvarへの相対参照や既存の関数ポインタを壊さない。 */
    for (ElfW(Half) i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
        if (ph->p_type != PT_LOAD || !(ph->p_flags & PF_X))
            continue;
        /* 読めない実行領域 (execute-only) は走査できない。黙って飛ばすと
         * 捕捉漏れを隠すため、計画全体を失敗にする。 */
        if (!(ph->p_flags & PF_R) ||
            grow((void **)&p->segments, &p->segcap, p->nsegments,
                 sizeof(*p->segments)))
            goto fail;
        struct segment *seg = &p->segments[p->nsegments++];
        *seg = (struct segment){
            .base = (uint8_t *)(info->dlpi_addr + ph->p_vaddr),
            .size = ph->p_memsz,
            /* 書き換え後に元の保護へ戻すため、ELF上の権限を記録しておく。 */
            .prot = PROT_READ | PROT_EXEC |
                    ((ph->p_flags & PF_W) ? PROT_WRITE : 0),
            .first = p->nsites,
        };
        struct collect_context ctx = {p, seg->base};
        struct zcomp_scan_stats stats;
        if (zcomp_scan(seg->base, seg->size, collect_site, &ctx, &stats))
            goto fail;
        seg->count = p->nsites - seg->first;
        p->total.candidates += stats.candidates;
        p->total.accepted += stats.accepted;
        p->total.covered += stats.covered;
        p->total.ambiguous += stats.ambiguous;
        p->total.undecodable += stats.undecodable;
    }
    return 0;
fail:
    p->failed = 1;
    /* 非0でdl_iterate_phdrの列挙を打ち切る。 */
    return 1;
}

static void map_trampoline(size_t page_size)
{
    /* MAP_FIXEDではなくNOREPLACEを使う。既存の0番地マップを黙って潰さない。 */
    long address = zcomp_raw_syscall(SYS_mmap, 0, page_size,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
        -1, 0);
    /* 権限不足は環境の問題なので77 (テストのSKIP) で終える。ネイティブ実行へ
     * フォールバックすると、捕捉していないのに成功したように見えるため。 */
    if (address == -EPERM || address == -EACCES)
        fatal("zcomp: Cannot map address zero (mmap_min_addr or security policy). "
              "Interception was not started; see README for requirements.\n", 77);
    if (address < 0)
        fatal("zcomp: Cannot map the trampoline at address zero.\n", 1);
    /* NOREPLACEを知らない古いカーネルはヒント扱いで別の番地を返す。 */
    if (address != 0) {
        zcomp_raw_syscall(SYS_munmap, address, page_size, 0, 0, 0, 0);
        fatal("zcomp: MAP_FIXED_NOREPLACE did not map the requested address.\n", 1);
    }
    /* 0番地への書き込みはCではNULL参照の未定義動作になるため、アセンブリで行う。 */
    zcomp_fill_trampoline((uintptr_t)address, (uintptr_t)zcomp_entry);
    /* W^Xを保つため、書き込み後に書き込み権限を外す。 */
    if (zcomp_raw_syscall(SYS_mprotect, 0, page_size, PROT_READ | PROT_EXEC,
                         0, 0, 0) < 0)
        fatal("zcomp: Cannot make the trampoline executable.\n", 1);
}

/* LD_PRELOADされたDSOのconstructorは、本体のmainより前に走る。 */
__attribute__((constructor)) static void initialize(void)
{
    const char *trace_setting = getenv("ZCOMP_TRACE");
    zcomp_trace = trace_setting && !strcmp(trace_setting, "1");
    /* 0番地をマップできない環境でも、走査器だけは実ELFで検証できるようにする。 */
    const char *scan_setting = getenv("ZCOMP_SCAN_ONLY");
    const int scan_only = scan_setting && !strcmp(scan_setting, "1");
    const char *detour_setting = getenv("ZCOMP_DETOUR");
    const int detour = detour_setting && !strcmp(detour_setting, "1");
    long page_size = sysconf(_SC_PAGESIZE);
    /* 下のページ境界への丸めはマスク演算なので、2の冪を前提とする。 */
    if (page_size <= 0 || (page_size & (page_size - 1)))
        fatal("zcomp: Unsupported page size.\n", 1);
    zcomp_page_size = (size_t)page_size;
    if (!scan_only) {
        Dl_info self;
        if (!dladdr((void *)zcomp_entry, &self) || !self.dli_fname ||
            !realpath(self.dli_fname, zcomp_preload_path))
            fatal("zcomp: Cannot resolve the DSO path for reinjection after exec.\n", 1);
        /* LD_PRELOADでは区切り文字をエスケープできず、$はローダーが展開する。
         * 読み直せない名前を受け入れると、exec後だけ捕捉が消えるため拒否する。 */
        if (strpbrk(zcomp_preload_path, " :\t\n\r\v\f$"))
            fatal("zcomp: The DSO path contains characters unsupported by LD_PRELOAD.\n", 1);
    }

    struct patch_plan plan = {0};
    dl_iterate_phdr(collect_object, &plan);
    /* 一部だけ書き換えた状態で動かすと結果を解釈できないので、全体を中止する。 */
    if (plan.failed)
        fatal("zcomp: Cannot complete scanning and patch planning for all regions.\n", 1);
    if (detour && !scan_only && prepare_detours(&plan, (size_t)page_size))
        fatal("zcomp: Cannot prepare the experimental syscall detours.\n", 1);
    /* ここはまだ書き換え前なので、libcのfprintfを使ってよい。 */
    fprintf(stderr,
        "zcomp: segments=%zu candidates=%zu accepted=%zu covered=%zu "
        "ambiguous=%zu undecodable=%zu mode=%s\n",
        plan.nsegments, plan.total.candidates, plan.total.accepted,
        plan.total.covered, plan.total.ambiguous, plan.total.undecodable,
        scan_only ? "scan-only" : "zpoline");

    if (!scan_only) {
        zcomp_guard_prepare();
        /* 書き換えより先に用意する。逆順だと書き換え直後のsyscallが0番地の
         * 未マップ領域へ飛ぶ。 */
        map_trampoline((size_t)page_size);
        /* すべての逆アセンブルを終えてから、初めてコードを書き換える。書き換え済み
         * のff d0が次の判定に混ざると、命令境界の判定が変わってしまうため。
         * 前提はconstructor実行時の単一スレッド。並行実行中の書き換えは対象外。 */
        for (size_t i = 0; i < plan.nsegments; ++i) {
            const struct segment *seg = &plan.segments[i];
            if (!seg->count)
                continue;
            /* mprotectはページ単位でしか指定できない。 */
            uintptr_t mask = (uintptr_t)page_size - 1;
            uintptr_t from = (uintptr_t)seg->base & ~mask;
            uintptr_t end = ((uintptr_t)seg->base + seg->size + mask) & ~mask;
            /* 以後libcのsyscallは書き換わり得るため、生のsyscallで呼ぶ。 */
            if (zcomp_raw_syscall(SYS_mprotect, from, end - from,
                                 seg->prot | PROT_WRITE, 0, 0, 0) < 0)
                fatal("zcomp: Cannot make the code region writable.\n", 1);
            for (size_t j = 0; j < seg->count; ++j) {
                /* syscall (0f 05) → call *%rax (ff d0)。同じ2バイトなので
                 * 後続命令の位置は変わらない。volatileで書き込みの省略を防ぐ。 */
                volatile uint8_t *site = plan.sites[seg->first + j];
                const struct zcomp_detour *d = plan.detours ?
                    &plan.detours[seg->first + j] : NULL;
                if (d && d->length) {
                    int32_t distance = jump_distance((uintptr_t)site + 5, (uintptr_t)d->stub);
                    site[0] = 0xe9;
                    for (unsigned k = 0; k < 4; ++k)
                        site[k + 1] = (uint32_t)distance >> (8 * k);
                    for (unsigned k = 5; k < d->length; ++k)
                        site[k] = 0x90;
                } else {
                    site[0] = 0xff;
                    site[1] = 0xd0;
                }
            }
            if (zcomp_raw_syscall(SYS_mprotect, from, end - from,
                                 seg->prot, 0, 0, 0) < 0)
                fatal("zcomp: Cannot restore the code region's permissions.\n", 1);
        }
    }
    free(plan.sites);
    free(plan.segments);
    free(plan.detours);
    if (!scan_only)
        zcomp_guard_start();
}
