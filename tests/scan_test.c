#include "scan.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

struct expected {
    size_t offsets[4];
    enum zcomp_site_kind kinds[4];
    size_t count, seen;
};

static int check_site(size_t offset, enum zcomp_site_kind kind, void *opaque)
{
    struct expected *e = opaque;
    assert(e->seen < e->count);
    assert(offset == e->offsets[e->seen]);
    assert(kind == e->kinds[e->seen]);
    ++e->seen;
    return 0;
}

static void check(const unsigned char *code, size_t size, struct expected e)
{
    struct zcomp_scan_stats stats;
    assert(zcomp_scan(code, size, check_site, &e, &stats) == 0);
    assert(e.seen == e.count);
    assert(stats.candidates == e.count);
    assert(stats.accepted + stats.covered + stats.ambiguous + stats.undecodable
           == stats.candidates);
}

int main(void)
{
    unsigned char code[512];
    memset(code, 0x90, sizeof(code));
    code[300] = 0x0f; code[301] = 0x05;
    check(code, sizeof(code), (struct expected){{300}, {ZCOMP_SITE_ACCEPT}, 1, 0});

    /* 即値中の0f 05を書き換えると命令を壊すため、movabsの偽候補と後続の本物を区別させる。 */
    memset(code, 0x90, sizeof(code));
    const unsigned char immediate[] = {0x48, 0xb8, 0x0f, 0x05, 0, 0, 0, 0, 0, 0,
                                       0x0f, 0x05};
    memcpy(code + 300, immediate, sizeof(immediate));
    check(code, sizeof(code), (struct expected){{302, 310},
          {ZCOMP_SITE_COVERED, ZCOMP_SITE_ACCEPT}, 2, 0});

    /* 変位中にも0f 05が現れるため、即値だけでなく変位の偽候補も除けることを検査する。 */
    memset(code, 0x90, sizeof(code));
    const unsigned char displacement[] = {0x48, 0x8b, 0x80, 0x0f, 0x05, 0, 0};
    memcpy(code + 300, displacement, sizeof(displacement));
    check(code, sizeof(code), (struct expected){{303}, {ZCOMP_SITE_COVERED}, 1, 0});

    /* 多数決で少数側の正しい境界を捨てないよう、mov-al/imm8の2系統が
     * 境界について一致しない候補を採用しないことを検査する。 */
    memset(code, 0xb0, sizeof(code));
    code[300] = 0x0f; code[301] = 0x05;
    check(code, sizeof(code), (struct expected){{300}, {ZCOMP_SITE_AMBIGUOUS}, 1, 0});

    /* 無効な列を途中から読み直して偽の境界を作らないよう、64ビットモードの
     * 無効命令で16開始点すべてを脱落させる。 */
    memset(code, 0x06, sizeof(code));
    code[300] = 0x0f; code[301] = 0x05;
    check(code, sizeof(code), (struct expected){{300}, {ZCOMP_SITE_UNDECODABLE}, 1, 0});

    check(NULL, 0, (struct expected){0});
    const unsigned char edge[] = {0x0f, 0x05, 0x0f};
    check(edge, sizeof(edge), (struct expected){{0}, {ZCOMP_SITE_ACCEPT}, 1, 0});

    /* 領域末尾のデコードで次のページを読まないことを検査するため、
     * 直後のページをアクセス不可にして、渡した長さを守らせる。 */
    long page = sysconf(_SC_PAGESIZE);
    unsigned char *mem = mmap(NULL, page * 2, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(mem != MAP_FAILED);
    assert(mprotect(mem + page, page, PROT_NONE) == 0);
    memset(mem + page - 32, 0x90, 32);
    mem[page - 2] = 0x0f; mem[page - 1] = 0x05;
    check(mem + page - 32, 32,
          (struct expected){{30}, {ZCOMP_SITE_ACCEPT}, 1, 0});
    assert(munmap(mem, page * 2) == 0);
    puts("Scanner: verified 16-stream convergence, embedded bytes, ambiguous boundaries, and region ends");
}
