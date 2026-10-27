#ifndef ZCOMP_SCAN_H
#define ZCOMP_SCAN_H

#include <stddef.h>
#include <stdint.h>

/* 開始点の数と遡る距離。x86命令は最長15バイトなので、256バイトあれば
 * 通常は開始点のずれが候補より手前で同じ境界に収束する。 */
enum { ZCOMP_SCAN_STREAMS = 16, ZCOMP_SCAN_WINDOW = 256 };

/* 採用しない理由を分けて数え、ヒューリスティックの効き方を評価できるようにする。 */
enum zcomp_site_kind {
    ZCOMP_SITE_ACCEPT,
    ZCOMP_SITE_COVERED,       /* 生き残った列では、候補が他の命令の内部にある。 */
    ZCOMP_SITE_AMBIGUOUS,     /* 生き残った列の間で、境界の判断が分かれる。 */
    ZCOMP_SITE_UNDECODABLE,   /* 候補まで生き残った列がない。 */
};

struct zcomp_scan_stats {
    size_t candidates;
    size_t accepted;
    size_t covered;
    size_t ambiguous;
    size_t undecodable;
};

/* 生の 0f 05 候補ごとに呼ばれる。非0を返すと走査を中止する。
 * 判定は後続の候補で前方の命令を読み直すため、走査中にバッファを書き換えてはならない。 */
typedef int (*zcomp_site_fn)(size_t offset, enum zcomp_site_kind kind, void *ctx);
int zcomp_scan(const uint8_t *code, size_t size, zcomp_site_fn visit, void *ctx,
               struct zcomp_scan_stats *stats);

#endif
