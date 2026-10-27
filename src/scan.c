#include "scan.h"

#include <Zydis/Zydis.h>

/* 0f 05 は即値や変位の一部にも現れるため、バイト列の一致だけでは書き換えない。
 *
 * 256バイトの遡り窓の左端から1バイトずつずらした最大16地点を開始点として、
 * 重なり合う命令列を並行してデコードする。x86の可変長命令は、どこから
 * 読み始めても数命令で同じ境界に収束しやすいため。
 * 無効な列は脱落させ、次のバイトから再開しない (再開すると任意の位置を境界と
 * みなせてしまい、証拠にならない)。多数決もしない (少数派が正しい場合に
 * 誤った書き換えで命令列を壊すため)。生き残ったすべての列が候補を境界とした
 * 場合だけ採用する。手前にバイトがないときに限り、候補自身を開始点にする。
 *
 * これは境界の証拠であって、そのバイトが実行されるコードである証明ではない。
 * 埋め込みデータ、別の入口、敵対的な符号化は原理的に曖昧なまま残る。
 * よって呼び出し側に見せる統計を「網羅率」と呼んではならない。
 */
static enum zcomp_site_kind classify(const ZydisDecoder *decoder,
                                     const uint8_t *code, size_t size, size_t at)
{
    const size_t left = at > ZCOMP_SCAN_WINDOW ? at - ZCOMP_SCAN_WINDOW : 0;
    size_t streams = at - left;
    if (streams > ZCOMP_SCAN_STREAMS)
        streams = ZCOMP_SCAN_STREAMS;
    if (!streams)
        streams = 1;

    unsigned boundary = 0, covered = 0;
    for (size_t seed = 0; seed < streams; ++seed) {
        size_t pos = left + seed;
        while (pos <= at) {
            ZydisDecodedInstruction instruction;
            /* 領域外を読まないよう、デコーダに渡す長さを領域末尾で切る。
             * 次のページが未マップでもフォールトしない。 */
            size_t remaining = size - pos;
            if (remaining > ZYDIS_MAX_INSTRUCTION_LENGTH)
                remaining = ZYDIS_MAX_INSTRUCTION_LENGTH;
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(
                    decoder, NULL, code + pos, remaining, &instruction)))
                break;
            if (pos == at) {
                /* 冗長なプレフィックス付きなど2バイトでないsyscallは、
                 * 2バイトのcallに置き換えると後続命令がずれるので除く。 */
                if (instruction.mnemonic == ZYDIS_MNEMONIC_SYSCALL &&
                    instruction.length == 2)
                    ++boundary;
                break;
            }
            if (instruction.length > at - pos) {
                ++covered;
                break;
            }
            pos += instruction.length;
        }
    }
    if (boundary && covered)
        return ZCOMP_SITE_AMBIGUOUS;
    if (boundary)
        return ZCOMP_SITE_ACCEPT;
    return covered ? ZCOMP_SITE_COVERED : ZCOMP_SITE_UNDECODABLE;
}

int zcomp_scan(const uint8_t *code, size_t size, zcomp_site_fn visit, void *ctx,
               struct zcomp_scan_stats *stats)
{
    ZydisDecoder decoder;
    *stats = (struct zcomp_scan_stats){0};
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64,
                                      ZYDIS_STACK_WIDTH_64)))
        return -1;
    /* 必要なのは長さとニーモニックだけ。オペランドの詳細解析を省いて速くする。 */
    if (!ZYAN_SUCCESS(ZydisDecoderEnableMode(&decoder, ZYDIS_DECODER_MODE_MINIMAL,
                                            ZYAN_TRUE)))
        return -1;
    for (size_t at = 0; at + 1 < size; ++at) {
        if (code[at] != 0x0f || code[at + 1] != 0x05)
            continue;
        enum zcomp_site_kind kind = classify(&decoder, code, size, at);
        ++stats->candidates;
        switch (kind) {
        case ZCOMP_SITE_ACCEPT:      ++stats->accepted; break;
        case ZCOMP_SITE_COVERED:     ++stats->covered; break;
        case ZCOMP_SITE_AMBIGUOUS:   ++stats->ambiguous; break;
        case ZCOMP_SITE_UNDECODABLE: ++stats->undecodable; break;
        }
        /* 採用以外も通知する。テストで分類そのものを検証するため。 */
        if (visit && visit(at, kind, ctx))
            return -1;
    }
    return 0;
}
