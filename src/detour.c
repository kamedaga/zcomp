#include "detour.h"

#include <limits.h>
#include <string.h>
#include <sys/syscall.h>
#include <Zydis/Zydis.h>

static int ordinary(ZydisMnemonic mnemonic)
{
    /* このPoCは位置依存・メモリ参照・制御移動を移設しない。
     * 認識できない命令を、そのままコピーして動いたことにしないため。 */
    switch (mnemonic) {
    case ZYDIS_MNEMONIC_MOV:
    case ZYDIS_MNEMONIC_MOVZX:
    case ZYDIS_MNEMONIC_MOVSX:
    case ZYDIS_MNEMONIC_CMP:
    case ZYDIS_MNEMONIC_TEST:
    case ZYDIS_MNEMONIC_XOR:
    case ZYDIS_MNEMONIC_AND:
    case ZYDIS_MNEMONIC_OR:
    case ZYDIS_MNEMONIC_ADD:
    case ZYDIS_MNEMONIC_SUB:
        return 1;
    default:
        return 0;
    }
}

static int register_only(const ZydisDecodedInstruction *ins,
                          const ZydisDecodedOperand *ops)
{
    if (!ordinary(ins->mnemonic))
        return 0;
    for (unsigned i = 0; i < ins->operand_count; ++i) {
        if (ops[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            if (ops[i].imm.is_relative)
                return 0;
        } else if (ops[i].type == ZYDIS_OPERAND_TYPE_REGISTER) {
            ZydisRegister reg = ZydisRegisterGetLargestEnclosing(
                ZYDIS_MACHINE_MODE_LONG_64, ops[i].reg.value);
            if ((reg < ZYDIS_REGISTER_RAX || reg > ZYDIS_REGISTER_R15) &&
                ops[i].reg.value != ZYDIS_REGISTER_RFLAGS &&
                ops[i].reg.value != ZYDIS_REGISTER_EFLAGS)
                return 0;
            if (reg == ZYDIS_REGISTER_RSP)
                return 0;
        } else {
            return 0;
        }
    }
    return 1;
}

static int number(const ZydisDecoder *decoder, const uint8_t *code, size_t at,
                   unsigned *nr)
{
    size_t left = at > 32 ? at - 32 : 0;
    int found = 0;
    for (size_t start = left; start + 5 <= at; ++start) {
        if (code[start] != 0xb8)
            continue;
        unsigned value;
        memcpy(&value, code + start + 1, sizeof(value));
        size_t pos = start + 5;
        while (pos < at) {
            ZydisDecodedInstruction ins;
            ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, code + pos,
                    at - pos, &ins, ops)) || !register_only(&ins, ops))
                break;
            int overwritten = 0;
            for (unsigned i = 0; i < ins.operand_count; ++i)
                if (ops[i].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    (ops[i].actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) &&
                    ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64,
                        ops[i].reg.value) == ZYDIS_REGISTER_RAX)
                    overwritten = 1;
            if (overwritten)
                break;
            pos += ins.length;
        }
        if (pos == at) {
            if (found && *nr != value)
                return 0;
            *nr = value;
            found = 1;
        }
    }
    return found;
}

void zcomp_detour_targets(const uint8_t *code, size_t size, uint8_t *targets)
{
    /* 命令境界を仮定せず、直接分岐らしい全符号化を保守的に調べる。
     * 即値内の一致で見送りが増えてもよい。間接分岐の別入口までの証明ではない。 */
    for (size_t i = 0; i < size; ++i) {
        size_t bytes = 0;
        int64_t displacement = 0;
        if ((code[i] == 0xe8 || code[i] == 0xe9) && size - i >= 5) {
            int32_t value;
            memcpy(&value, code + i + 1, sizeof(value));
            displacement = value;
            bytes = 5;
        } else if ((code[i] == 0xeb || (code[i] >= 0x70 && code[i] <= 0x7f) ||
                    (code[i] >= 0xe0 && code[i] <= 0xe3)) && size - i >= 2) {
            displacement = (int8_t)code[i + 1];
            bytes = 2;
        } else if (code[i] == 0x0f && size - i >= 6 &&
                   code[i + 1] >= 0x80 && code[i + 1] <= 0x8f) {
            int32_t value;
            memcpy(&value, code + i + 2, sizeof(value));
            displacement = value;
            bytes = 6;
        }
        int64_t target = (int64_t)i + bytes + displacement;
        if (bytes && target >= 0 && (uint64_t)target < size)
            targets[target] = 1;
    }
}

enum zcomp_detour_result zcomp_detour_analyze(const uint8_t *code, size_t size,
                                             size_t at, const uint8_t *targets,
                                             struct zcomp_detour *out)
{
    *out = (struct zcomp_detour){0};
    ZydisDecoder decoder;
    if (at > size || size - at < 2 || code[at] != 0x0f || code[at + 1] != 0x05 ||
        !ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64,
                                      ZYDIS_STACK_WIDTH_64)) ||
        !number(&decoder, code, at, &out->nr))
        return ZCOMP_DETOUR_NUMBER;
    /* 子のstack切替とsignal frameからの復帰は、通常のC転送契約と異なる。
     * 番号を静的に確認できる地点だけに限定し、既存の専用入口を維持する。 */
    if (out->nr == SYS_clone || out->nr == SYS_clone3 ||
        out->nr == SYS_vfork || out->nr == SYS_rt_sigreturn)
        return ZCOMP_DETOUR_SPECIAL;
    size_t pos = at + 2;
    while (pos - at < 5) {
        ZydisDecodedInstruction ins;
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        if (pos >= size || !ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder,
                code + pos, size - pos, &ins, ops)) || !register_only(&ins, ops))
            return ZCOMP_DETOUR_INSTRUCTION;
        pos += ins.length;
    }
    for (size_t i = at + 1; i < pos; ++i)
        if (targets[i])
            return ZCOMP_DETOUR_BRANCH;
    out->length = (unsigned)(pos - at);
    return ZCOMP_DETOUR_OK;
}

static int relative(uint8_t *destination, uintptr_t next, uintptr_t target)
{
    int64_t distance = (int64_t)target - (int64_t)next;
    if (distance < INT32_MIN || distance > INT32_MAX)
        return -1;
    int32_t value = (int32_t)distance;
    memcpy(destination, &value, sizeof(value));
    return 0;
}

int zcomp_detour_emit(uint8_t *stub, const uint8_t *site,
                      const struct zcomp_detour *plan, uintptr_t entry)
{
    /* rcxは元のsyscall自身が上書きする。入口ではdescriptorを渡し、
     * 保存後に本来のsite+2へ直す。他のレジスタとフラグには触れない。 */
    memset(stub, 0xcc, ZCOMP_DETOUR_SLOT);
    stub[0] = 0x48;
    stub[1] = 0xb9;
    uintptr_t descriptor = (uintptr_t)(stub + 24);
    memcpy(stub + 2, &descriptor, sizeof(descriptor));
    const uint8_t jump[] = {0xff, 0x25, 0, 0, 0, 0};
    memcpy(stub + 10, jump, sizeof(jump));
    memcpy(stub + 16, &entry, sizeof(entry));
    uintptr_t original_next = (uintptr_t)(site + 2);
    uintptr_t epilogue = (uintptr_t)(stub + 48);
    memcpy(stub + 24, &original_next, sizeof(original_next));
    memcpy(stub + 32, &epilogue, sizeof(epilogue));
    uint64_t nr = plan->nr;
    memcpy(stub + 40, &nr, sizeof(nr));
    /* rspを戻す前に保存したepilogueへ跳ぶ。先にrspを戻すと、signal配送が
     * red zoneより下の一時的な復帰先を上書きする隙間が生じるため。 */
    const uint8_t restore[] = {0x48, 0x8d, 0xa4, 0x24, 0x90, 0, 0, 0};
    memcpy(stub + 48, restore, sizeof(restore));
    memcpy(stub + 56, site + 2, plan->length - 2);
    size_t end = 56 + plan->length - 2;
    stub[end] = 0xe9;
    if (relative(stub + end + 1, (uintptr_t)(stub + end + 5),
                 (uintptr_t)(site + plan->length)))
        return -1;
    return 0;
}
