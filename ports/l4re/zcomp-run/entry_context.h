#pragma once

// アセンブリとC++で配置を共有し、片側だけの変更による保存領域の破壊を検出する。
#define ZCOMP_CTX_NATIVE_RSP 0
#define ZCOMP_CTX_NATIVE_FS 8
#define ZCOMP_CTX_GUEST_RSP 16
#define ZCOMP_CTX_GUEST_FS 24
#define ZCOMP_CTX_SAVED_RAX 32
#define ZCOMP_CTX_THREAD 40
#define ZCOMP_CTX_NATIVE_FX 48
#define ZCOMP_CTX_STACK 560
#define ZCOMP_CTX_STACK_END 66096
#define ZCOMP_ANCHOR_CONTEXT 8
#define ZCOMP_ANCHOR_RAX 16
#define ZCOMP_ANCHOR_RSP 24
#define ZCOMP_ANCHOR_PID 32
#define ZCOMP_ANCHOR_CACHED_CALLS 40
#define ZCOMP_CTX_NATIVE_FS_SELECTOR 66144
#define ZCOMP_CTX_GUEST_FS_SELECTOR 66146

#ifndef __ASSEMBLER__
#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace Zcomp {
struct Thread_state;

struct alignas(16) Execution_context {
    uintptr_t native_rsp = 0;
    uintptr_t native_fs = 0;
    uintptr_t guest_rsp = 0;
    uintptr_t guest_fs = 0;
    uint64_t saved_rax = 0;
    Thread_state *thread = nullptr;
    alignas(16) unsigned char native_fx[512]{};
    alignas(16) unsigned char stack[65536]{};
    // GS:0のUTCB取得ABIを保ちつつ、libpthread所有のUTCB.userを変更せず入口を選ぶ。
    // PID=0は通常経路への復帰要求。fork先には親の入口をコピーせず、新PIDで初期化する。
    uintptr_t anchor[6]{};
    // GDTの登録はnative Thread固有。fork先や共有VMのworkerへ親の値をコピーしない。
    uint16_t native_fs_selector = 0;
    uint16_t guest_fs_selector = 0;
    uint16_t original_fs_selector = 0;
};

static_assert(std::is_standard_layout_v<Execution_context>, "入口の状態は固定配置である必要があります。");
#define ZCOMP_CHECK_CONTEXT(member, offset) \
    static_assert(offsetof(Execution_context, member) == offset, "入口の保存位置がアセンブリと一致する必要があります。")
ZCOMP_CHECK_CONTEXT(native_rsp, ZCOMP_CTX_NATIVE_RSP);
ZCOMP_CHECK_CONTEXT(native_fs, ZCOMP_CTX_NATIVE_FS);
ZCOMP_CHECK_CONTEXT(guest_rsp, ZCOMP_CTX_GUEST_RSP);
ZCOMP_CHECK_CONTEXT(guest_fs, ZCOMP_CTX_GUEST_FS);
ZCOMP_CHECK_CONTEXT(saved_rax, ZCOMP_CTX_SAVED_RAX);
ZCOMP_CHECK_CONTEXT(thread, ZCOMP_CTX_THREAD);
ZCOMP_CHECK_CONTEXT(native_fx, ZCOMP_CTX_NATIVE_FX);
ZCOMP_CHECK_CONTEXT(stack, ZCOMP_CTX_STACK);
ZCOMP_CHECK_CONTEXT(native_fs_selector, ZCOMP_CTX_NATIVE_FS_SELECTOR);
ZCOMP_CHECK_CONTEXT(guest_fs_selector, ZCOMP_CTX_GUEST_FS_SELECTOR);
#undef ZCOMP_CHECK_CONTEXT
static_assert(offsetof(Execution_context, anchor) == ZCOMP_CTX_STACK_END, "入口のスタック終端と一致する必要があります。");
static_assert(ZCOMP_ANCHOR_PID == 4 * sizeof(uintptr_t)
              && ZCOMP_ANCHOR_CACHED_CALLS == 5 * sizeof(uintptr_t),
              "キャッシュのGS相対位置がアセンブリと一致する必要があります。");
}
#endif
