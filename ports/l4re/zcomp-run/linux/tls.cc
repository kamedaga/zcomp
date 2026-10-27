#include "../runtime.h"
#include <l4/sys/segment.h>
#include <l4/sys/utcb.h>
#include <pthread-l4.h>
#include <cerrno>
#include <cstring>

namespace Zcomp {
namespace {
// nativeライブラリの先頭slotと競合しないよう、入口は後半2個を専有する。
constexpr unsigned Gdt_first = 2;

uint64_t tls_descriptor(uintptr_t base)
{
    return 0x00cff2000000ffffULL | ((base & 0xffff) << 16)
        | (((base >> 16) & 0xff) << 32) | (((base >> 24) & 0xff) << 56);
}

long set_guest_fs(Execution_context &context, uintptr_t base)
{
    uint16_t selector = 0;
    if (context.native_fs_selector && base <= UINT32_MAX) {
        uint64_t descriptor = tls_descriptor(base);
        long result = fiasco_gdt_set(L4_INVALID_CAP, &descriptor, sizeof(descriptor),
                                    Gdt_first + 1, l4_utcb());
        if (result < 0) return -EIO;
        selector = static_cast<uint16_t>(result);
    }
    // 4 GiB以上の基点も受理し、その場合だけ従来の64-bit APIへ戻す。
    // 登録失敗時はguestの論理値も変えず、古いTLSで安全に復帰できるようにする。
    context.guest_fs = base;
    context.guest_fs_selector = selector;
    return 0;
}
}

void bind_execution(Execution_context &context)
{
    auto utcb = l4_utcb();
    __asm__ volatile("mov %%fs:0,%0; mov %%fs,%1"
                     : "=r"(context.native_fs), "=r"(context.original_fs_selector));
    context.native_fs_selector = context.guest_fs_selector = 0;
    // 非ゼロselectorのnative TLSは既存GDTの利用者とみなし、登録を上書きしない。
    if (!context.original_fs_selector && context.native_fs <= UINT32_MAX) {
        uint64_t descriptors[] = {tls_descriptor(context.native_fs), tls_descriptor(0)};
        long selector = fiasco_gdt_set(L4_INVALID_CAP, descriptors, sizeof(descriptors), Gdt_first, utcb);
        if (selector >= 0) {
            context.native_fs_selector = static_cast<uint16_t>(selector);
            if (set_guest_fs(context, context.guest_fs) < 0)
                context.native_fs_selector = context.guest_fs_selector = 0;
        }
    }
    context.anchor[0] = reinterpret_cast<uintptr_t>(utcb);
    context.anchor[1] = reinterpret_cast<uintptr_t>(&context);
    long result = fiasco_amd64_set_segment_base(L4_INVALID_CAP, L4_AMD64_SEGMENT_GS,
        reinterpret_cast<uintptr_t>(context.anchor), utcb);
    if (result < 0) fail("Cannot bind the per-thread syscall entry", result);
    // 初期化途中のworkerも生成元から見えるため、UTCBとGSの準備後にだけ操作先を公開する。
    __atomic_store_n(&context.thread->native_thread, pthread_l4_cap(pthread_self()), __ATOMIC_RELEASE);
}

void unbind_execution()
{
    auto utcb = l4_utcb();
    uintptr_t pointer;
    __asm__ volatile("mov %%gs:8,%0" : "=r"(pointer));
    auto &context = *reinterpret_cast<Execution_context *>(pointer);
    // selectorを0へ戻すとFS基点も消える。libpthreadへ戻る前に元のnative TLSを復元する。
    __asm__ volatile("mov %w0,%%fs" :: "r"(context.original_fs_selector) : "memory");
    if (!context.original_fs_selector
        && fiasco_amd64_set_fs(L4_INVALID_CAP, context.native_fs, utcb) < 0)
        __builtin_trap();
    // Fiasco amd64の標準GS基点はMR領域直後のutcb_addr。Thread_stateを破棄する前に戻す。
    auto native_anchor = reinterpret_cast<uintptr_t *>(utcb) + L4_UTCB_GENERIC_DATA_SIZE;
    if (*native_anchor != reinterpret_cast<uintptr_t>(utcb)) fail("Invalid native UTCB anchor");
    long result = fiasco_amd64_set_segment_base(L4_INVALID_CAP, L4_AMD64_SEGMENT_GS,
        reinterpret_cast<uintptr_t>(native_anchor), utcb);
    if (result < 0) fail("Cannot restore the native UTCB anchor", result);
}

extern "C" long zcomp_set_fs(uintptr_t base)
{
    // UTCBはGSから取得できる。FSがゲストを指す間にEnvやlibcを経由してはならない。
    // selectorの高速経路を使えない基点でも、Linuxの64-bit TLSを切り捨てない。
    return fiasco_amd64_set_fs(L4_INVALID_CAP, base, l4_utcb());
}

long arch_prctl(Thread_state &thread, Registers const &r)
{
    auto &space = *thread.process->address_space;
    auto &guest_fs = thread.execution.guest_fs;
    constexpr uint64_t Arch_set_fs = 0x1002;
    constexpr uint64_t Arch_get_fs = 0x1003;
    if (r.rdi == Arch_set_fs) {
        // 未写像の基点もLinuxと同様に設定できるが、カーネル側のアドレスは受理しない。
        if (r.rsi >= 0x0000800000000000ULL)
            return -EPERM;
        // C++ shimの実行途中ではFSを変更せず、アセンブリの復帰経路で適用する。
        return set_guest_fs(thread.execution, r.rsi);
    }
    if (r.rdi == Arch_get_fs) {
        if (!space.writable(r.rsi, sizeof(guest_fs)))
            return -EFAULT;
        std::memcpy(reinterpret_cast<void *>(r.rsi), &guest_fs, sizeof(guest_fs));
        return 0;
    }
    // GSはUTCBとスレッド別入口用。ゲストのGS ABIを受理するとnative IPCまで壊れてしまう。
    return -EOPNOTSUPP;
}
}
