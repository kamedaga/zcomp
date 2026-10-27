#include "capabilities.h"
#include "runtime.h"
#include <l4/re/env>
#include <l4/re/util/unique_cap>
#include <l4/sys/task>
#include <l4/sys/vcon.h>
#include <cstdarg>
#include <cstdio>

namespace Zcomp {
namespace {
void log_capability(char const *format, ...)
{
    // 一行を一回のIPCで送る。並行起動中に別taskの行が混ざると観測結果を照合できない。
    char line[L4_VCON_WRITE_SIZE + 1];
    va_list arguments;
    va_start(arguments, format);
    int length = std::vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    if (length < 0 || size_t(length) >= sizeof(line)) fail("The capability observation line is too long");
    l4_vcon_write(L4Re::Env::env()->log().cap(), line, size_t(length));
}

void copy_cap(L4::Cap<void> source, L4::Cap<void> destination, unsigned rights)
{
    auto task = L4Re::Env::env()->task();
    long result = l4_error(task->map(task, source.fpage(static_cast<L4_cap_fpage_rights>(rights)),
                                   destination.snd_base()));
    if (result < 0) fail("Cannot derive a capability for observation", result);
}

long compare_caps(L4::Cap<void> first, L4::Cap<void> second)
{
    long result = l4_error(L4Re::Env::env()->task()->cap_equal(first, second));
    if (result < 0) fail("Cannot compare capabilities", result);
    return result;
}

unsigned object_ws_rights(L4::Cap<void> cap)
{
    unsigned rights = L4_CAP_FPAGE_R;
    // 宣言値ではなく、権利を減らした複製との差からW/Sを観測する。Dなど全権利の監査ではない。
    for (unsigned bit : {L4_CAP_FPAGE_W, L4_CAP_FPAGE_S}) {
        auto copy = L4Re::Util::make_unique_cap<void>();
        if (!copy.is_valid()) fail("Cannot allocate a slot for capability observation");
        copy_cap(cap, copy.get(), L4_CAP_FPAGE_RWS & ~bit);
        if (!compare_caps(cap, copy.get())) rights |= bit;
    }
    return rights;
}

void describe_cap(char const *name, l4_cap_idx_t selector, char const *source)
{
    auto cap = L4::Cap<void>(selector);
    long present = cap.is_valid() ? l4_error(L4Re::Env::env()->task()->cap_valid(cap)) : 0;
    if (present < 0) fail("Cannot inspect an initial capability", present);
    // selectorの形式だけでなく、カーネル内の存在も確認する。許可・不許可はここでは判断しない。
    log_capability("[zcomp-cap] name=%s selector=%#lx present=%s source=%s\n",
                   name, selector, present ? "yes" : "no", source);
    if (present)
        log_capability("[zcomp-cap-rights] name=%s rights=%u\n", name, object_ws_rights(cap));
}
}

void describe_initial_capabilities()
{
    auto env = L4Re::Env::env();
    // Env ABIの固定フィールドであり、アプリや試験ケースの許可リストではない。
    describe_cap("task", env->task().cap(), "env");
    describe_cap("main_thread", env->main_thread().cap(), "env");
    describe_cap("rm", env->rm().cap(), "env");
    describe_cap("itas", env->itas().cap(), "env");
    describe_cap("parent", env->parent().cap(), "env");
    describe_cap("mem_alloc", env->mem_alloc().cap(), "env");
    describe_cap("factory", env->factory().cap(), "env");
    describe_cap("scheduler", env->scheduler().cap(), "env");
    describe_cap("log", env->log().cap(), "env");
    describe_cap("dbg_events", env->dbg_events().cap(), "env");
    for (auto entry = env->initial_caps(); entry && entry->flags != ~0UL; ++entry)
        describe_cap(entry->name, entry->cap, "named");
}

void describe_memory_allocators(std::initializer_list<Named_allocator> allocators)
{
    for (auto const &item : allocators) {
        if (!item.cap.is_valid()) continue;
        L4Re::Mem_alloc::Stats stats{};
        long result = item.cap->info(stats);
        if (result < 0) fail("Cannot inspect a memory allocator", result);
        log_capability("[zcomp-cap-memory] name=%s quota=%lu used=%lu\n", item.name,
                       static_cast<unsigned long>(stats.quota), static_cast<unsigned long>(stats.quota_used));
        for (auto const &other : allocators) {
            if (&other == &item) break;
            if (!other.cap.is_valid()) continue;
            auto a = L4Re::Util::make_unique_cap<void>(), b = L4Re::Util::make_unique_cap<void>();
            if (!a.is_valid() || !b.is_valid()) fail("Cannot allocate slots for allocator observation");
            // 異なるW/Sの同一オブジェクトを別allocatorと誤認しないよう、同じRへ揃えて比較する。
            copy_cap(item.cap, a.get(), L4_CAP_FPAGE_R);
            copy_cap(other.cap, b.get(), L4_CAP_FPAGE_R);
            log_capability("[zcomp-cap-alias] first=%s second=%s same=%s\n",
                           other.name, item.name, compare_caps(a.get(), b.get()) ? "yes" : "no");
        }
    }
}

}
