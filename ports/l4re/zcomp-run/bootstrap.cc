#include "bootstrap.h"
#include "runtime.h"
#include <l4/re/env>
#include <l4/re/util/cap_alloc>
#include <l4/re/util/unique_cap>
#include <l4/sys/task>
#include <l4/sys/vcon.h>
#include <cstdio>

namespace Zcomp {
void drop_startup_capability(char const *name, bool audit)
{
    auto env = L4Re::Env::env();
    auto task = env->task();
    auto source = env->get_cap<void>(name);
    if (!source.is_valid()) return;
    auto present = [&](L4::Cap<void> cap) {
        long result = l4_error(task->cap_valid(cap));
        if (result < 0) fail("Cannot inspect a startup capability", result);
        return result != 0;
    };
    if (!present(source)) return;
    auto unmap = [&](L4::Cap<void> cap) {
        // DELETE_OBJは使わず、自taskの参照だけを捨てる。他taskのサービスを破壊しない。
        long result = l4_error(task->unmap(cap.fpage(L4_CAP_FPAGE_RWS), L4_FP_ALL_SPACES));
        if (result < 0) fail("Cannot drop a startup capability", result);
    };
    auto copy = [&](L4::Cap<void> from, L4::Cap<void> to) {
        long result = l4_error(task->map(task, from.fpage(L4_CAP_FPAGE_R), to.snd_base()));
        if (result < 0) fail("Cannot compare startup capability aliases", result);
    };
    size_t removed = 0;
    {
        auto reference = L4Re::Util::make_unique_cap<void>();
        auto candidate = L4Re::Util::make_unique_cap<void>();
        auto probe = L4Re::Util::make_unique_cap<void>();
        if (!reference.is_valid() || !candidate.is_valid() || !probe.is_valid())
            fail("Cannot allocate slots for startup capability cleanup");
        copy(source, reference.get());
        // 監査時は意図的に複製を一つ残し、元slotだけ消す実装では通らないようにする。
        if (audit) copy(source, probe.get());
        std::vector<L4::Cap<void>> aliases;
        // 初期slot群と標準allocatorの全範囲を調べる。ゲスト開始前なので範囲外へ複製する者はいない。
        // オブジェクトcapは階層的でなく、一つのunmapで別slotの複製まで消えるとは限らない。
        for (long index = 0; index <= L4Re::Util::cap_alloc.last(); ++index) {
            L4::Cap<void> cap(l4_cap_idx_t(index) << L4_CAP_SHIFT);
            if (cap == reference.get() || cap == candidate.get() || !present(cap)) continue;
            // cap_equalはW/Sも比較するため、権利の異なる別名も同じRに揃えて照合する。
            copy(cap, candidate.get());
            long equal = l4_error(task->cap_equal(reference.get(), candidate.get()));
            unmap(candidate.get());
            if (equal < 0) fail("Cannot compare startup capabilities", equal);
            if (equal) aliases.push_back(cap);
        }
        for (auto cap : aliases) unmap(cap);
        for (auto cap : aliases)
            if (present(cap)) fail("A startup capability alias survived cleanup");
        if (present(source) || (audit && present(probe.get())))
            fail("Startup capability cleanup did not remove the original and probe");
        removed = aliases.size();
        // 最後の照合用参照も実slotの不在を検査する。RAIIだけに任せて観測用の権限を残さない。
        unmap(reference.get());
        if (present(reference.get()) || present(candidate.get()))
            fail("A comparison capability survived startup cleanup");
    }
    if (audit) {
        char line[L4_VCON_WRITE_SIZE + 1];
        int length = std::snprintf(line, sizeof(line),
            "[zcomp-bootstrap] dropped=%s aliases=%zu probe=removed\n", name, removed);
        if (length < 0 || size_t(length) >= sizeof(line)) fail("The startup cleanup log is too long");
        l4_vcon_write(env->log().cap(), line, size_t(length));
    }
}
}
