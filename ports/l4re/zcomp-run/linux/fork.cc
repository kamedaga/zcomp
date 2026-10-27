#include "../task.h"
#include "../bootstrap.h"
#include "lifecycle.h"
#include <l4/re/env>
#include <l4/re/protocols.h>
#include <l4/sys/ipc.h>
#include <l4/sys/utcb.h>
#include <l4/sys/vcon.h>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstring>

namespace Zcomp {
namespace {
void log_fork(char const *format, ...)
{
    // printfの分割IPCで親子の行が混ざると試験ログを照合できないため、一回の送信にまとめる。
    char line[128];
    static_assert(sizeof(line) <= L4_VCON_WRITE_SIZE, "診断行は一回のVcon送信に収めます。");
    va_list arguments;
    va_start(arguments, format);
    int length = std::vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    if (length > 0)
        l4_vcon_write(L4Re::Env::env()->log().cap(), line,
                      size_t(length) < sizeof(line) ? size_t(length) : sizeof(line) - 1);
}
constexpr uint64_t Clone_settls = 0x80000, Clone_parent_settid = 0x100000;
constexpr uint64_t Clone_child_cleartid = 0x200000, Clone_child_settid = 0x1000000;
constexpr size_t Max_snapshot_regions = ZCOMP_MAX_SEGMENTS + 1;
constexpr size_t Max_snapshot_names = 64;
struct Region_record {
    uintptr_t address;
    size_t size, visible_offset;
    unsigned flags;
    int mapping;
    l4_cap_idx_t dataspace;
};
struct Fd_record {
    bool present, close_on_exec;
    File_object::Kind kind;
    l4_cap_idx_t object, position;
    size_t size;
    uint64_t inode;
};
struct Backing_record { l4_cap_idx_t dataspace; size_t size; bool file; };
struct Mapping_record {
    uintptr_t address;
    size_t size, offset, backing;
    unsigned flags;
    bool prepared;
};
struct Area_record { uintptr_t address; size_t size; };
// ポインタやC++オブジェクトは転送しない。固定幅の値と子側のcap selectorだけを記録する。
struct Fork_snapshot {
    uint64_t magic = 0x5a434f4d50464f55;
    uint32_t pid, parent_pid;
    uintptr_t guest_rsp, guest_fs, clear_child_tid;
    uint64_t signal_mask;
    uint32_t umask;
    bool immutable_files;
    Signal_actions signal_actions;
    Registers registers;
    alignas(16) unsigned char fx[512];
    Loaded_elf main_elf, interpreter;
    size_t area_count = 0;
    Area_record areas[2];
    size_t region_count = 0, name_count = 0;
    size_t backing_count = 0, mapping_count = 0;
    Region_record regions[Max_snapshot_regions];
    Backing_record backings[Max_mappings];
    Mapping_record mappings[Max_mappings];
    Fd_record files[Max_fds]{};
    char names[Max_snapshot_names][256];
};

long native_error(long error, char const *stage = "snapshot")
{
    log_fork("[zcomp-fork] operation=create stage=%s native_error=%ld\n", stage, error);
    if (error == -L4_EPERM || error == -L4_EACCESS) return -EACCES;
    if (error == -L4_ENOMEM || error == -L4_ENOSPC) return -ENOMEM;
    return -EIO;
}

long copy_region(Child_task &child, Process_family &family, Region const &region, int mapping,
                 Fork_snapshot &snapshot)
{
    if (!region.address) return 0; // 0ページは子のnative入口を指す新しいtrampolineで作る。
    if (snapshot.region_count == Max_snapshot_regions) return -ENOMEM;
    Local_dataspace source;
    // PROT_NONEの内容も複製するが、ゲストの保護を一時的に緩めずnative aliasから読む。
    long result = l4_error(L4Re::Env::env()->task()->map(L4Re::Env::env()->task(),
        region.dataspace().fpage(L4_CAP_FPAGE_R), source.cap.get().snd_base()));
    if (result < 0) return result;
    result = source.attach(region.size, L4Re::Rm::F::R);
    if (result < 0) return result;
    auto copy = std::make_unique<Local_dataspace>();
    result = copy->allocate(region.size, family.memory);
    if (result < 0) return result;
    // Dataspace::copy_inの実装にCOWの有無を委ねず、この版では必ず実メモリをコピーする。
    std::memcpy(copy->data, source.data, region.size);
    l4_cap_idx_t slot;
    result = child.add_cap(copy->cap.get(), L4_CAP_FPAGE_RWS, &slot);
    if (result < 0) return result;
    snapshot.regions[snapshot.region_count++] = {region.address, region.size, 0,
                                                region.elf_flags, mapping, slot};
    result = copy->detach();
    if (result < 0) return result;
    child.storage.push_back(std::move(copy));
    return 0;
}

long copy_mappings(Address_space const &space, Child_task &child, Process_family &family, Fork_snapshot &snapshot)
{
    std::vector<Memory_backing const *> copied;
    for (auto const &span : space.mappings.spans) {
        if (snapshot.mapping_count == Max_mappings) return -L4_ENOMEM;
        size_t index = 0;
        while (index < copied.size() && copied[index] != span.backing.get()) ++index;
        if (index == copied.size()) {
            // 分割区間ごとにコピーするとoffsetと実体の共有関係が失われる。実体ごとに一度だけ複製する。
            auto const &backing = *span.backing;
            l4_cap_idx_t slot = L4_INVALID_CAP;
            if (backing.size) {
                Local_dataspace source;
                auto task = L4Re::Env::env()->task();
                long result = l4_error(task->map(task, backing.dataspace().fpage(L4_CAP_FPAGE_R), source.cap.get().snd_base()));
                if (result < 0) return result;
                // slab全体をコピーすると別の割当まで子に混ざる。leaseの開始位置から必要量だけ読む。
                result = source.attach(backing.size, L4Re::Rm::F::R, backing.pool_offset);
                if (result < 0) return result;
                auto copy = std::make_unique<Local_dataspace>();
                result = copy->allocate(backing.size, family.memory);
                if (result < 0) return result;
                std::memcpy(copy->data, source.data, backing.size);
                result = child.add_cap(copy->cap.get(), L4_CAP_FPAGE_RWS, &slot);
                if (result < 0) return result;
                result = copy->detach();
                if (result < 0) return result;
                child.storage.push_back(std::move(copy));
            }
            snapshot.backings[index] = {slot, backing.size, backing.file};
            copied.push_back(&backing);
        }
        snapshot.mappings[snapshot.mapping_count++] = {span.address, span.size, span.offset,
                                                       index, span.flags, span.prepared};
    }
    snapshot.backing_count = copied.size();
    return 0;
}

long copy_files(Thread_state &thread, Child_task &child, Fork_snapshot &snapshot)
{
    auto &process = *thread.process;
    for (size_t fd = 0; fd < Max_fds; ++fd) {
        auto const &entry = thread.files->entries[fd];
        if (!entry.description) continue;
        // 親のcloseで派生capを取り消さないよう、子の終了までは供給元を保持する。
        child.inherited_files.push_back(entry.description);
        auto &description = *entry.description;
        auto &file = *description.object;
        auto &record = snapshot.files[fd];
        record.present = true; record.close_on_exec = entry.close_on_exec; record.kind = file.kind;
        record.size = file.size; record.inode = file.inode;
        auto cap = file.kind == File_object::Kind::Regular ? L4::Cap<void>(file.dataspace)
                                                         : L4::Cap<void>(file.console);
        // 出力権限なしの開いたfdも引き継ぐ。無効capをマップしてEBADFへ変えてはいけない。
        record.object = L4_INVALID_CAP;
        if (cap.is_valid()) {
            long result = child.add_cap(cap, L4_CAP_FPAGE_R, &record.object);
            if (result < 0) return result;
        }
        if (file.kind != File_object::Kind::Regular) continue;
        if (!description.shared_offset) {
            auto shared = std::make_shared<Shared_offset>();
            long result = shared->page.allocate(Page_size, process.family->memory);
            if (result < 0) return result;
            shared->value().offset = description.offset;
            description.shared_offset = std::move(shared);
        }
        long result = child.add_cap(description.shared_offset->page.cap.get(), L4_CAP_FPAGE_RWS, &record.position);
        if (result < 0) return result;
    }
    auto const &names = thread.filesystem->root->file_names;
    if (names.size() > Max_snapshot_names) return -ENOMEM;
    snapshot.name_count = names.size();
    for (size_t i = 0; i < names.size(); ++i) {
        if (names[i].size() >= sizeof(snapshot.names[i])) return -ENOMEM;
        std::memcpy(snapshot.names[i], names[i].c_str(), names[i].size() + 1);
    }
    return 0;
}

}

long clone_process(Thread_state &thread, Registers const &r)
{
    uint64_t flags = r.rax == 57 ? 17 : r.rdi;
    if (flags & 0x100) return clone_shared(thread, r);
    uintptr_t stack = r.rax == 57 ? 0 : r.rsi;
    constexpr uint64_t Supported = 255 | Clone_settls | Clone_parent_settid | Clone_child_cleartid | Clone_child_settid;
    if ((flags & 255) != 0 && (flags & 255) != 17) return -EOPNOTSUPP;
    if (flags & ~Supported) return -EOPNOTSUPP;
    auto &process = *thread.process;
    // snapshot用の全スレッド停止・復帰はまだないので、不整合な実コピーを成功扱いしない。
    if (process.address_space->execution_threads > 1) return -EOPNOTSUPP;
    auto &space = *process.address_space;
    auto memory = L4Re::Env::env()->get_cap<L4Re::Mem_alloc>("linux_process");
    if (!memory.is_valid()) return -EACCES;
    if (process.children.size() >= 8) return -EAGAIN;
    if (stack && (stack < 8 || !space.writable(stack - 8, 8))) return -EFAULT;
    if ((flags & Clone_parent_settid) && !space.writable(r.rdx, sizeof(int))) return -EFAULT;
    if ((flags & Clone_child_settid) && !space.writable(r.r10, sizeof(int))) return -EFAULT;
    if ((flags & Clone_settls) && r.r8 >= 0x0000800000000000ULL) return -EPERM;
    long allocation_error;
    uint32_t pid = allocate_tid(process, &allocation_error);
    if (!pid) return allocation_error;
    if (!child_receiver().is_valid()) return -EAGAIN;
    auto child = std::make_shared<Child_task>();
    child->pid = pid;
    child->clone_child = !(flags & 255);
    long result = child->create(memory);
    if (result < 0) return native_error(result, "objects");
    auto image = std::make_unique<Local_dataspace>();
    constexpr size_t Snapshot_size = (sizeof(Fork_snapshot) + Page_size - 1) & ~(Page_size - 1);
    result = image->allocate(Snapshot_size, memory);
    if (result < 0) return native_error(result);
    auto &snapshot = *new (image->data) Fork_snapshot{};
    snapshot.pid = child->pid; snapshot.parent_pid = process.pid;
    snapshot.guest_rsp = stack ? stack - 8 : thread.execution.guest_rsp;
    snapshot.guest_fs = flags & Clone_settls ? r.r8 : thread.execution.guest_fs;
    snapshot.clear_child_tid = flags & Clone_child_cleartid ? r.r10 : 0;
    snapshot.signal_mask = thread.signal_mask;
    snapshot.umask = thread.filesystem->umask;
    snapshot.immutable_files = thread.filesystem->root->immutable;
    snapshot.signal_actions = *process.signal_actions;
    snapshot.registers = r; snapshot.registers.rax = 0;
    snapshot.registers.rcx = *reinterpret_cast<uint64_t *>(thread.execution.guest_rsp);
    snapshot.registers.r11 = r.flags;
    snapshot.main_elf = space.main_elf;
    snapshot.interpreter = space.interpreter;
    if (space.elf_areas.size() > 2) return -ENOMEM;
    for (auto const &area : space.elf_areas)
        snapshot.areas[snapshot.area_count++] = {area->address, area->size};
    std::memcpy(snapshot.fx, reinterpret_cast<unsigned char const *>(&r) - 512, sizeof(snapshot.fx));
    for (auto const &region : space.regions) {
        result = copy_region(*child, *process.family, *region, -1, snapshot);
        if (result < 0) return native_error(result, "loaded-region");
    }
    result = copy_mappings(space, *child, *process.family, snapshot);
    if (result < 0) return native_error(result, "mmap-backing");
    // CHILD_SETTIDは子のコピーだけを更新する。親と同じ仮想番地でも物理メモリは異なる。
    if (flags & Clone_child_settid) {
        bool written = false;
        for (auto const &record : snapshot.regions) {
            if (record.address > r.r10 || r.r10 - record.address > record.size - sizeof(int)) continue;
            Local_dataspace target;
            result = l4_error(L4Re::Env::env()->task()->map(child->task.get(),
                L4::Cap<L4Re::Dataspace>(record.dataspace).fpage(L4_CAP_FPAGE_RWS), target.cap.get().snd_base()));
            if (result < 0) return native_error(result);
            result = target.attach(record.size, L4Re::Rm::F::RW);
            if (result < 0) return native_error(result);
            std::memcpy(target.data + r.r10 - record.address, &child->pid, sizeof(child->pid));
            written = true; break;
        }
        for (size_t i = 0; !written && i < snapshot.mapping_count; ++i) {
            auto const &record = snapshot.mappings[i];
            if (record.address > r.r10 || record.size < sizeof(int)
                || r.r10 - record.address > record.size - sizeof(int)) continue;
            auto const &backing = snapshot.backings[record.backing];
            Local_dataspace target;
            result = l4_error(L4Re::Env::env()->task()->map(child->task.get(),
                L4::Cap<L4Re::Dataspace>(backing.dataspace).fpage(L4_CAP_FPAGE_RWS), target.cap.get().snd_base()));
            if (result < 0) return native_error(result);
            result = target.attach(backing.size, L4Re::Rm::F::RW);
            if (result < 0) return native_error(result);
            std::memcpy(target.data + record.offset + r.r10 - record.address, &child->pid, sizeof(child->pid));
            written = true;
        }
        if (!written) return -EFAULT;
    }
    result = copy_files(thread, *child, snapshot);
    if (result < 0) return native_error(result);
    result = child->add_named("zcomp_snapshot", image->cap.get(), L4_CAP_FPAGE_R);
    if (result < 0) return native_error(result);
    result = child->add_named("zcomp_family", process.family->ids.cap.get(), L4_CAP_FPAGE_RWS);
    if (result < 0) return native_error(result);
    for (auto cap = L4Re::Env::env()->initial_caps(); cap && cap->flags != ~0UL; ++cap) {
        if (!std::strcmp(cap->name, "zcomp_snapshot") || !std::strcmp(cap->name, "zcomp_family")) continue;
        // 起動時に破棄したcapを再び配らない。名前の除外リストではなく、実際のslotを確認する。
        auto inherited = L4::Cap<void>(cap->cap);
        if (!inherited.is_valid()) continue;
        result = l4_error(L4Re::Env::env()->task()->cap_valid(inherited));
        if (result < 0) return native_error(result);
        if (!result) continue;
        auto rights = !std::strcmp(cap->name, "linux_memory") || !std::strcmp(cap->name, "linux_process")
                      ? L4_CAP_FPAGE_RS : L4_CAP_FPAGE_R;
        result = child->add_named(cap->name, inherited, rights);
        if (result < 0) return native_error(result);
    }
    size_t copied_regions = snapshot.region_count + snapshot.mapping_count;
    result = image->detach();
    if (result < 0) return native_error(result);
    child->storage.push_back(std::move(image));
    process.children.push_back(child);
    register_child(thread.process, child);
    result = child->start(memory);
    timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 5;
    if (result >= 0) while (!child->ready && !child->exited) {
        if (runtime_wait_until(deadline) == ETIMEDOUT) { result = -L4_EIO; break; }
    }
    if (result < 0 || !child->ready) {
        unregister_child(child);
        for (auto i = process.children.begin(); i != process.children.end(); ++i)
            if (*i == child) { process.children.erase(i); break; }
        return result < 0 ? native_error(result, "bootstrap") : -EIO;
    }
    if (flags & Clone_parent_settid)
        std::memcpy(reinterpret_cast<void *>(r.rdx), &child->pid, sizeof(child->pid));
    log_fork("[zcomp-fork] parent=%u child=%u copied_regions=%zu method=eager-copy\n",
                process.pid, child->pid, copied_regions);
    return child->pid;
}

int restore_fork_child()
{
    auto env = L4Re::Env::env();
    Local_dataspace image;
    long result = l4_error(env->task()->map(env->task(), env->get_cap<L4Re::Dataspace>("zcomp_snapshot").fpage(L4_CAP_FPAGE_R), image.cap.get().snd_base()));
    if (result < 0) fail("Cannot receive the fork snapshot", result);
    L4Re::Dataspace::Stats stats{};
    if (image.cap->info(&stats) < 0 || stats.size < sizeof(Fork_snapshot)) fail("Invalid fork snapshot size");
    result = image.attach((stats.size + Page_size - 1) & ~(Page_size - 1), L4Re::Rm::F::R);
    if (result < 0) fail("Cannot map the fork snapshot", result);
    auto const &snapshot = *reinterpret_cast<Fork_snapshot const *>(image.data);
    if (snapshot.magic != 0x5a434f4d50464f55 || snapshot.region_count > Max_snapshot_regions || snapshot.area_count > 2
        || snapshot.mapping_count > Max_mappings || snapshot.backing_count > Max_mappings
        || snapshot.name_count > Max_snapshot_names || snapshot.pid < 2
        || snapshot.pid >= (Page_size / sizeof(uint32_t) - 1) * 32
        || snapshot.parent_pid >= (Page_size / sizeof(uint32_t) - 1) * 32) fail("Invalid fork snapshot metadata");
    Runtime runtime;
    auto &thread = *runtime.main_thread;
    auto &process = *thread.process;
    auto &space = *process.address_space;
    process.pid = thread.tid = snapshot.pid; process.parent_pid = snapshot.parent_pid;
    thread.signal_mask = snapshot.signal_mask;
    thread.filesystem->umask = snapshot.umask;
    *process.signal_actions = snapshot.signal_actions;
    thread.clear_child_tid = snapshot.clear_child_tid;
    space.main_elf = snapshot.main_elf;
    space.interpreter = snapshot.interpreter;
    space.memory = env->get_cap<L4Re::Mem_alloc>("linux_memory");
    process.filesystem->root->capability = env->get_cap<L4Re::Namespace>("linux_files");
    // 親のnative写像やcacheは転送せず、公開元との不変性の約束だけを引き継ぐ。
    process.filesystem->root->immutable = snapshot.immutable_files;
    for (size_t i = 0; i < snapshot.name_count; ++i) {
        if (!std::memchr(snapshot.names[i], 0, sizeof(snapshot.names[i]))) fail("Invalid snapshot file name");
        process.filesystem->root->file_names.emplace_back(snapshot.names[i]);
    }
    process.family = std::make_shared<Process_family>();
    process.family->memory = env->get_cap<L4Re::Mem_alloc>("linux_process");
    result = l4_error(env->task()->map(env->task(), env->get_cap<L4Re::Dataspace>("zcomp_family").fpage(L4_CAP_FPAGE_RWS), process.family->ids.cap.get().snd_base()));
    if (result < 0 || process.family->ids.attach(Page_size, L4Re::Rm::F::RW) < 0) fail("Cannot map family PID state", result);
    for (size_t i = 0; i < snapshot.region_count; ++i) {
        auto const &record = snapshot.regions[i];
        if (!record.address || !record.size || (record.address & (Page_size - 1))
            || (record.size & (Page_size - 1)) || record.address > UINTPTR_MAX - record.size
            || record.mapping != -1 || record.visible_offset
            || (record.flags & ~(PF_R | PF_W | PF_X))
            || ((record.flags & PF_W) && (record.flags & PF_X))) fail("Invalid snapshot region");
        auto region = std::make_unique<Region>(record.address, record.size, record.flags);
        result = region->import(L4::Cap<L4Re::Dataspace>(record.dataspace));
        if (result < 0) fail("Cannot restore a guest region", result);
        space.regions.push_back(std::move(region));
    }
    std::vector<std::shared_ptr<Memory_backing>> backings;
    for (size_t i = 0; i < snapshot.backing_count; ++i) {
        auto const &record = snapshot.backings[i];
        if ((record.size & (Page_size - 1)) || record.size > Mmap_end - Mmap_start
            || (!record.size && !record.file)) fail("Invalid snapshot backing");
        auto backing = std::make_shared<Memory_backing>();
        backing->size = record.size; backing->file = record.file;
        if (record.size) backing->cap = L4Re::Util::Unique_cap<L4Re::Dataspace>(L4::Cap<L4Re::Dataspace>(record.dataspace));
        backings.push_back(std::move(backing));
    }
    if (snapshot.mapping_count && space.mmap_area.reserve() < 0) fail("Cannot reserve the child mmap arena");
    for (size_t i = 0; i < snapshot.area_count; ++i) {
        auto const &record = snapshot.areas[i];
        // 親の選んだ実際の番地を再現する。子で再配置すると再配置済みポインタやTLSを壊す。
        if (space.reserve_elf_area(record.address, record.size) < 0) fail("Cannot restore an ELF reservation");
    }
    uintptr_t previous = 0;
    for (size_t i = 0; i < snapshot.mapping_count; ++i) {
        auto const &record = snapshot.mappings[i];
        if (!record.size || record.address < previous || !space.managed_range(record.address, record.size)
            || record.offset > SIZE_MAX - record.size
            || ((record.address | record.size | record.offset) & (Page_size - 1))
            || record.backing >= backings.size() || (record.flags & ~(PF_R | PF_W | PF_X))
            || ((record.flags & PF_W) && (record.flags & PF_X))
            || ((record.flags & PF_X) && !record.prepared)) fail("Invalid snapshot mapping");
        auto backing = backings[record.backing];
        if (!backing->file && record.offset + record.size > backing->size) fail("Invalid snapshot mapping offset");
        Guest_mapping mapping{record.address, record.size, record.offset, record.flags, backing, record.prepared};
        if (attach_mapping(mapping) < 0) fail("Cannot restore a guest mapping");
        previous = mapping.end();
        space.mappings.spans.push_back(std::move(mapping));
    }
    publish_file_faults(thread);
    for (size_t fd = 0; fd < Max_fds; ++fd) {
        auto const &record = snapshot.files[fd];
        if (!record.present) continue;
        auto file = std::make_shared<File_object>();
        file->kind = record.kind; file->size = record.size; file->inode = record.inode;
        auto description = std::make_shared<File_description>();
        description->object = file;
        if (record.kind == File_object::Kind::Console) file->console = L4::Cap<L4::Vcon>(record.object);
        else {
            file->dataspace = L4::Cap<L4Re::Dataspace>(record.object);
            if (file->size) {
                size_t size = (file->size + Page_size - 1) & ~(Page_size - 1);
                result = env->rm()->attach(&file->data, size,
                                           L4Re::Rm::F::R | L4Re::Rm::F::Search_addr | L4Re::Rm::F::No_eager_map,
                                           file->dataspace);
                if (result < 0) fail("Cannot restore an inherited file", result);
                result = file->dataspace->map_region(0, L4Re::Dataspace::F::R,
                    reinterpret_cast<uintptr_t>(file->data), reinterpret_cast<uintptr_t>(file->data) + size);
                if (result < 0) fail("Cannot map an inherited file", result);
            }
            description->shared_offset = std::make_shared<Shared_offset>();
            description->shared_offset->page.cap = L4Re::Util::Unique_cap<L4Re::Dataspace>(L4::Cap<L4Re::Dataspace>(record.position));
            if (description->shared_offset->page.attach(Page_size, L4Re::Rm::F::RW) < 0) fail("Cannot restore a file position");
        }
        process.files->entries[fd] = {std::move(description), record.close_on_exec};
    }
    prepare_trampoline(space);
    space.regions.back()->publish();
    auto &execution = thread.execution;
    execution.guest_fs = snapshot.guest_fs; execution.guest_rsp = snapshot.guest_rsp;
    if (!space.writable(execution.guest_rsp, sizeof(uint64_t))) fail("Invalid child stack");
    std::memcpy(reinterpret_cast<void *>(execution.guest_rsp), &snapshot.registers.rcx, sizeof(uint64_t));
    auto frame = execution.stack + sizeof(execution.stack) - sizeof(Registers);
    std::memcpy(frame, &snapshot.registers, sizeof(Registers));
    std::memcpy(frame - 512, snapshot.fx, sizeof(snapshot.fx));
    // 復元後のsnapshotは不要。ローカル写像・複製を先に外し、名前付きの受領capも回収する。
    result = image.detach();
    if (result < 0) fail("Cannot detach the fork snapshot", result);
    image.cap.reset();
    drop_startup_capability("zcomp_snapshot");
    auto rom = env->get_cap<void>("rom");
    if (rom.is_valid() && l4_error(env->task()->cap_valid(rom)) != 0)
        fail("The child inherited startup ROM authority");
    log_fork("[zcomp-fork] child=%u fresh-native=yes guest-restored=yes startup-caps=absent\n", process.pid);
    l4_utcb_mr()->mr[0] = 0;
    auto tag = l4_ipc_call(env->parent().cap(), l4_utcb(), l4_msgtag(Fork_ready_protocol, 1, 0, 0), L4_IPC_NEVER);
    if (l4_msgtag_has_error(tag)) fail("Cannot notify the parent of child startup");
    register_thread(thread);
    bind_execution(execution);
    int status = zcomp_resume(&execution);
    unbind_execution();
    finish_runtime();
    status = process.exit_status;
    return status;
}
}
