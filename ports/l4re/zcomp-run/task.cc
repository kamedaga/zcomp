#include "task.h"
#include "linux/lifecycle.h"
#include <l4/re/env>
#include <l4/sys/kip.h>
#include <l4/sys/scheduler>
#include <l4/sys/task>
#include <cerrno>
#include <cstring>

namespace Zcomp {
// L4Re固有auxv。l4/util/elf.h全体はlibcのelf.hと型・マクロが重複するため併用しない。
constexpr uintptr_t Native_aux_env = 0xf1, Native_aux_kip = 0xf2;
Local_dataspace::~Local_dataspace() { detach(); }

long Local_dataspace::attach(size_t bytes, L4Re::Rm::Flags flags, size_t offset)
{
    size = bytes;
    long result = L4Re::Env::env()->rm()->attach(&data, size,
        flags | L4Re::Rm::F::Search_addr | L4Re::Rm::F::No_eager_map,
        L4::Ipc::make_cap(cap.get(), flags & L4Re::Rm::F::W ? L4_CAP_FPAGE_RW : L4_CAP_FPAGE_R), offset);
    if (result < 0) return result;
    return cap->map_region(offset, L4Re::Dataspace::Flags(flags.raw & L4Re::Rm::F::RWX),
                          reinterpret_cast<uintptr_t>(data), reinterpret_cast<uintptr_t>(data) + size);
}

long Local_dataspace::allocate(size_t bytes, L4::Cap<L4Re::Mem_alloc> allocator)
{
    if (!cap.is_valid()) return -ENOMEM;
    long result = allocator->alloc(bytes, cap.get());
    if (result < 0) return result;
    result = cap->allocate(0, bytes);
    if (result < 0) return result;
    result = attach(bytes, L4Re::Rm::F::RW);
    if (result >= 0) std::memset(data, 0, bytes);
    return result;
}

long Local_dataspace::detach()
{
    if (!data) return 0;
    long result = L4Re::Env::env()->rm()->detach(data, nullptr);
    if (result >= 0) data = nullptr;
    return result;
}

void Child_task::stop()
{
    // 失敗途中のtaskも対象にする。作成前の空slotへのunmapは無害。
    thread.reset();
    task.reset();
    parent.reset();
    rm.reset();
    storage.clear();
    inherited_files.clear();
}
Child_task::~Child_task() { stop(); }

long Child_task::map_cap(L4::Cap<void> source, l4_cap_idx_t destination, L4_cap_fpage_rights rights)
{
    return l4_error(task->map(L4Re::Env::env()->task(), source.fpage(rights),
                            L4::Cap<void>(destination).snd_base()));
}

long Child_task::add_cap(L4::Cap<void> source, L4_cap_fpage_rights rights, l4_cap_idx_t *destination)
{
    *destination = next_cap;
    next_cap += L4_CAP_OFFSET;
    return map_cap(source, *destination, rights);
}

long Child_task::add_named(char const *name, L4::Cap<void> source, L4_cap_fpage_rights rights)
{
    l4_cap_idx_t slot;
    long result = add_cap(source, rights, &slot);
    if (result >= 0) named_caps.emplace_back(name, slot);
    return result;
}

long Child_task::create(L4::Cap<L4Re::Mem_alloc> memory)
{
    if (!task.is_valid() || !thread.is_valid() || !rm.is_valid() || !parent.is_valid()) return -ENOMEM;
    auto env = L4Re::Env::env();
    // RMの匿名ページも子の資源枠に課金する。親のstartup allocatorに逃がさない。
    long result = l4_error(L4::cap_cast<L4::Factory>(memory)->create(rm.get()));
    if (result < 0) return result;
    l4_fpage_t utcbs = l4_fpage(0xb3000000, L4_PAGESHIFT, 0);
    result = l4_error(env->factory()->create_task(task.get(), &utcbs));
    if (result < 0) return result;
    result = l4_error(env->factory()->create(thread.get()));
    if (result < 0) return result;
    return l4_error(env->factory()->create_gate(parent.get(), child_receiver(), uintptr_t(pid) << 2));
}

long Child_task::start(L4::Cap<L4Re::Mem_alloc> memory)
{
    auto env = L4Re::Env::env();
    // 親の稼働中の.data/TLSを読まず、公開済みのnative ELFから新規初期化する。
    Local_dataspace binary;
    auto native_elf = env->get_cap<L4Re::Dataspace>("zcomp_binary");
    if (!native_elf.is_valid()) return -EACCES;
    long result = l4_error(env->task()->map(env->task(), native_elf.fpage(L4_CAP_FPAGE_R),
                                          binary.cap.get().snd_base()));
    if (result < 0) return result;
    L4Re::Dataspace::Stats stats{};
    result = binary.cap->info(&stats);
    if (result < 0) return result;
    if (stats.size < sizeof(Elf64_Ehdr) || stats.size > 32 * 1024 * 1024) return -ENOEXEC;
    result = binary.attach((stats.size + Page_size - 1) & ~(Page_size - 1), L4Re::Rm::F::R);
    if (result < 0) return result;
    Elf64_Ehdr header;
    std::memcpy(&header, binary.data, sizeof(header));
    if (std::memcmp(header.e_ident, ELFMAG, SELFMAG) || header.e_type != ET_EXEC
        || header.e_machine != EM_X86_64 || header.e_phentsize != sizeof(Elf64_Phdr)
        || header.e_phnum > 32 || header.e_phoff > stats.size
        || header.e_phnum * sizeof(Elf64_Phdr) > stats.size - header.e_phoff) return -ENOEXEC;
    for (unsigned i = 0; i < header.e_phnum; ++i) {
        Elf64_Phdr p;
        std::memcpy(&p, binary.data + header.e_phoff + i * sizeof(p), sizeof(p));
        if (p.p_type == PT_INTERP || p.p_type == PT_DYNAMIC) return -ENOEXEC;
        if (p.p_type != PT_LOAD) continue;
        if (p.p_filesz > p.p_memsz || p.p_offset > stats.size || p.p_filesz > stats.size - p.p_offset
            || p.p_memsz > 32 * 1024 * 1024 || p.p_vaddr > UINT64_MAX - p.p_memsz - Page_size) return -ENOEXEC;
        uintptr_t address = p.p_vaddr & ~(Page_size - 1);
        size_t size = ((p.p_vaddr + p.p_memsz + Page_size - 1) & ~(Page_size - 1)) - address;
        auto segment = std::make_unique<Local_dataspace>();
        result = segment->allocate(size, memory);
        if (result < 0) return result;
        std::memcpy(segment->data + p.p_vaddr - address, binary.data + p.p_offset, p.p_filesz);
        L4Re::Rm::Flags flags = L4Re::Rm::F::No_eager_map;
        if (p.p_flags & PF_R) flags |= L4Re::Rm::F::R;
        if (p.p_flags & PF_W) flags |= L4Re::Rm::F::W;
        if (p.p_flags & PF_X) flags |= L4Re::Rm::F::X;
        // 外部RMへ暗黙変換で渡すとRのみになるため、書込み可能segmentではWも明示する。
        result = rm->attach(&address, size, flags,
            L4::Ipc::make_cap(segment->cap.get(), p.p_flags & PF_W ? L4_CAP_FPAGE_RW : L4_CAP_FPAGE_R));
        if (result < 0) return result;
        result = segment->detach();
        if (result < 0) return result;
        storage.push_back(std::move(segment));
    }

    // 子に親のtask/thread/UTCBを渡さない。標準slotには子自身のオブジェクトを置く。
    for (auto mapping : {std::pair<L4::Cap<void>, l4_cap_idx_t>{task.get(), L4RE_THIS_TASK_CAP},
                         {thread.get(), 0x3000}, {rm.get(), 0x10000}}) {
        result = map_cap(mapping.first, mapping.second, L4_CAP_FPAGE_RWS);
        if (result < 0) return result;
    }
    // 子にgateのbind権限を与えると、親への通知先を書き換えられてしまう。
    result = map_cap(parent.get(), 0x13000, L4_CAP_FPAGE_R);
    if (result < 0) return result;
    for (auto mapping : {std::pair<L4::Cap<void>, l4_cap_idx_t>{env->factory(), 0x2000},
                         {env->scheduler(), 0x7000}, {memory, 0x11000}, {env->log(), 0x5000}}) {
        auto rights = mapping.second == 0x2000 ? L4_CAP_FPAGE_RWS
                    : mapping.second == 0x5000 ? L4_CAP_FPAGE_R : L4_CAP_FPAGE_RS;
        result = map_cap(mapping.first, mapping.second, rights);
        if (result < 0) return result;
    }
    uintptr_t kip = reinterpret_cast<uintptr_t>(l4re_kip());
    result = l4_error(task->map(env->task(), l4_fpage(kip, L4_PAGESHIFT, L4_FPAGE_RX), kip));
    if (result < 0) return result;
    l4_addr_t reserved = 0xb3000000;
    result = rm->reserve_area(&reserved, Page_size, L4Re::Rm::F::Kernel);
    if (result < 0) return result;
    reserved = kip;
    result = rm->reserve_area(&reserved, Page_size, L4Re::Rm::F::Kernel);
    if (result < 0) return result;

    auto stack = std::make_unique<Local_dataspace>();
    result = stack->allocate(65536, memory);
    if (result < 0) return result;
    constexpr uintptr_t Native_stack = 0xb2000000;
    size_t cursor = stack->size;
    auto push = [&](void const *data, size_t bytes, size_t alignment) {
        cursor = (cursor - bytes) & ~(alignment - 1);
        std::memcpy(stack->data + cursor, data, bytes);
        return Native_stack + cursor;
    };
    char const arg0[] = "zcomp-run", arg1[] = "--fork-child";
    uintptr_t a0 = push(arg0, sizeof(arg0), 1), a1 = push(arg1, sizeof(arg1), 1);
    named_caps.emplace_back();
    auto caps = push(named_caps.data(), named_caps.size() * sizeof(named_caps[0]), 8);
    l4re_env_t initial{};
    initial.parent = 0x13000; initial.rm = 0x10000; initial.mem_alloc = 0x11000;
    initial.log = 0x5000; initial.main_thread = 0x3000; initial.factory = 0x2000;
    initial.scheduler = 0x7000; initial.itas = L4_INVALID_CAP; initial.dbg_events = L4_INVALID_CAP;
    // 標準slotと受領済みのDataspace・名前付きcapを、CRTのallocatorで上書きしない。
    initial.first_free_cap = next_cap >> L4_CAP_SHIFT;
    initial.utcb_area = l4_fpage(0xb3000000, L4_PAGESHIFT, 0);
    initial.first_free_utcb = 0xb3000000 + L4_UTCB_OFFSET;
    initial.caps = reinterpret_cast<l4re_env_cap_entry_t *>(caps);
    auto environment = push(&initial, sizeof(initial), 8);
    uintptr_t words[] = {2, a0, a1, 0, 0,
        AT_PHDR, 0x10000000 + header.e_phoff, AT_PHENT, sizeof(Elf64_Phdr), AT_PHNUM, header.e_phnum,
        AT_PAGESZ, Page_size, Native_aux_env, environment, Native_aux_kip, kip, AT_NULL, 0};
    auto sp = push(words, sizeof(words), 16);
    l4_addr_t stack_address = Native_stack;
    result = rm->attach(&stack_address, stack->size, L4Re::Rm::F::RW | L4Re::Rm::F::No_eager_map,
                       L4::Ipc::make_cap(stack->cap.get(), L4_CAP_FPAGE_RW));
    if (result < 0) return result;
    result = stack->detach();
    if (result < 0) return result;
    storage.push_back(std::move(stack));
    L4::Thread::Attr attributes;
    // pager/exception selectorは呼出側ではなく、bind先taskのcap表で解釈される。
    attributes.pager(L4::Cap<void>(0x10000));
    attributes.exc_handler(L4::Cap<void>(0x13000));
    attributes.bind(reinterpret_cast<l4_utcb_t *>(0xb3000000), task.get());
    result = l4_error(thread->control(attributes));
    if (result < 0) return result;
    result = l4_error(env->scheduler()->run_thread(thread.get(), l4_sched_param(2)));
    if (result < 0) return result;
    return l4_error(thread->ex_regs(header.e_entry, sp, 0));
}
}
