#include "runtime.h"
#include <l4/re/env>
#include <l4/re/mem_alloc>
#include <l4/re/util/cap_alloc>
#include <l4/sys/task>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace Zcomp {
[[noreturn]] void fail(char const *message, long error)
{
    std::fprintf(stderr, "[zcomp-run] Error: %s (error=%ld)\n", message, error);
    std::exit(1);
}

Region::Region(uintptr_t address, size_t size, unsigned elf_flags)
: address(address), size(size), elf_flags(elf_flags) {}

void Region::create()
{
    long result = try_create(L4Re::Env::env()->mem_alloc());
    if (result < 0)
        fail("Cannot prepare the memory region", result);
}

long Region::try_create(L4::Cap<L4Re::Mem_alloc> allocator)
{
    auto env = L4Re::Env::env();
    // MAP_FIXEDのように既存のランタイムやUTCBを上書きしてはならない。
    long result;
    // ITASの管理範囲外にある0番地だけは、publishで自taskへ直接マップする。
    if (address != 0) {
        l4_addr_t wanted = address;
        result = env->rm()->reserve_area(&wanted, size);
        if (result < 0 || wanted != address) {
            if (result >= 0)
                env->rm()->free_area(wanted);
            return result < 0 ? result : -L4_EADDRNOTAVAIL;
        }
        _reserved = true;
    }
    if (!_dataspace.is_valid()) {
        _dataspace = L4Re::Util::cap_alloc.alloc<L4Re::Dataspace>();
        if (!_dataspace.is_valid())
            return -L4_ENOMEM;
        result = allocator->alloc(size, _dataspace);
        if (result < 0)
            return result;
        // Dataspaceは遅延確保され得る。quota不足を後のページフォールトでなくここで返す。
        result = _dataspace->allocate(0, size);
        if (result < 0)
            return result;
    }
    result = env->rm()->attach(&alias, size,
        L4Re::Rm::F::Search_addr | L4Re::Rm::F::RW | L4Re::Rm::F::No_eager_map,
        L4::Ipc::make_cap(_dataspace, L4_CAP_FPAGE_RW));
    if (result < 0)
        return result;
    // この版のRm::attachはeager mappingのエラーを返さないため、写像を別途検査する。
    result = _dataspace->map_region(0, L4Re::Dataspace::F::RW,
        reinterpret_cast<uintptr_t>(alias), reinterpret_cast<uintptr_t>(alias) + size);
    if (result < 0)
        return result;
    // ファイルに初期値を持たないBSSと、ページ端の未使用部分まで必ずゼロにする。
    std::memset(alias, 0, size);
    return 0;
}

void Region::publish()
{
    long result = try_publish();
    if (result < 0)
        fail("Cannot publish the memory region", result);
}

long Region::try_publish()
{
    auto rm = L4Re::Env::env()->rm();
    long result = rm->detach(alias, nullptr);
    if (result < 0)
        return result;
    alias = nullptr;
    if (address == 0) {
        // 書き込みaliasを消した後、RXの供給元だけを残してW^Xを守る。
        result = rm->attach(&alias, size,
            L4Re::Rm::F::Search_addr | L4Re::Rm::F::RX | L4Re::Rm::F::No_eager_map,
            _dataspace);
        if (result < 0)
            return result;
        result = _dataspace->map_region(0, L4Re::Dataspace::F::RX,
            reinterpret_cast<uintptr_t>(alias), reinterpret_cast<uintptr_t>(alias) + size);
        if (result < 0)
            return result;
        auto task = L4Re::Env::env()->task();
        result = l4_error(task->map(task,
            l4_fpage(reinterpret_cast<l4_addr_t>(alias), L4_PAGESHIFT, L4_FPAGE_RX),
            0));
        if (result < 0)
            return result;
        // mapの成功タグだけでは既存マップとの衝突を検出できないため、実内容も確認する。
        if (!zcomp_check_trampoline(reinterpret_cast<uintptr_t>(&zcomp_entry)))
            return -L4_EIO;
        _attached = true;
        return 0;
    }
    return attach_visible();
}

long Region::attach_visible()
{
    // PROT_NONEは予約とDataspaceだけを保持する。pagerに読めるregionを残すと保護を迂回してしまう。
    if (!elf_flags)
        return 0;
    L4Re::Rm::Flags flags = L4Re::Rm::F::In_area | L4Re::Rm::F::No_eager_map;
    if (elf_flags & PF_R)
        flags |= L4Re::Rm::F::R;
    if (elf_flags & PF_W)
        flags |= L4Re::Rm::F::W;
    if (elf_flags & PF_X)
        flags |= L4Re::Rm::F::X;
    l4_addr_t start = address;
    l4_addr_t wanted = start;
    long result = L4Re::Env::env()->rm()->attach(&wanted, size,
                                               flags, L4::Ipc::make_cap(_dataspace,
                                                   elf_flags & PF_W ? L4_CAP_FPAGE_RW : L4_CAP_FPAGE_R),
                                               0);
    if (result < 0 || wanted != start)
        return result < 0 ? result : -L4_EADDRNOTAVAIL;
    _attached = true;
    return _dataspace->map_region(0,
                                  L4Re::Dataspace::Flags(flags.raw & L4Re::Rm::F::RWX),
                                  start, address + size);
}

Region::~Region()
{
    auto rm = L4Re::Env::env()->rm();
    // 0番地の直接マップも、この供給元の解除で派生マッピングとして取り消される。
    if (alias)
        rm->detach(alias, nullptr);
    if (_attached && address != 0)
        rm->detach(address, nullptr);
    if (_reserved)
        rm->free_area(address);
    if (_dataspace.is_valid())
        L4Re::Util::cap_alloc.free(_dataspace, L4Re::This_task, L4_FP_ALL_SPACES);
}

long Region::import(L4::Cap<L4Re::Dataspace> dataspace)
{
    if (!address || !dataspace.is_valid())
        return -L4_EINVAL;
    l4_addr_t wanted = address;
    long result = L4Re::Env::env()->rm()->reserve_area(&wanted, size);
    if (result < 0 || wanted != address) {
        if (result >= 0) L4Re::Env::env()->rm()->free_area(wanted);
        return result < 0 ? result : -L4_EADDRNOTAVAIL;
    }
    _reserved = true;
    _dataspace = dataspace;
    return attach_visible();
}

bool Address_space::readable(uintptr_t address, size_t size) const
{
    return accessible(address, size, PF_R);
}

bool Address_space::writable(uintptr_t address, size_t size) const
{
    return accessible(address, size, PF_W);
}

bool Address_space::accessible(uintptr_t address, size_t size, unsigned flags) const
{
    // ポインタ検査はLinuxのEFAULT用であり、同一task内部のセキュリティ境界ではない。
    auto contains = [&](auto const &region) {
        return region && region->address != 0 && (region->elf_flags & flags) == flags
            && address >= region->address
            && address - region->address <= region->size
            && size <= region->size - (address - region->address);
    };
    for (auto const &region : regions)
        if (contains(region))
            return true;
    return mappings.covers(address, size, flags, true);
}

}
