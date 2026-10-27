#include "runtime.h"
#include <l4/re/env>
#include <algorithm>
#include <cstring>

namespace Zcomp {
namespace {
class Native_view {
public:
    unsigned char *data = nullptr;
    ~Native_view() { close(); }
    long open(L4::Cap<L4Re::Dataspace> cap, size_t offset, size_t size, L4Re::Rm::Flags flags)
    {
        if (!size) return 0;
        long result = L4Re::Env::env()->rm()->attach(&data, size,
            flags | L4Re::Rm::F::Search_addr | L4Re::Rm::F::No_eager_map,
            L4::Ipc::make_cap(cap, flags & L4Re::Rm::F::W ? L4_CAP_FPAGE_RW : L4_CAP_FPAGE_R), offset);
        if (result < 0) return result;
        return cap->map_region(offset, L4Re::Dataspace::Flags(flags.raw & L4Re::Rm::F::RWX),
                              reinterpret_cast<uintptr_t>(data), reinterpret_cast<uintptr_t>(data) + size);
    }
    void close()
    {
        // 書込みaliasの解除失敗を無視すると、RXで公開してもW^Xが成立しなくなる。
        if (data && L4Re::Env::env()->rm()->detach(data, nullptr) < 0)
            fail("Cannot detach a temporary memory view");
        data = nullptr;
    }
};

Guest_mapping native_part(Guest_mapping const &span, uintptr_t first, uintptr_t last)
{
    uintptr_t begin = std::max(span.address, first);
    uintptr_t end = std::min(span.address + span.mapped_size(), last);
    return span.slice(begin, std::max(begin, end));
}

long detach_mapping(Guest_mapping const &span)
{
    if (!span.flags || !span.size) return 0;
    long result;
    bool changed = false;
    do {
        // 表では結合済みでもRMには複数regionが残り得る。Detach_againを処理し切ってから成功とする。
        result = L4Re::Env::env()->rm()->detach(span.address, span.size, nullptr);
        if (result < 0 && changed) fail("A partial native detach could not be completed", result);
        changed = result >= 0;
    } while (result >= 0 && (result & L4Re::Rm::Detach_again));
    return result;
}

void restore(std::vector<Guest_mapping> const &detached)
{
    for (auto const &span : detached)
        if (attach_mapping(span) < 0) fail("Cannot restore a guest mapping after rollback");
}

long allocate_dataspace(size_t size, L4::Cap<L4Re::Mem_alloc> memory,
                        L4Re::Util::Unique_cap<L4Re::Dataspace> &cap)
{
    cap = L4Re::Util::make_unique_cap<L4Re::Dataspace>();
    if (!cap.is_valid()) return -L4_ENOMEM;
    long result = memory->alloc(size, cap.get());
    return result < 0 ? result : cap->allocate(0, size);
}
}

bool Memory_slab::take(size_t bytes, size_t &offset)
{
    if (!bytes || (bytes & (Page_size - 1))) fail("Invalid pooled memory allocation size");
    size_t run = 0, pages = bytes / Page_size;
    for (size_t page = 0; page < size / Page_size; ++page) {
        if (_used[page / 64] & (uint64_t(1) << (page % 64))) run = 0;
        else if (++run == pages) {
            size_t first = page + 1 - pages;
            for (size_t i = first; i <= page; ++i) _used[i / 64] |= uint64_t(1) << (i % 64);
            offset = first * Page_size;
            return true;
        }
    }
    return false;
}

void Memory_slab::release(size_t offset, size_t bytes)
{
    if ((offset | bytes) & (Page_size - 1) || offset > size || bytes > size - offset)
        fail("Invalid pooled memory release");
    for (size_t page = offset / Page_size; page < (offset + bytes) / Page_size; ++page) {
        uint64_t bit = uint64_t(1) << (page % 64);
        if (!(_used[page / 64] & bit)) fail("Pooled memory was released twice");
        _used[page / 64] &= ~bit;
    }
}

bool Memory_slab::empty() const
{ return std::all_of(_used.begin(), _used.end(), [](uint64_t bits) { return !bits; }); }

Memory_backing::~Memory_backing()
{
    if (slab) slab->release(pool_offset, size);
}

long Dataspace_pool::take(Memory_backing &backing, L4::Cap<L4Re::Mem_alloc> memory, bool &reused)
{
    for (auto const &slab : _slabs)
        if (slab && slab->take(backing.size, backing.pool_offset)) {
            backing.slab = slab;
            reused = true;
            return 0;
        }
    if (backing.size > Max_bytes - _bytes) return 0;
    for (auto &slot : _slabs) {
        if (slot) continue;
        auto slab = std::make_shared<Memory_slab>();
        slab->size = std::min(Max_bytes - _bytes, std::max(Slab_bytes, backing.size));
        long result = allocate_dataspace(slab->size, memory, slab->cap);
        if ((result == -L4_ENOMEM || result == -L4_ENOSPC) && slab->size > backing.size) {
            // 小さいquotaで先取り分だけが失敗原因なら、要求量ちょうどの実体へ縮める。
            slab->cap.reset();
            slab->size = backing.size;
            result = allocate_dataspace(slab->size, memory, slab->cap);
        }
        if (result < 0) return result;
        if (!slab->take(backing.size, backing.pool_offset)) fail("A new memory slab cannot fit its request");
        _bytes += slab->size;
        slot = slab;
        backing.slab = std::move(slab);
        return 0;
    }
    return 0;
}

bool Dataspace_pool::reclaim()
{
    // quota回収で破棄できるのは完全に未使用の実体だけ。部分使用中の実体を無効化しない。
    bool reclaimed = false;
    for (auto &slab : _slabs)
        if (slab && slab->empty()) { _bytes -= slab->size; slab.reset(); reclaimed = true; }
    return reclaimed;
}

long Memory_backing::create(size_t bytes, L4::Cap<L4Re::Mem_alloc> memory,
                            unsigned char const *source, size_t source_size,
                            Dataspace_pool *pool, bool *reused)
{
    size = bytes;
    bool from_pool = false;
    if (reused) *reused = false;
    if (!size) return 0;
    if (pool && !file) {
        long result = pool->take(*this, memory, from_pool);
        if (result < 0) return result;
    }
    if (!slab) {
        long result = allocate_dataspace(size, memory, cap);
        if (result < 0) return result;
    }
    Native_view view;
    long result = view.open(dataspace(), pool_offset, size, L4Re::Rm::F::RW);
    if (result < 0) return result;
    // ファイル末尾の端数と再利用ページを含め、元の内容をguestへ漏らさない。
    std::memset(view.data, 0, size);
    if (source_size) std::memcpy(view.data, source, source_size);
    if (reused) *reused = from_pool;
    return 0;
}

long Guest_reservation::reserve(Guest_reservation const *parent)
{
    if (reserved) return 0;
    if (parent) {
        // 共通arena内のELF予約は論理的に分割する。RMへ重複予約したり、親の予約を解放したりしない。
        if (!parent->reserved || !parent->contains(address, size)) return -L4_EINVAL;
        reserved = true;
        return 0;
    }
    l4_addr_t wanted = address;
    long result = L4Re::Env::env()->rm()->reserve_area(&wanted, size);
    if (result < 0) return result;
    if (wanted != address) {
        L4Re::Env::env()->rm()->free_area(wanted);
        return -L4_EADDRNOTAVAIL;
    }
    reserved = true;
    owns_native_area = true;
    return 0;
}

Guest_reservation::~Guest_reservation()
{
    if (owns_native_area && L4Re::Env::env()->rm()->free_area(address) < 0)
        fail("Cannot release the guest address reservation");
}

long attach_mapping(Guest_mapping const &span)
{
    size_t size = span.mapped_size();
    if (!span.flags || !size) return 0;
    L4Re::Rm::Flags flags = L4Re::Rm::F::In_area | L4Re::Rm::F::No_eager_map;
    if (span.flags & PF_R) flags |= L4Re::Rm::F::R;
    if (span.flags & PF_W) flags |= L4Re::Rm::F::W;
    if (span.flags & PF_X) flags |= L4Re::Rm::F::X;
    l4_addr_t address = span.address;
    auto cap = span.backing->dataspace();
    size_t offset = span.backing->pool_offset + span.offset;
    long result = L4Re::Env::env()->rm()->attach(&address, size, flags,
        L4::Ipc::make_cap(cap, span.flags & PF_W ? L4_CAP_FPAGE_RW : L4_CAP_FPAGE_R), offset);
    if (result < 0) return result;
    if (address != span.address) fail("The RM changed a fixed guest mapping address");
    result = cap->map_region(offset, L4Re::Dataspace::Flags(flags.raw & L4Re::Rm::F::RWX),
                             address, address + size);
    if (result < 0 && L4Re::Env::env()->rm()->detach(address, size, nullptr) < 0)
        fail("Cannot remove a failed guest mapping");
    return result;
}

long prepare_executable(Address_space &space, Guest_mapping &span, bool unpublished)
{
    if (!(span.flags & PF_X) || span.prepared) return 0;
    size_t size = span.mapped_size();
    if (!size) { span.prepared = true; return 0; }
    if (!unpublished) {
        // mprotectが後で失敗しても、元のRW/Rの内容を変更しないよう準備用コピーへ書換える。
        Native_view source;
        long result = source.open(span.backing->dataspace(), span.backing->pool_offset + span.offset,
                                  size, L4Re::Rm::F::R);
        if (result < 0) return result;
        auto copy = std::make_shared<Memory_backing>();
        copy->file = span.backing->file;
        result = copy->create(size, space.memory, source.data, size, &space.memory_pool);
        if (result == -L4_ENOMEM || result == -L4_ENOSPC) {
            // コピー失敗時のleaseも先に返し、元の写像を保持したまま未使用実体だけ回収する。
            copy.reset();
            if (space.memory_pool.reclaim()) {
                copy = std::make_shared<Memory_backing>();
                copy->file = span.backing->file;
                result = copy->create(size, space.memory, source.data, size);
            }
        }
        if (result < 0) return result;
        span.backing = std::move(copy);
        span.offset = 0;
    }
    Native_view target;
    long result = target.open(span.backing->dataspace(), span.backing->pool_offset + span.offset,
                              size, L4Re::Rm::F::RW);
    if (result < 0) return result;
    result = rewrite_syscalls(target.data, size);
    if (result >= 0) span.prepared = true;
    return result;
}

long change_mappings(Address_space &space, uintptr_t address, size_t size, std::vector<Guest_mapping> next)
{
    Mapping_layout<Memory_backing>::coalesce(next);
    if (next.size() > Max_mappings) return -L4_ENOMEM;
    uintptr_t end = address + size;
    std::vector<Guest_mapping> detached, attached;
    // native写像を変更した後に管理表の追加確保で失敗しないよう、復旧用の記録枠を先に確保する。
    detached.reserve(space.mappings.spans.size());
    attached.reserve(next.size());
    for (auto const &span : space.mappings.spans) {
        if (span.end() <= address || span.address >= end || !span.flags) continue;
        auto part = native_part(span, address, end);
        if (!part.size) continue;
        long result = detach_mapping(part);
        if (result < 0) { restore(detached); return result; }
        detached.push_back(std::move(part));
    }
    for (auto const &span : next) {
        if (span.end() <= address || span.address >= end || !span.flags) continue;
        auto part = native_part(span, address, end);
        if (!part.size) continue;
        long result = attach_mapping(part);
        if (result < 0) {
            for (auto const &made : attached)
                if (detach_mapping(made) < 0) fail("Cannot undo a guest mapping update");
            restore(detached);
            return result;
        }
        attached.push_back(std::move(part));
    }
    space.mappings.spans.swap(next);
    // 旧表と復旧用の参照が消えてからleaseを返す。失敗時や部分解除で生きた領域を再利用しない。
    return 0;
}

Address_space::~Address_space()
{
    // 実体capの解放や予約解除より先に、native pagerに残る写像を取り除く。
    for (auto const &span : mappings.spans) {
        auto part = span.slice(span.address, span.address + span.mapped_size());
        if (detach_mapping(part) < 0) fail("Cannot detach a guest mapping during teardown");
    }
    mappings.spans.clear();
}

bool Address_space::managed_range(uintptr_t address, size_t size) const
{
    if (mmap_area.contains(address, size)) return true;
    for (auto const &area : elf_areas) if (area->contains(address, size)) return true;
    return false;
}

uintptr_t Address_space::find_free(uintptr_t first, uintptr_t limit, size_t size,
                                  size_t alignment, uintptr_t bias_origin) const
{
    for (;;) {
        auto candidate = mappings.find_free(first, limit, size, alignment, bias_origin);
        if (!candidate) return 0;
        uintptr_t next = limit;
        bool occupied = false;
        // セグメントの間に穴があってもELF全体の予約を守り、別のmmapを紛れ込ませない。
        for (auto const &area : elf_areas)
            if (candidate < area->address + area->size && area->address < candidate + size) {
                next = std::min(next, area->address + area->size);
                occupied = true;
            }
        if (!occupied) return candidate;
        first = next;
    }
}

long Address_space::reserve_elf_area(uintptr_t address, size_t size)
{
    if (!size || address < Page_size || address >= User_address_end || size > User_address_end - address
        || ((address | size) & (Page_size - 1)) || elf_areas.size() >= 2) return -L4_EINVAL;
    uintptr_t end = address + size;
    if (address < Stack_address + Stack_size && Stack_address < end) return -L4_EADDRNOTAVAIL;
    for (auto const &area : elf_areas)
        if (address < area->address + area->size && area->address < end) return -L4_EADDRNOTAVAIL;
    bool in_arena = mmap_area.contains(address, size);
    if (!in_arena && address < Mmap_end && Mmap_start < end) return -L4_EADDRNOTAVAIL;
    auto area = std::make_unique<Guest_reservation>(address, size);
    long result = in_arena ? mmap_area.reserve() : 0;
    if (result >= 0) result = area->reserve(in_arena ? &mmap_area : nullptr);
    if (result >= 0) elf_areas.push_back(std::move(area));
    return result;
}
}
