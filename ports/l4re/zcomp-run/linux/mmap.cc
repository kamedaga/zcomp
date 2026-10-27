#include "lifecycle.h"
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <sys/mman.h>

namespace Zcomp {
namespace {
constexpr uint64_t Fixed_noreplace = 0x100000;

bool rounded_size(uint64_t length, size_t &size)
{
    if (!length || length > UINT64_MAX - Page_size + 1) return false;
    size = (length + Page_size - 1) & ~(Page_size - 1);
    return true;
}

bool guest_range(uint64_t address, size_t size)
{ return address >= Mmap_start && address <= Mmap_end && size <= Mmap_end - address; }

bool protection(uint64_t prot, unsigned &flags)
{
    if (prot & ~uint64_t(PROT_READ | PROT_WRITE | PROT_EXEC)
        || ((prot & PROT_WRITE) && (prot & PROT_EXEC))) return false;
    // amd64ではW/Xのページも読める。ポインタ検査もnativeの実効保護に合わせる。
    flags = prot ? PF_R : 0;
    if (prot & PROT_WRITE) flags |= PF_W;
    if (prot & PROT_EXEC) flags |= PF_X;
    return true;
}

long linux_error(long result)
{
    if (result == -L4_ENOMEM || result == -L4_ENOSPC) return -ENOMEM;
    if (result == -ENOEXEC) return -ENOEXEC;
    if (result == -L4_EPERM || result == -L4_EACCESS) return -EACCES;
    return -EIO;
}
}

long map_memory(Thread_state &thread, Registers const &r)
{
    auto &space = *thread.process->address_space;
    size_t size;
    unsigned flags;
    if (!rounded_size(r.rsi, size)) return -EINVAL;
    if (size > Mmap_end - Mmap_start) return -ENOMEM;
    if (!protection(r.rdx, flags)) return -EOPNOTSUPP;
    constexpr uint64_t Supported = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | Fixed_noreplace
                                 | 0x20000 | 0x800 | 0x1000;
    if ((r.r10 & 0x0f) != MAP_PRIVATE || (r.r10 & ~Supported)) return -EOPNOTSUPP;
    bool fixed = r.r10 & (MAP_FIXED | Fixed_noreplace), anonymous = r.r10 & MAP_ANONYMOUS;
    if ((r.r9 & (Page_size - 1)) || r.r9 > INT64_MAX || (anonymous && r.r9)) return -EINVAL;
    uintptr_t address;
    if (fixed) {
        if (r.rdi & (Page_size - 1)) return -EINVAL;
        if (!space.managed_range(r.rdi, size)) return -EACCES;
        address = r.rdi;
        if (r.r10 & Fixed_noreplace)
            for (auto const &span : space.mappings.spans)
                if (address < span.end() && span.address < address + size) return -EEXIST;
    } else {
        uintptr_t hint = r.rdi & ~(Page_size - 1);
        address = guest_range(hint, size) ? space.find_free(hint, Mmap_end, size) : 0;
        if (!address) address = space.find_free(Mmap_start, Mmap_end, size);
        if (!address) return -ENOMEM;
    }
    if (!space.memory.is_valid()) return -EACCES;
    unsigned char const *source = nullptr;
    size_t copied = 0, physical = size;
    if (!anonymous) {
        auto fd = thread.files->get(static_cast<uint32_t>(r.r8));
        if (!fd || fd->object->kind != File_object::Kind::Regular) return -EBADF;
        auto &file = *fd->object;
        if (r.r9 < file.size) {
            copied = std::min(size, file.size - size_t(r.r9));
            source = file.data + r.r9;
        }
        physical = (copied + Page_size - 1) & ~(Page_size - 1);
    }
    long result = space.mmap_area.reserve();
    if (result < 0) return linux_error(result);
    bool reused = false;
    auto backing = std::make_shared<Memory_backing>();
    backing->file = !anonymous;
    result = backing->create(physical, space.memory, source, copied,
                              anonymous ? &space.memory_pool : nullptr, &reused);
    if (result == -L4_ENOMEM || result == -L4_ENOSPC) {
        // 使用中のslabには触らず、失敗したleaseと完全に未使用の実体だけ回収する。
        backing.reset();
        reused = false;
        if (space.memory_pool.reclaim()) {
            ++thread.process->counters.mmap_evictions;
            backing = std::make_shared<Memory_backing>(); backing->file = !anonymous;
            result = backing->create(physical, space.memory, source, copied);
        }
    }
    Guest_mapping mapping{address, size, 0, flags, std::move(backing)};
    if (result >= 0) result = prepare_executable(space, mapping, true);
    if (result >= 0) result = change_mappings(space, address, size, space.mappings.replace(address, size, &mapping));
    if (result < 0) {
        std::printf("[zcomp-memory] operation=mmap size=%zu native_error=%ld\n", size, result);
        return linux_error(result);
    }
    if (reused) ++thread.process->counters.mmap_reuses;
    publish_file_faults(thread);
    return static_cast<long>(address);
}

long protect_memory(Thread_state &thread, Registers const &r)
{
    auto &space = *thread.process->address_space;
    size_t size;
    unsigned flags;
    if (r.rdi & (Page_size - 1)) return -EINVAL;
    if (!r.rsi) return 0;
    if (!rounded_size(r.rsi, size)) return -EINVAL;
    if (!protection(r.rdx, flags)) return -EOPNOTSUPP;
    if (!space.managed_range(r.rdi, size) || !space.mappings.covers(r.rdi, size)) return -ENOMEM;
    auto next = space.mappings.protect(r.rdi, size, flags);
    for (auto &span : next) {
        if (span.end() <= r.rdi || span.address >= r.rdi + size) continue;
        // 実行済みコードの再書換えはJIT用の同期が必要。黙って不完全な再走査をしない。
        if ((flags & PF_W) && span.prepared) return -EOPNOTSUPP;
        long result = prepare_executable(space, span, false);
        if (result < 0) return linux_error(result);
    }
    long result = change_mappings(space, r.rdi, size, std::move(next));
    if (result < 0) return linux_error(result);
    publish_file_faults(thread);
    return 0;
}

long unmap_memory(Thread_state &thread, Registers const &r)
{
    auto &space = *thread.process->address_space;
    size_t size;
    if ((r.rdi & (Page_size - 1)) || !rounded_size(r.rsi, size) || r.rdi > UINT64_MAX - size) return -EINVAL;
    if (!space.managed_range(r.rdi, size)) return -EACCES;
    for (auto const &region : space.regions)
        if (r.rdi < region->address + region->size && region->address < r.rdi + size) return -EACCES;
    // 範囲外は部分成功させず拒否する。guest arena内の穴への解除はLinux同様に成功する。
    long result = change_mappings(space, r.rdi, size, space.mappings.replace(r.rdi, size));
    if (result < 0) return linux_error(result);
    publish_file_faults(thread);
    return 0;
}
}
