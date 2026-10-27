#pragma once

#include "elf_image.h"
#include "linux/syscalls.h"
#include "state.h"
#include "mapping_layout.h"
#include <l4/re/dataspace>
#include <l4/re/rm>
#include <l4/re/mem_alloc>
#include <l4/re/namespace>
#include <l4/re/util/unique_cap>
#include <l4/sys/vcon>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace Zcomp {

constexpr size_t Page_size = 4096;
constexpr size_t Stack_size = 128 * 1024;
constexpr uintptr_t Stack_address = 0x70000000;
constexpr unsigned Syscall_limit = 512;
constexpr uintptr_t Mmap_start = 0x60000000;
constexpr uintptr_t Mmap_end = 0x68000000;
constexpr uintptr_t User_address_end = 0x0000800000000000;

// 初期ELF・スタック・trampolineのロード用。実行中のmmapは下の予約・実体・区間で管理する。
// aliasは準備中だけ書込み可能にし、実行前に外してW^Xを保つ。
class Region {
public:
    Region(uintptr_t address, size_t size, unsigned elf_flags);
    ~Region();
    Region(Region const &) = delete;
    Region &operator=(Region const &) = delete;
    void create();
    void publish();
    long try_create(L4::Cap<L4Re::Mem_alloc> allocator);
    long try_publish();
    L4::Cap<L4Re::Dataspace> dataspace() const { return _dataspace; }
    long import(L4::Cap<L4Re::Dataspace> dataspace);
    uintptr_t address;
    size_t size;
    unsigned elf_flags;
    unsigned char *alias = nullptr;
private:
    long attach_visible();
    L4::Cap<L4Re::Dataspace> _dataspace;
    bool _reserved = false;
    bool _attached = false;
};

// fdまたはnamespaceのcacheが実体を参照している間は、写像とCapabilityを保持する。
struct File_object {
    enum class Kind { Regular, Console };
    ~File_object();
    File_object() = default;
    File_object(File_object const &) = delete;
    File_object &operator=(File_object const &) = delete;
    Kind kind = Kind::Regular;
    L4::Cap<L4Re::Dataspace> dataspace;
    L4::Cap<L4::Vcon> console;
    unsigned char *data = nullptr;
    size_t size = 0;
    uint64_t inode = 0;
};

struct Registers {
    uint64_t rax, rdi, rsi, rdx, r10, r8, r9;
    uint64_t rbx, rbp, r12, r13, r14, r15, rcx, r11, flags;
};
static_assert(sizeof(Registers) == 128, "アセンブリの保存フレームと一致する必要があります。");
static_assert(offsetof(Registers, rcx) == 104, "RCXの復元位置と一致する必要があります。");
static_assert(offsetof(Registers, flags) == 120, "フラグの復元位置と一致する必要があります。");

struct Memory_slab {
    static constexpr size_t Max_bytes = 1024 * 1024;
    size_t size = 0;
    L4Re::Util::Unique_cap<L4Re::Dataspace> cap;
    bool take(size_t bytes, size_t &offset);
    void release(size_t offset, size_t bytes);
    bool empty() const;
private:
    // ページ単位の固定bitmapなら、解放経路で管理用メモリを追加確保せずに済む。
    std::array<uint64_t, Max_bytes / Page_size / 64> _used{};
};

class Dataspace_pool;
struct Memory_backing {
    ~Memory_backing();
    size_t size = 0;
    bool file = false;
    L4Re::Util::Unique_cap<L4Re::Dataspace> cap;
    // 部分munmap後も、残った区間がある間は割当全体を保持する。生きたページを再利用しない。
    std::shared_ptr<Memory_slab> slab;
    size_t pool_offset = 0;
    L4::Cap<L4Re::Dataspace> dataspace() const { return slab ? slab->cap.get() : cap.get(); }
    long create(size_t bytes, L4::Cap<L4Re::Mem_alloc> memory,
                unsigned char const *source = nullptr, size_t source_size = 0,
                Dataspace_pool *pool = nullptr, bool *reused = nullptr);
};
using Guest_mapping = Mapping_span<Memory_backing>;

class Dataspace_pool {
public:
    // 使用中の部分も含めて1 MiB以内に収め、保持枠を増やすだけの最適化にしない。
    static constexpr size_t Max_bytes = Memory_slab::Max_bytes;
    // 通常は一つの連続実体を使い、小さいquotaで縮小した場合だけ複数実体を許す。
    static constexpr size_t Slab_bytes = Max_bytes, Max_slabs = 16;
    long take(Memory_backing &backing, L4::Cap<L4Re::Mem_alloc> memory, bool &reused);
    bool reclaim();
    size_t bytes() const { return _bytes; }
private:
    // leaseも実体を所有するため、pool破棄と失敗経路の一時参照の寿命を取り違えない。
    std::array<std::shared_ptr<Memory_slab>, Max_slabs> _slabs;
    size_t _bytes = 0;
};

// LinuxのPROT_NONE写像とは別のnative予約。穴もguest allocatorが再利用できるよう全体を保持する。
struct Guest_reservation {
    Guest_reservation(uintptr_t start = Mmap_start, size_t length = Mmap_end - Mmap_start)
        : address(start), size(length) {}
    ~Guest_reservation();
    uintptr_t address;
    size_t size;
    bool reserved = false;
    bool owns_native_area = false;
    long reserve(Guest_reservation const *parent = nullptr);
    bool contains(uintptr_t start, size_t length) const
    { return start >= address && start - address <= size && length <= size - (start - address); }
};

struct Loaded_elf {
    zcomp_elf_image image{};
    uintptr_t load_bias = 0;
    uintptr_t entry() const { return load_bias + image.header.e_entry; }
    uintptr_t phdr() const { return load_bias + image.phdr_address; }
};

struct Address_space {
    size_t execution_threads = 0;
    Loaded_elf main_elf, interpreter;
    std::vector<std::unique_ptr<Region>> regions;
    ~Address_space();
    Guest_reservation mmap_area;
    std::vector<std::unique_ptr<Guest_reservation>> elf_areas;
    Mapping_layout<Memory_backing> mappings;
    L4::Cap<L4Re::Mem_alloc> memory;
    // 匿名メモリの未使用部分を再利用する。VM共有時もruntime mutex内で操作する。
    Dataspace_pool memory_pool;
    std::vector<File_fault_range> reported_file_faults;
    bool readable(uintptr_t address, size_t size) const;
    bool writable(uintptr_t address, size_t size) const;
    bool accessible(uintptr_t address, size_t size, unsigned flags) const;
    bool managed_range(uintptr_t address, size_t size) const;
    uintptr_t find_free(uintptr_t first, uintptr_t limit, size_t size,
                        size_t alignment = 1, uintptr_t bias_origin = 0) const;
    long reserve_elf_area(uintptr_t address, size_t size);
    uintptr_t entry() const { return interpreter.image.count ? interpreter.entry() : main_elf.entry(); }
};

long attach_mapping(Guest_mapping const &mapping);
long change_mappings(Address_space &space, uintptr_t address, size_t size, std::vector<Guest_mapping> next);
long prepare_executable(Address_space &space, Guest_mapping &mapping, bool unpublished);
long rewrite_syscalls(unsigned char *code, size_t size);

struct File_namespace {
    L4::Cap<L4Re::Namespace> capability;
    // FS状態を複製しても同じ公開namespaceの仮想inode割当を分岐させない。
    std::vector<std::string> file_names;
    // R権限は不変性を意味しない。公開元が名前・内容の固定を約束した場合だけ再利用する。
    bool immutable = false;
    static constexpr size_t Cache_entries = 16;
    static constexpr size_t Cache_bytes = 1024 * 1024;
    std::shared_ptr<File_object> cached(std::string const &name) const;
    void remember(std::string const &name, std::shared_ptr<File_object> const &file);
    bool clear_cache();
private:
    struct Cache_entry { std::string name; std::shared_ptr<File_object> file; };
    // fd数とは別に保持する参照なので、件数とページ単位の写像容量を両方制限する。
    std::array<Cache_entry, Cache_entries> _cache{};
    size_t _cached_bytes = 0, _next = 0;
};

struct Fs_context {
    std::shared_ptr<File_namespace> root = std::make_shared<File_namespace>();
    uint32_t umask = 0022;
    // 相対パスのcwdは公開rootに固定する。chdirやdirectory fdはまだ実装しない。
};

// 起動・所有のための束。syscallはこの束でなく、呼び出したThread_stateを受け取る。
struct Runtime {
    Runtime();
    std::unique_ptr<Thread_state> main_thread;
};

[[noreturn]] void fail(char const *message, long error = 0);
long lookup_file(File_namespace &root, char const *path, std::shared_ptr<File_object> &file);
void load_elf(Thread_state &thread, char const *path, uintptr_t placement_min = Mmap_start);
uintptr_t prepare_stack(Address_space &space, int argc, char **argv);
void prepare_trampoline(Address_space &space);

extern "C" long zcomp_enter(Execution_context *context, uintptr_t entry, uintptr_t stack);
extern "C" long zcomp_resume(Execution_context *context);
extern "C" void zcomp_entry();
extern "C" int zcomp_check_trampoline(uintptr_t entry);
extern "C" [[noreturn]] void zcomp_finish(long status);
// 入口でlibcを呼ぶ前に使うため、この関数はTLS非依存のL4 IPCだけで実装する。
extern "C" long zcomp_set_fs(uintptr_t base);
void bind_execution(Execution_context &context);
void unbind_execution();
}
