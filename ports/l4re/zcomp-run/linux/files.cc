#include "../runtime.h"
#include "../task.h"
#include "path.h"
#include <l4/re/env>
#include <l4/re/util/cap_alloc>
#include <cerrno>
#include <climits>
#include <cstring>
#include <fcntl.h>

namespace Zcomp {
size_t &File_description::position()
{
    return shared_offset ? shared_offset->value().offset : offset;
}
namespace {
// fd表は別でもopen file descriptionの位置は共有する。readv全体を一つの更新にする。
// 保持中はIPCや待ちを行わない。非信頼ゲストによるlock破壊への耐性は主張しない。
class Position_lock {
    Shared_offset *shared;
public:
    explicit Position_lock(File_description &file) : shared(file.shared_offset.get())
    {
        if (shared)
            while (__atomic_exchange_n(&shared->value().locked, 1, __ATOMIC_ACQUIRE))
                __asm__ volatile("pause");
    }
    ~Position_lock()
    {
        if (shared) __atomic_store_n(&shared->value().locked, 0, __ATOMIC_RELEASE);
    }
};
// ホストlibcのstruct statを流用すると、L4Re側のABI変更でゲストのバッファを壊し得る。
// Linux x86-64のsyscall ABIを固定し、ネイティブのメタデータ構造とは切り離す。
struct Linux_stat {
    uint64_t device, inode, links;
    uint32_t mode, uid, gid, padding;
    uint64_t rdevice;
    int64_t size, block_size, blocks;
    uint64_t access_time, access_nsec, modify_time, modify_nsec, change_time, change_nsec;
    int64_t unused[3];
};
static_assert(sizeof(Linux_stat) == 144, "Linux x86-64のstatは144バイトです。");
static_assert(offsetof(Linux_stat, mode) == 24 && offsetof(Linux_stat, size) == 48
              && offsetof(Linux_stat, access_time) == 72,
              "Linux x86-64のstatフィールド配置と一致する必要があります。");

struct Linux_iovec { uint64_t base, size; };
static_assert(sizeof(Linux_iovec) == 16, "Linux x86-64のiovecは16バイトです。");

// Linuxのfdはintであり、syscallレジスタ上位32ビットはfdの一部ではない。
File_description *find_file(Thread_state &thread, uint32_t fd)
{
    auto description = thread.files->get(fd);
    return description && description->object->kind == File_object::Kind::Regular ? description : nullptr;
}

long check_output(Thread_state const &thread, uint32_t fd)
{
    auto description = thread.files->get(fd);
    if (!description)
        return -EBADF;
    return description->object->console.is_valid() ? 0 : -EACCES;
}

long read_at(Thread_state &thread, File_description const &description, uint64_t buffer,
             uint64_t count, uint64_t offset)
{
    auto &space = *thread.process->address_space;
    auto &file = *description.object;
    if (count > LONG_MAX)
        return -EINVAL;
    // lseekはEOFの先にも移動できる。先に減算するとsize_tが巻き戻って領域外を読んでしまう。
    if (!count || offset >= file.size)
        return 0;
    size_t size = file.size - offset;
    if (size > count)
        size = count;
    if (!space.writable(buffer, size))
        return -EFAULT;
    std::memcpy(reinterpret_cast<void *>(buffer), file.data + offset, size);
    return static_cast<long>(size);
}

long guest_path(Address_space const &space, uint64_t address, char (&path)[256])
{
    // open/stat/accessのどの経路でも、NUL終端までをゲストの有効範囲内で読む。
    for (size_t i = 0; i < sizeof(path); ++i) {
        if (address > UINT64_MAX - i || !space.readable(address + i, 1)) return -EFAULT;
        path[i] = *reinterpret_cast<char const *>(address + i);
        if (!path[i]) return i ? 0 : -ENOENT;
    }
    return -ENAMETOOLONG;
}

void regular_stat(File_object const &file, Linux_stat &stat)
{
    stat.mode = 0100000 | 0444;
    stat.device = 1;
    stat.inode = file.inode;
    stat.size = file.size;
    stat.blocks = (file.size + 511) / 512;
}

long path_stat(Thread_state &thread, uint64_t address, Linux_stat &stat)
{
    char path[256];
    long result = guest_path(*thread.process->address_space, address, path);
    if (result < 0) return result;
    std::string name;
    result = namespace_path(path, name);
    // cwdは公開rootに固定されている。rootの存在もlinux_filesの付与に従う。
    if (result == -EISDIR) {
        if (!thread.filesystem->root->capability.is_valid()) return -EACCES;
        stat.mode = 0040000 | 0555;
        stat.device = 1;
        stat.inode = UINT64_MAX;
        return 0;
    }
    if (result < 0) return result;
    std::shared_ptr<File_object> file;
    result = lookup_file(*thread.filesystem->root, path, file);
    if (result >= 0) regular_stat(*file, stat);
    return result;
}

long write_stat(Address_space &space, uint64_t address, Linux_stat &stat)
{
    if (!space.writable(address, sizeof(stat))) return -EFAULT;
    // Dataspaceには所有者・時刻がない。0は仮想メタデータであり、権限判定には使わない。
    stat.links = 1;
    stat.block_size = Page_size;
    std::memcpy(reinterpret_cast<void *>(address), &stat, sizeof(stat));
    return 0;
}
}

std::shared_ptr<File_object> File_namespace::cached(std::string const &name) const
{
    if (immutable)
        for (auto const &entry : _cache)
            if (entry.file && entry.name == name) return entry.file;
    return {};
}

void File_namespace::remember(std::string const &name, std::shared_ptr<File_object> const &file)
{
    if (!immutable || file->size > Cache_bytes) return;
    auto mapped_size = [](File_object const &object) {
        return (object.size + Page_size - 1) & ~(Page_size - 1);
    };
    size_t size = mapped_size(*file);
    // 単純なFIFOで上限を守る。追い出しても、開いているfdの参照と位置は残る。
    size_t slot = _next;
    do {
        auto &entry = _cache[_next];
        if (entry.file) _cached_bytes -= mapped_size(*entry.file);
        entry = {};
        _next = (_next + 1) % Cache_entries;
    } while (_cached_bytes > Cache_bytes - size);
    _cache[slot] = {name, file};
    _cached_bytes += size;
    // 容量回収が一周した場合も、入れた直後の項目を次の追い出し対象にしない。
    if (_next == slot) _next = (_next + 1) % Cache_entries;
}

bool File_namespace::clear_cache()
{
    bool had_entries = false;
    for (auto &entry : _cache) {
        had_entries |= bool(entry.file);
        entry = {};
    }
    _cached_bytes = _next = 0;
    return had_entries;
}

File_object::~File_object()
{
    if (data)
        L4Re::Env::env()->rm()->detach(data, nullptr);
    if (dataspace.is_valid())
        L4Re::Util::cap_alloc.free(dataspace, L4Re::This_task, L4_FP_ALL_SPACES);
}

long open_file(Thread_state &thread, Registers const &r)
{
    auto &space = *thread.process->address_space;
    auto &files = *thread.files;
    auto &root = *thread.filesystem->root;
    char path[256];
    long result = guest_path(space, r.rsi, path);
    if (result < 0) return result;
    // Linux同様に絶対パスはdirfdを使わない。相対パスのdirectory fdはまだ受理しない。
    if (path[0] != '/' && static_cast<int32_t>(r.rdi) != AT_FDCWD)
        return -EBADF;
    if (r.rdx & O_ACCMODE)
        return -EACCES;
    // muslのopenはx86-64でもO_LARGEFILEを付ける。offsetは初めから64ビットなので害なく許せる。
    constexpr uint64_t Linux_o_largefile = 0100000;
    // 公開namespaceにはsymlinkを置かないため、NOFOLLOWでも同じ名前解決を利用できる。
    if (r.rdx & ~uint64_t(O_CLOEXEC | O_NOFOLLOW | Linux_o_largefile))
        return -EOPNOTSUPP;
    size_t index = 3;
    while (index < files.entries.size() && files.entries[index].description)
        ++index;
    if (index == files.entries.size())
        return -EMFILE;
    std::shared_ptr<File_object> file;
    result = lookup_file(root, path, file);
    if (result < 0) return result;
    auto description = std::make_shared<File_description>();
    description->object = std::move(file);
    files.entries[index] = {std::move(description), bool(r.rdx & O_CLOEXEC)};
    return static_cast<long>(index);
}

namespace {
long load_file(File_namespace &root, std::string const &name, std::shared_ptr<File_object> &output)
{
    auto file = std::make_shared<File_object>();
    file->dataspace = L4Re::Util::cap_alloc.alloc<L4Re::Dataspace>();
    if (!file->dataspace.is_valid())
        return -ENOMEM;
    // interpreterとopenは同じ公開rootを使う。起動用ROMへのフォールバックは設けない。
    long result = root.capability->query(name.c_str(), file->dataspace, 0);
    if (result < 0)
        return result == -L4_ENOENT ? -ENOENT : (result == -L4_EPERM ? -EACCES : -EIO);
    L4Re::Dataspace::Stats stats{};
    result = file->dataspace->info(&stats);
    if (result < 0 || stats.size > 64 * 1024 * 1024)
        return result < 0 ? -EIO : -EFBIG;
    file->size = stats.size;
    if (file->size) {
        size_t mapped = (file->size + Page_size - 1) & ~(Page_size - 1);
        result = L4Re::Env::env()->rm()->attach(&file->data, mapped,
            L4Re::Rm::F::Search_addr | L4Re::Rm::F::R | L4Re::Rm::F::No_eager_map,
            L4::Ipc::make_cap(file->dataspace, L4_CAP_FPAGE_R));
        if (result < 0)
            return -ENOMEM;
        result = file->dataspace->map_region(0, L4Re::Dataspace::F::R,
            reinterpret_cast<uintptr_t>(file->data), reinterpret_cast<uintptr_t>(file->data) + mapped);
        if (result < 0)
            return result == -L4_EPERM ? -EACCES : -ENOMEM;
    }
    size_t identity = 0;
    while (identity < root.file_names.size() && root.file_names[identity] != name)
        ++identity;
    if (identity == root.file_names.size())
        root.file_names.emplace_back(name);
    // Dataspaceのnative inodeはないため、公開namespace内の名前をこのtask内のidentityにする。
    file->inode = identity + 1;
    output = std::move(file);
    return 0;
}
}

long lookup_file(File_namespace &root, char const *path, std::shared_ptr<File_object> &output)
{
    std::string name;
    long result = namespace_path(path, name);
    if (result < 0) return result;
    if (!root.capability.is_valid()) return -EACCES;
    if (auto file = root.cached(name)) {
        output = std::move(file);
        return 0;
    }
    result = load_file(root, name, output);
    // 空きslot・写像の不足をcacheだけで引き起こさない。開いているfdの参照は回収されない。
    if (result == -ENOMEM && root.clear_cache()) result = load_file(root, name, output);
    // 成功した実体だけを保持し、ENOENT/EACCESや失敗途中のCapabilityを再利用しない。
    if (result >= 0) root.remember(name, output);
    return result;
}

long read_file(Thread_state &thread, Registers const &r)
{
    auto file = find_file(thread, r.rdi);
    if (!file)
        return -EBADF;
    Position_lock lock(*file);
    long result = read_at(thread, *file, r.rsi, r.rdx, file->position());
    if (result > 0)
        file->position() += result;
    return result;
}

long pread_file(Thread_state &thread, Registers const &r)
{
    if (r.r10 > uint64_t(INT64_MAX))
        return -EINVAL;
    auto file = find_file(thread, r.rdi);
    if (!file)
        return -EBADF;
    // 通常のreadと同じ範囲検査を使うが、fdの共有位置は変更しない。
    return read_at(thread, *file, r.rsi, r.rdx, r.r10);
}

long seek_file(Thread_state &thread, Registers const &r)
{
    uint32_t fd = r.rdi;
    if (fd == 1 || fd == 2) {
        long result = check_output(thread, fd);
        return result < 0 ? result : -ESPIPE;
    }
    auto file = find_file(thread, r.rdi);
    if (!file)
        return -EBADF;
    Position_lock lock(*file);
    uint64_t base;
    switch (static_cast<uint32_t>(r.rdx)) {
    case 0: base = 0; break;
    case 1: base = file->position(); break;
    case 2: base = file->object->size; break;
    default: return -EINVAL;
    }
    uint64_t position;
    if (r.rsi > uint64_t(INT64_MAX)) {
        // INT64_MINの符号反転を符号付きで行うと未定義動作になるため、絶対値もunsignedで求める。
        uint64_t backwards = uint64_t(0) - r.rsi;
        if (backwards > base)
            return -EINVAL;
        position = base - backwards;
    } else {
        if (r.rsi > uint64_t(INT64_MAX) - base)
            return -EINVAL;
        position = base + r.rsi;
    }
    // エラー時は位置を変えない。次のreadまで含めてLinuxの挙動を維持する。
    file->position() = position;
    return static_cast<long>(position);
}

long stat_file(Thread_state &thread, Registers const &r)
{
    auto &space = *thread.process->address_space;
    Linux_stat stat{};
    uint32_t fd = r.rdi;
    if (fd == 1 || fd == 2) {
        long result = check_output(thread, fd);
        if (result < 0)
            return result;
        // Vconはseekできない出力デバイスとして公開し、通常ファイルと区別する。
        stat.mode = 0020000 | 0222;
        stat.inode = 1;
    } else {
        auto file = find_file(thread, r.rdi);
        if (!file)
            return -EBADF;
        regular_stat(*file->object, stat);
    }
    return write_stat(space, r.rsi, stat);
}

long stat_path(Thread_state &thread, Registers const &r)
{
    Linux_stat stat{};
    // 公開モデルにsymlinkはない。stat/lstatともopenと同じnamespaceの実体を調べる。
    long result = path_stat(thread, r.rdi, stat);
    return result < 0 ? result : write_stat(*thread.process->address_space, r.rsi, stat);
}

long access_file(Thread_state &thread, Registers const &r)
{
    uint32_t mode = r.rsi;
    if (mode & ~7U) return -EINVAL;
    Linux_stat stat{};
    long result = path_stat(thread, r.rdi, stat);
    if (result < 0) return result;
    // read-only公開ファイルに書込み・実行の成功を返さない。directoryの探索だけは許可する。
    return ((mode & 2) || ((mode & 1) && !(stat.mode & 0111))) ? -EACCES : 0;
}

long read_vector(Thread_state &thread, Registers const &r)
{
    auto &space = *thread.process->address_space;
    auto file = find_file(thread, r.rdi);
    if (!file)
        return -EBADF;
    if (r.rdx > 1024)
        return -EINVAL;
    if (!r.rdx)
        return 0;
    if (!space.readable(r.rsi, r.rdx * sizeof(Linux_iovec)))
        return -EFAULT;
    // 読み取り先がiovec自身と重なっても、後続の要素の解釈を変えないよう先に複製する。
    std::array<Linux_iovec, 1024> vectors;
    std::memcpy(vectors.data(), reinterpret_cast<void const *>(r.rsi), r.rdx * sizeof(Linux_iovec));
    uint64_t total = 0;
    for (uint64_t i = 0; i < r.rdx; ++i) {
        if (vectors[i].size > uint64_t(LONG_MAX) - total)
            return -EINVAL;
        total += vectors[i].size;
    }
    Position_lock lock(*file);
    long copied = 0;
    for (uint64_t i = 0; i < r.rdx; ++i) {
        auto const &vector = vectors[i];
        long result = read_at(thread, *file, vector.base, vector.size, file->position());
        // 後半のバッファだけが不正なら、既に読めたバイト数と位置を保持して部分成功を返す。
        if (result < 0)
            return copied ? copied : result;
        file->position() += result;
        copied += result;
        if (uint64_t(result) != vector.size)
            break;
    }
    return copied;
}

long close_file(Thread_state &thread, uint64_t raw_fd)
{
    uint32_t fd = raw_fd;
    auto &files = *thread.files;
    if (!files.get(fd))
        return -EBADF;
    // ここで消すのはfdだけ。複製した表や別fdの参照があれば記述と位置は存続する。
    files.entries[fd] = {};
    return 0;
}
}
