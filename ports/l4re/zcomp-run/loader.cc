#include "runtime.h"
#include "linux/identity.h"
extern "C" {
#include "scan.h"
}
#include <cstdio>
#include <cerrno>
#include <cstring>
#include <algorithm>

namespace Zcomp {
namespace {
struct Patch_plan {
    std::vector<size_t> sites;
    bool uncertain = false;
};

int collect_site(size_t offset, zcomp_site_kind kind, void *context)
{
    auto &plan = *static_cast<Patch_plan *>(context);
    if (kind == ZCOMP_SITE_ACCEPT)
        plan.sites.push_back(offset);
    else if (kind != ZCOMP_SITE_COVERED)
        plan.uncertain = true;
    return 0;
}

}

long rewrite_syscalls(unsigned char *code, size_t size)
{
    Patch_plan plan;
    zcomp_scan_stats stats;
    if (zcomp_scan(code, size, collect_site, &plan, &stats))
        return -L4_EIO;
    // Linuxと違い、見送った命令をホストLinuxに処理してもらうことはできない。
    if (plan.uncertain)
        return -ENOEXEC;
    // 走査中の変更は後続の収束判定を変えるため、全候補の判定後に書き換える。
    for (size_t offset : plan.sites) {
        code[offset] = 0xff;
        code[offset + 1] = 0xd0;
    }
    std::printf("[zcomp-run] Scan: candidates=%zu accepted=%zu covered=%zu\n",
                stats.candidates, stats.accepted, stats.covered);
    return 0;
}

namespace {
void place_elf(Address_space &space, Loaded_elf &loaded, unsigned char const *bytes, uintptr_t placement_min)
{
    auto const &image = loaded.image;
    size_t size = image.last_page - image.first_page;
    uintptr_t address = image.first_page;
    if (image.header.e_type == ET_DYN) {
        // 固定の基点を仮定せず、imageの全範囲とalignmentを満たす空きを選ぶ。ASLRは行わない。
        address = space.find_free(placement_min, Mmap_end, size, image.alignment, image.first_page);
        if (!address) fail("No aligned guest range is available for the ELF");
        loaded.load_bias = address - image.first_page;
    }
    long result = space.reserve_elf_area(address, size);
    if (result < 0) fail("Cannot reserve the ELF guest range", result);
    for (size_t i = 0; i < loaded.image.count; ++i) {
        auto const &p = loaded.image.segments[i];
        uintptr_t start = loaded.load_bias + p.p_vaddr;
        uintptr_t address = start & ~(Page_size - 1);
        size_t prefix = start - address;
        size_t size = (prefix + p.p_memsz + Page_size - 1) & ~(Page_size - 1);
        // ページ先頭を含むファイル内容とELF BSSを区別する。BSSとページ端数はcreateでゼロ化する。
        if ((p.p_vaddr & (Page_size - 1)) != (p.p_offset & (Page_size - 1)) || p.p_offset < prefix)
            fail("The ELF segment is not page-congruent");
        auto backing = std::make_shared<Memory_backing>();
        result = backing->create(size, space.memory, bytes + p.p_offset - prefix,
                                 p.p_filesz ? prefix + p.p_filesz : 0);
        Guest_mapping span{address, size, 0, p.p_flags, backing};
        if (result >= 0) result = prepare_executable(space, span, true);
        if (result >= 0) result = change_mappings(space, address, size, space.mappings.replace(address, size, &span));
        if (result < 0) fail("Cannot place and rewrite an ELF segment", result);
    }
}
}

void load_elf(Thread_state &thread, char const *path, uintptr_t placement_min)
{
    auto &space = *thread.process->address_space;
    FILE *file = std::fopen(path, "rb");
    if (!file)
        fail("Cannot open the guest ELF");
    if (std::fseek(file, 0, SEEK_END) || std::ftell(file) < 0)
        fail("Cannot determine the guest ELF size");
    long length = std::ftell(file);
    if (length > 64 * 1024 * 1024)
        fail("The guest ELF exceeds the prototype's size limit");
    std::rewind(file);
    std::vector<unsigned char> bytes(static_cast<size_t>(length));
    if (std::fread(bytes.data(), 1, bytes.size(), file) != bytes.size())
        fail("Cannot read the entire guest ELF");
    std::fclose(file);
    auto &main = space.main_elf;
    if (auto error = zcomp_elf_validate(bytes.data(), bytes.size(), &main.image))
        fail(error);
    if (main.image.interpreter[0]) {
        if (!space.memory.is_valid()) fail("Dynamic ELF loading requires linux_memory");
        if (space.mmap_area.reserve() < 0) fail("Cannot reserve the guest address arena");
        std::shared_ptr<File_object> interpreter;
        long result = lookup_file(*thread.filesystem->root, main.image.interpreter, interpreter);
        if (result < 0) fail("Cannot resolve the ELF interpreter in linux_files", result);
        if (auto error = zcomp_elf_validate(interpreter->data, interpreter->size, &space.interpreter.image))
            fail(error);
        if (space.interpreter.image.header.e_type != ET_DYN || space.interpreter.image.interpreter[0]
            || !space.interpreter.image.dynamic.p_type)
            fail("Expected a self-contained ET_DYN interpreter");
        // ET_EXECの指定番地は先に確保する。PIEはinterpreter配置後の空きから選び、相互衝突を避ける。
        if (main.image.header.e_type == ET_EXEC) place_elf(space, main, bytes.data(), placement_min);
        place_elf(space, space.interpreter, interpreter->data, placement_min);
        if (main.image.header.e_type == ET_DYN) place_elf(space, main, bytes.data(), placement_min);
        std::printf("[zcomp-loader] main_type=%s bias=%#lx entry=%#lx phdr=%#lx\n",
                    main.image.header.e_type == ET_DYN ? "ET_DYN" : "ET_EXEC",
                    main.load_bias, main.entry(), main.phdr());
        std::printf("[zcomp-loader] interpreter=%s bias=%#lx entry=%#lx\n", main.image.interpreter,
                    space.interpreter.load_bias, space.entry());
        return;
    }
    if (main.image.header.e_type == ET_DYN) {
        if (auto error = zcomp_elf_validate_static_pie(bytes.data(), &main.image)) fail(error);
        if (!space.memory.is_valid()) fail("Static PIE loading requires linux_memory");
        if (space.mmap_area.reserve() < 0) fail("Cannot reserve the guest address arena");
        // 自己再配置はguestのCRTが行う。ここで再配置すると、guestによる加算と二重適用になる。
        place_elf(space, main, bytes.data(), placement_min);
        std::printf("[zcomp-loader] static_pie=yes bias=%#lx entry=%#lx phdr=%#lx\n",
                    main.load_bias, main.entry(), main.phdr());
        return;
    }
    if (main.image.dynamic.p_type)
        fail("A dynamic ET_EXEC without an interpreter is not supported");
    for (size_t i = 0; i < main.image.count; ++i) {
        auto const &p = main.image.segments[i];
        uintptr_t address = p.p_vaddr & ~(Page_size - 1);
        size_t size = ((p.p_vaddr + p.p_memsz + Page_size - 1) & ~(Page_size - 1)) - address;
        auto region = std::make_unique<Region>(address, size, p.p_flags);
        region->create();
        auto data = region->alias + (p.p_vaddr - address);
        std::memcpy(data, bytes.data() + p.p_offset, p.p_filesz);
        // ネイティブのL4 IPCにもsyscallがある。ロードしたLinux領域だけを走査する。
        if (p.p_flags & PF_X) {
            long result = rewrite_syscalls(data, p.p_filesz);
            if (result < 0) fail("Cannot rewrite the executable region; hybrid is not supported", result);
        }
        space.regions.push_back(std::move(region));
    }
}

uintptr_t prepare_stack(Address_space &space, int argc, char **argv)
{
    auto region = std::make_unique<Region>(Stack_address, Stack_size, PF_R | PF_W);
    region->create();
    size_t cursor = Stack_size;
    std::vector<uint64_t> arguments;
    for (int i = 0; i < argc; ++i) {
        size_t length = std::strlen(argv[i]) + 1;
        if (length > cursor || cursor - length < 4096)
            fail("Arguments do not fit in the initial stack");
        cursor -= length;
        std::memcpy(region->alias + cursor, argv[i], length);
        arguments.push_back(Stack_address + cursor);
    }
    // 未提供のvDSOや乱数をauxvに偽装して、対応しているように見せない。
    std::vector<uint64_t> words{static_cast<uint64_t>(argc)};
    words.insert(words.end(), arguments.begin(), arguments.end());
    // Linuxの起動コードが配列を安全にたどれるよう、argvのNULL終端を置く。
    words.push_back(0);
    // L4Re用の環境変数を暗黙に引き継がせず、初版のenvpは空にする。
    words.push_back(0);
    auto aux = [&words](uint64_t type, uint64_t value) {
        words.push_back(type); words.push_back(value);
    };
    aux(AT_PAGESZ, Page_size);
    // libcの起動判定とgetuid/getgidの結果を一致させる。native側のIDや権限を引き継ぐ値ではない。
    aux(AT_UID, Guest_uid); aux(AT_EUID, Guest_uid);
    aux(AT_GID, Guest_gid); aux(AT_EGID, Guest_gid);
    aux(AT_SECURE, 0);
    aux(AT_ENTRY, space.main_elf.entry());
    aux(AT_BASE, space.interpreter.load_bias);
    aux(AT_PHENT, sizeof(Elf64_Phdr));
    aux(AT_PHNUM, space.main_elf.image.header.e_phnum);
    // 存在しないヘッダーをauxvに指させず、初版の配置方法で読める対象に限定する。
    if (!space.main_elf.image.phdr_address)
        fail("The prototype requires program headers to be included in PT_LOAD");
    aux(AT_PHDR, space.main_elf.phdr());
    aux(AT_EXECFN, arguments[0]);
    aux(AT_NULL, 0);
    size_t bytes = words.size() * sizeof(uint64_t);
    if (bytes > cursor || cursor - bytes < 4096)
        fail("Initial stack metadata does not fit");
    cursor = (cursor - bytes) & ~size_t(15);
    std::memcpy(region->alias + cursor, words.data(), bytes);
    space.regions.push_back(std::move(region));
    return Stack_address + cursor;
}

void prepare_trampoline(Address_space &space)
{
    auto region = std::make_unique<Region>(0, Page_size, PF_R | PF_X);
    region->create();
    auto code = region->alias;
    std::memset(code, 0x90, Syscall_limit);
    // 任意の64ビット番地へ、レジスタを変更せずに飛ぶRIP相対の間接jmp。
    const unsigned char jump[] = {0xff, 0x25, 0, 0, 0, 0};
    std::memcpy(code + Syscall_limit, jump, sizeof(jump));
    uintptr_t entry = reinterpret_cast<uintptr_t>(&zcomp_entry);
    std::memcpy(code + Syscall_limit + sizeof(jump), &entry, sizeof(entry));
    // 範囲外の番号は未対応。偶然ゼロ埋め領域で走り続けないよう停止命令で埋める。
    for (size_t i = Syscall_limit + 14; i + 1 < Page_size; i += 2) {
        code[i] = 0x0f; code[i + 1] = 0x0b;
    }
    space.regions.push_back(std::move(region));
}
}
