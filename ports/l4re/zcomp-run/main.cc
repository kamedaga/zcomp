#include "runtime.h"
#include "task.h"
#include "capabilities.h"
#include "bootstrap.h"
#include "linux/lifecycle.h"
#include <l4/re/env>
#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <cstring>

int main(int argc, char **argv)
{
    using namespace Zcomp;
    if (argc == 2 && !std::strcmp(argv[1], "--fork-child"))
        return restore_fork_child();
    int guest_index = 1;
    uintptr_t placement_min = Mmap_start;
    bool audit = false;
    bool immutable_files = false;
    while (guest_index < argc) {
        char const *option = argv[guest_index];
        if (!std::strcmp(option, "--audit-caps")) {
            audit = true;
            ++guest_index;
        } else if (!std::strcmp(option, "--immutable-files")) {
            immutable_files = true;
            ++guest_index;
        } else if (!std::strcmp(option, "--load-min")) {
            if (guest_index + 1 >= argc) fail("Expected an address after --load-min");
            char *end;
            errno = 0;
            auto value = std::strtoull(argv[guest_index + 1], &end, 0);
            if (errno || !argv[guest_index + 1][0] || *end || value < Mmap_start || value >= Mmap_end || (value & (Page_size - 1)))
                fail("The load minimum must be a page-aligned address inside the guest arena");
            placement_min = value;
            guest_index += 2;
        } else break;
    }
    if (argc <= guest_index)
        fail("Usage: zcomp-run [--audit-caps] [--immutable-files] [--load-min <address>] <Linux ELF path> [args...]");
    Runtime runtime;
    auto &thread = *runtime.main_thread;
    auto &process = *thread.process;
    auto &space = *process.address_space;
    auto &counters = process.counters;
    auto output = std::make_shared<File_object>();
    output->kind = File_object::Kind::Console;
    // 対象とランタイムは同じ非信頼taskであり、この変数を隠すことが隔離ではない。
    // 権限の上限は、Nedがtaskへ渡したcapabilityとサービス側の検査が決める。
    output->console = L4Re::Env::env()->get_cap<L4::Vcon>("linux_stdout");
    process.filesystem->root->capability = L4Re::Env::env()->get_cap<L4Re::Namespace>("linux_files");
    process.filesystem->root->immutable = immutable_files;
    space.memory = L4Re::Env::env()->get_cap<L4Re::Mem_alloc>("linux_memory");
    if (audit) {
        describe_initial_capabilities();
        // 型が既知のruntime ABIだけを渡す。不明な名前付きcapへallocatorのIPCを送らない。
        describe_memory_allocators({{"mem_alloc", L4Re::Env::env()->mem_alloc()},
                                    {"linux_memory", space.memory},
                                    {"linux_process", L4Re::Env::env()->get_cap<L4Re::Mem_alloc>("linux_process")}});
    }
    auto description = std::make_shared<File_description>();
    description->object = output;
    process.files->entries[1].description = description;
    process.files->entries[2].description = description;
    // fd表以外に参照を残すと、最後のcloseでもファイル実体を解放できない。
    description.reset();
    output.reset();
    std::printf("[zcomp-run] Phase 1: Runtime ready; output=%s\n",
                process.files->get(1)->object->console.is_valid() ? "available" : "unavailable");
    load_elf(thread, argv[guest_index], placement_min);
    std::puts("[zcomp-run] Phase 2: Linux ELF loaded and scanned");
    uintptr_t stack = prepare_stack(space, argc - guest_index, argv + guest_index);
    prepare_trampoline(space);
    std::puts("[zcomp-run] Phase 3: Initial stack and trampoline ready");
    for (auto &region : space.regions)
        region->publish();
    // ELFの内容はprivateな写像へ配置済み。起動ROMをゲストの実行中まで保持しない。
    drop_startup_capability("rom", audit);
    std::puts("[zcomp-run] Phase 4: Entering Linux ELF");
    register_thread(thread);
    bind_execution(thread.execution);
    std::printf("[zcomp-run] TLS: method=%s fallback=kernel-api threads=1\n",
                thread.execution.guest_fs_selector ? "gdt-selectors" : "kernel-api");
    long status = zcomp_enter(&thread.execution, space.entry(), stack);
    unbind_execution();
    finish_runtime();
    status = process.exit_status;
    std::printf("[zcomp-run] Guest exited: status=%ld calls=%llu writes=%llu\n", status,
                static_cast<unsigned long long>(counters.calls),
                static_cast<unsigned long long>(counters.writes));
    std::printf("[zcomp-run] Fast calls: getpid_cached=%llu\n",
                static_cast<unsigned long long>(counters.cached_getpids));
    std::printf("[zcomp-run] Resource calls: openat=%llu read=%llu close=%llu mmap=%llu munmap=%llu\n",
                static_cast<unsigned long long>(counters.opens),
                static_cast<unsigned long long>(counters.reads),
                static_cast<unsigned long long>(counters.closes),
                static_cast<unsigned long long>(counters.mmaps),
                static_cast<unsigned long long>(counters.munmaps));
    std::printf("[zcomp-run] Memory reuse: hits=%llu evictions=%llu\n",
                static_cast<unsigned long long>(counters.mmap_reuses),
                static_cast<unsigned long long>(counters.mmap_evictions));
    std::printf("[zcomp-run] Libc calls: arch_prctl=%llu set_tid_address=%llu writev=%llu ioctl=%llu\n",
                static_cast<unsigned long long>(counters.arch_prctls),
                static_cast<unsigned long long>(counters.tid_sets),
                static_cast<unsigned long long>(counters.writevs),
                static_cast<unsigned long long>(counters.ioctls));
    std::printf("[zcomp-run] File calls: fstat=%llu lseek=%llu pread64=%llu readv=%llu open=%llu\n",
                static_cast<unsigned long long>(counters.stats),
                static_cast<unsigned long long>(counters.seeks),
                static_cast<unsigned long long>(counters.preads),
                static_cast<unsigned long long>(counters.readvs),
                static_cast<unsigned long long>(counters.legacy_opens));
    std::printf("[zcomp-run] Protection calls: mprotect=%llu\n",
                static_cast<unsigned long long>(counters.mprotects));
    std::printf("[zcomp-run] Process calls: clone=%llu wait4=%llu\n",
                static_cast<unsigned long long>(counters.clones),
                static_cast<unsigned long long>(counters.waits));
    std::printf("[zcomp-run] Lifecycle calls: waitid=%llu futex=%llu signals=%llu\n",
                static_cast<unsigned long long>(counters.waitids),
                static_cast<unsigned long long>(counters.futexes),
                static_cast<unsigned long long>(counters.signals));
    // ゲストは自身のtaskを壊せる。ここへの正常復帰は、互換性の確認であって隔離の証明ではない。
    return static_cast<int>(status);
}
