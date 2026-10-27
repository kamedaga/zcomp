#pragma once

#include "entry_context.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

namespace Zcomp {
constexpr size_t Max_files = 16;
constexpr size_t Max_fds = 3 + Max_files;
struct File_object;
struct Address_space;
struct Fs_context;
struct Shared_offset;
struct Process_family;
struct Child_task;
struct Signal_action { uint64_t handler = 0, flags = 0, restorer = 0, mask = 0; };
struct Signal_actions { std::array<Signal_action, 65> entries{}; };
struct Child_info {
    int32_t signo = 0, error = 0, code = 0, padding = 0;
    uint32_t pid = 0, uid = 0;
    int32_t status = 0, padding2 = 0;
    uint64_t user_time = 0, system_time = 0;
    unsigned char unused[80]{};
};
static_assert(sizeof(Child_info) == 128, "Linux x86-64のsiginfo配置と一致する必要があります。");

// 別々のopenは別記述を作る。fd表を複製した場合は同じ記述を参照し、位置を共有する。
struct File_description {
    std::shared_ptr<File_object> object;
    size_t offset = 0;
    std::shared_ptr<Shared_offset> shared_offset;
    size_t &position();
};

// CLOEXECはファイル記述ではなくfdの属性なので、表の複製後は独立して変更できる。
struct Fd_entry {
    std::shared_ptr<File_description> description;
    bool close_on_exec = false;
};

struct Fd_table {
    std::array<Fd_entry, Max_fds> entries{};

    File_description *get(uint32_t fd) const
    {
        return fd < entries.size() ? entries[fd].description.get() : nullptr;
    }
};

struct Syscall_counters {
    uint64_t calls = 0, writes = 0;
    uint64_t cached_getpids = 0;
    uint64_t clones = 0, waits = 0;
    uint64_t waitids = 0, futexes = 0, signals = 0;
    uint64_t opens = 0, reads = 0, closes = 0, mmaps = 0, munmaps = 0;
    uint64_t mmap_reuses = 0, mmap_evictions = 0;
    uint64_t stats = 0, seeks = 0, preads = 0, readvs = 0, legacy_opens = 0;
    uint64_t mprotects = 0;
    uint64_t arch_prctls = 0, tid_sets = 0, writevs = 0, ioctls = 0;
};

// Linuxのプロセス（thread group）。ジョブ制御のprocess groupとは別の単位。
// files/filesystemは起動時の既定参照。実行中のsyscallはThread_stateの参照を使う。
// VM・fd表・FSの共有指定を一つのboolへまとめない。
struct Process_state {
    uint32_t pid = 1;
    uint32_t parent_pid = 0;
    std::shared_ptr<Address_space> address_space;
    std::shared_ptr<Fd_table> files = std::make_shared<Fd_table>();
    std::shared_ptr<Fs_context> filesystem;
    Syscall_counters counters;
    std::shared_ptr<Process_family> family;
    std::vector<std::shared_ptr<Child_task>> children;
    std::shared_ptr<Signal_actions> signal_actions = std::make_shared<Signal_actions>();
    std::vector<struct Thread_state *> threads;
    uint64_t pending_signals = 0;
    Child_info child_info;
    std::weak_ptr<Process_state> parent;
    std::weak_ptr<Child_task> parent_record;
    bool group_exiting = false;
    int group_status = 0;
    int exit_status = 0;
    bool exited = false;
};

struct Thread_state {
    explicit Thread_state(std::shared_ptr<Process_state> owner, uint32_t id = 1)
    : process(std::move(owner)), files(process->files), filesystem(process->filesystem), tid(id)
    {
        execution.thread = this;
    }
    // execution.threadが自分を指すため、オブジェクトを移動して参照を無効化しない。
    Thread_state(Thread_state const &) = delete;
    Thread_state &operator=(Thread_state const &) = delete;
    std::shared_ptr<Process_state> process;
    // CLONE_THREADでもFILES/FS共有は別指定なので、group所属だけで共有を強制しない。
    std::shared_ptr<Fd_table> files;
    std::shared_ptr<Fs_context> filesystem;
    uint32_t tid;
    // native IPCやTLSの途中では破棄しない。停止用IPと、その前の復帰先をスレッド別に保持する。
    uintptr_t native_thread = 0;
    uintptr_t parked_ip = 0;
    uintptr_t clear_child_tid = 0;
    uint64_t signal_mask = 0;
    std::vector<uintptr_t> signal_frames;
    bool exited = false;
    int exit_status = 0;
    Execution_context execution;

    void refresh_getpid_cache()
    {
        // pendingがmasked/defaultでも保守的に通常経路へ戻す。配送条件の二重実装を避ける。
        // 呼出元は起動前かruntime mutex内。別Threadの入口による読出しとはatomicに同期する。
        uintptr_t pid = !exited && !process->group_exiting && !process->pending_signals ? process->pid : 0;
        __atomic_store_n(&execution.anchor[4], pid, __ATOMIC_RELEASE);
    }

    void collect_cached_calls()
    {
        // 実行中の他Threadからは呼ばない。通常入口か自身の終了経路でだけ統計を移す。
        process->counters.calls += execution.anchor[5];
        process->counters.cached_getpids += execution.anchor[5];
        execution.anchor[5] = 0;
    }
};
}
