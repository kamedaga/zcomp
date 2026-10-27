#pragma once

#include "runtime.h"
#include <l4/re/util/unique_cap>
#include <l4/sys/factory>
#include <l4/sys/thread>
#include <l4/sys/ipc_gate>

namespace Zcomp {
// ローカルの一時写像とCapabilityの寿命をまとめ、失敗経路でも回収する。
struct Local_dataspace {
    ~Local_dataspace();
    L4Re::Util::Unique_cap<L4Re::Dataspace> cap = L4Re::Util::make_unique_cap<L4Re::Dataspace>();
    unsigned char *data = nullptr;
    size_t size = 0;
    long allocate(size_t bytes, L4::Cap<L4Re::Mem_alloc> allocator);
    long attach(size_t bytes, L4Re::Rm::Flags flags, size_t offset = 0);
    long detach();
};

struct Shared_offset {
    struct Value { uint32_t locked; size_t offset; };
    Local_dataspace page;
    Value &value() { return *reinterpret_cast<Value *>(page.data); }
};
struct Process_family {
    Local_dataspace ids;
    L4::Cap<L4Re::Mem_alloc> memory;
};

struct Child_task {
    // Threadを先に停止し、消えたTaskのmappingへ復帰する競合を防いでから供給元を解放する。
    ~Child_task();
    uint32_t pid = 0;
    bool ready = false, exited = false, clone_child = false;
    bool indirect = false;
    std::weak_ptr<Process_state> local_process;
    int status = 0;
    int termination_signal = 0;
    l4_cap_idx_t next_cap = 0x20000;
    L4Re::Util::Unique_del_cap<L4::Task> task = L4Re::Util::make_unique_del_cap<L4::Task>();
    L4Re::Util::Unique_del_cap<L4::Thread> thread = L4Re::Util::make_unique_del_cap<L4::Thread>();
    L4Re::Util::Unique_del_cap<L4Re::Rm> rm = L4Re::Util::make_unique_del_cap<L4Re::Rm>();
    L4Re::Util::Unique_del_cap<L4::Ipc_gate> parent = L4Re::Util::make_unique_del_cap<L4::Ipc_gate>();
    std::vector<std::unique_ptr<Local_dataspace>> storage;
    std::vector<l4re_env_cap_entry_t> named_caps;
    std::vector<std::shared_ptr<File_description>> inherited_files;
    // 未処理のfile EOF faultをSIGSEGVと区別するための、子から更新される互換性用情報。
    std::vector<File_fault_range> file_faults;
    long create(L4::Cap<L4Re::Mem_alloc> memory);
    long map_cap(L4::Cap<void> source, l4_cap_idx_t destination, L4_cap_fpage_rights rights);
    long add_cap(L4::Cap<void> source, L4_cap_fpage_rights rights, l4_cap_idx_t *destination);
    long add_named(char const *name, L4::Cap<void> source, L4_cap_fpage_rights rights);
    long start(L4::Cap<L4Re::Mem_alloc> memory);
    void stop();
};

constexpr long Fork_ready_protocol = 0x5a43;
constexpr long Guest_exit_protocol = 0x5a44;
constexpr long Adopt_protocol = 0x5a45;
constexpr long Forward_exit_protocol = 0x5a46;
constexpr long File_fault_protocol = 0x5a47;
long clone_process(Thread_state &thread, Registers const &registers);
long wait_child(Thread_state &thread, Registers const &registers);
int restore_fork_child();
}
