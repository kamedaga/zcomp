#include "lifecycle.h"
#include <l4/sys/thread.h>
#include <elf.h>
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <cstdio>

namespace Zcomp {
namespace {
constexpr uint64_t Vm = 0x100, Fs = 0x200, Files = 0x400, Sighand = 0x800;
constexpr uint64_t Thread = 0x10000, Sysvsem = 0x40000, Settls = 0x80000;
constexpr uint64_t Parent_tid = 0x100000, Clear_tid = 0x200000, Child_tid = 0x1000000;
struct Worker {
    pthread_t native;
    std::unique_ptr<Thread_state> thread;
    bool completed = false;
};
std::vector<std::unique_ptr<Worker>> workers;
extern "C" void zcomp_park();
extern "C" void zcomp_abort();

void try_stop_guest(Thread_state &thread)
{
    auto cap = __atomic_load_n(&thread.native_thread, __ATOMIC_ACQUIRE);
    if (!cap) return;
    uintptr_t park = reinterpret_cast<uintptr_t>(zcomp_park);
    l4_addr_t ip = park, sp = ~0UL;
    l4_umword_t flags = 0;
    auto tag = l4_thread_ex_regs_ret(cap, &ip, &sp, &flags);
    if (l4_error(tag) < 0) fail("Cannot park a guest thread", l4_error(tag));
    if (ip != park) thread.parked_ip = ip;
    // Fiascoは例外IPC中の変更を成功扱いで無視し得る。停止の成立を読戻しで確認する。
    l4_addr_t observed = ~0UL; sp = ~0UL; flags = 0;
    tag = l4_thread_ex_regs_ret(cap, &observed, &sp, &flags);
    if (l4_error(tag) < 0) fail("Cannot inspect a parked guest thread", l4_error(tag));
    if (observed != park) return;
    auto &space = *thread.process->address_space;
    bool guest = thread.parked_ip < Page_size || space.accessible(thread.parked_ip, 1, PF_X);
    // 単なるIPの観測後に書換えると、その間にnative lockへ入れる。先に無副作用のループへ固定する。
    // native IPCをcancelしない。待機列やmutexの後始末は元の処理とsyscall安全点に任せる。
    uintptr_t destination = guest ? reinterpret_cast<uintptr_t>(zcomp_abort) : thread.parked_ip;
    tag = l4_thread_ex_regs(cap, destination, ~0UL, 0);
    if (l4_error(tag) < 0) fail("Cannot resume a parked guest thread", l4_error(tag));
    // 最後の変更も例外中なら無視されるため、parked_ipは次の試行まで保持する。
}

void stop_group(Thread_state &caller, int status)
{
    auto &process = *caller.process;
    process.group_exiting = true;
    process.group_status = status;
    // native入口の途中は強制破棄しないため、次のgetpidが終了用の通常入口へ進むようにする。
    for (auto thread : process.threads) thread->refresh_getpid_cache();
    for (;;) {
        bool remaining = false;
        for (auto thread : process.threads) {
            if (thread == &caller) continue;
            remaining = true;
            try_stop_guest(*thread);
        }
        if (!remaining) return;
        runtime_notify();
        // 同じmutexが必要な後始末へ実行権を渡す。yieldだけでは低優先度Threadを飢餓にし得る。
        // native復帰途中を観測した場合も再試行できるよう、通知待ちは短いtimeout付きにする。
        timespec deadline;
        clock_gettime(CLOCK_REALTIME, &deadline);
        deadline.tv_nsec += 1000000;
        if (deadline.tv_nsec >= 1000000000) { ++deadline.tv_sec; deadline.tv_nsec -= 1000000000; }
        runtime_wait_until(deadline);
    }
}

void *run_guest(void *argument)
{
    auto &worker = *static_cast<Worker *>(argument);
    auto &thread = *worker.thread;
    runtime_lock();
    bool skip = thread.process->group_exiting;
    if (skip) exit_thread(thread, thread.process->group_status, false);
    runtime_unlock();
    if (!skip) {
        bind_execution(thread.execution);
        zcomp_resume(&thread.execution);
        unbind_execution();
    }
    runtime_lock();
    worker.completed = true;
    runtime_notify();
    runtime_unlock();
    return nullptr;
}

void collect_workers()
{
    for (size_t i = 0; i < workers.size();) {
        if (!workers[i]->completed) { ++i; continue; }
        auto worker = std::move(workers[i]);
        workers.erase(workers.begin() + i);
        // nativeの終了処理にもCPUが必要。runtime mutexを持ったままjoinしない。
        runtime_unlock();
        pthread_join(worker->native, nullptr);
        runtime_lock();
    }
}
}

long clone_shared(Thread_state &parent, Registers const &r)
{
    uint64_t flags = r.rdi;
    constexpr uint64_t Supported = 255 | Vm | Fs | Files | Sighand | Thread | Sysvsem
                                 | Settls | Parent_tid | Clear_tid | Child_tid | 0x400000;
    if (flags & ~Supported) return -EOPNOTSUPP;
    if (!(flags & Vm) || ((flags & Thread) && !(flags & Sighand))) return -EINVAL;
    if ((flags & 255) != 0 && (flags & 255) != 17) return -EOPNOTSUPP;
    if ((flags & Thread) && (flags & 255)) return -EINVAL;
    auto &space = *parent.process->address_space;
    // 共有スタックで親子を復帰させると互いのフレームを上書きする。vforkは別経路が必要。
    if (!r.rsi) return -EINVAL;
    if (r.rsi < 8 || !space.writable(r.rsi - 8, 8)) return -EFAULT;
    if ((flags & Parent_tid) && !space.writable(r.rdx, 4)) return -EFAULT;
    if ((flags & Child_tid) && !space.writable(r.r10, 4)) return -EFAULT;
    if ((flags & Settls) && r.r8 >= 0x0000800000000000ULL) return -EPERM;
    collect_workers();
    if (workers.size() >= 32 || (!(flags & Thread) && parent.process->children.size() >= 32)) return -EAGAIN;
    long error;
    uint32_t tid = allocate_tid(*parent.process, &error);
    if (!tid) return error;
    auto process = parent.process;
    std::shared_ptr<Child_task> record;
    if (!(flags & Thread)) {
        process = std::make_shared<Process_state>();
        process->pid = tid; process->parent_pid = parent.process->pid;
        process->parent = parent.process;
        process->address_space = parent.process->address_space;
        process->family = parent.process->family;
        process->signal_actions = flags & Sighand ? parent.process->signal_actions
            : std::make_shared<Signal_actions>(*parent.process->signal_actions);
        record = std::make_shared<Child_task>();
        record->pid = tid; record->clone_child = !(flags & 255); record->ready = true;
        record->local_process = process;
        process->parent_record = record;
    }
    auto worker = std::make_unique<Worker>();
    worker->thread = std::make_unique<Thread_state>(process, tid);
    auto &thread = *worker->thread;
    thread.files = flags & Files ? parent.files : std::make_shared<Fd_table>(*parent.files);
    thread.filesystem = flags & Fs ? parent.filesystem : std::make_shared<Fs_context>(*parent.filesystem);
    if (!(flags & Thread)) { process->files = thread.files; process->filesystem = thread.filesystem; }
    thread.signal_mask = parent.signal_mask;
    thread.clear_child_tid = flags & Clear_tid ? r.r10 : 0;
    auto &execution = thread.execution;
    execution.guest_rsp = r.rsi - 8;
    execution.guest_fs = flags & Settls ? r.r8 : parent.execution.guest_fs;
    Registers child = r; child.rax = 0;
    child.rcx = *reinterpret_cast<uint64_t const *>(parent.execution.guest_rsp);
    child.r11 = r.flags;
    std::memcpy(reinterpret_cast<void *>(execution.guest_rsp), &child.rcx, 8);
    auto frame = execution.stack + sizeof(execution.stack) - sizeof(Registers);
    std::memcpy(frame, &child, sizeof(child));
    std::memcpy(frame - 512, reinterpret_cast<unsigned char const *>(&r) - 512, 512);
    register_thread(thread);
    error = create_native_thread(&worker->native, run_guest, worker.get());
    if (error < 0) {
        process->threads.erase(std::remove(process->threads.begin(), process->threads.end(), &thread), process->threads.end());
        --space.execution_threads;
        return error;
    }
    if (record) parent.process->children.push_back(record);
    // 子はruntime mutex取得まで待つので、TID公開と所有権の確立を先に完了できる。
    if (flags & Parent_tid) std::memcpy(reinterpret_cast<void *>(r.rdx), &tid, 4);
    if (flags & Child_tid) std::memcpy(reinterpret_cast<void *>(r.r10), &tid, 4);
    workers.push_back(std::move(worker));
    std::printf("[zcomp-clone] parent=%u child=%u vm=shared group=%s files=%s\n",
                parent.process->pid, tid, flags & Thread ? "shared" : "separate",
                flags & Files ? "shared" : "copied");
    return tid;
}

void exit_thread(Thread_state &thread, int status, bool group)
{
    auto &process = *thread.process;
    if (thread.exited) return;
    // 最初の終了要求を採用する。競合したexit_groupが互いの完了を待つ循環を作らない。
    if (group && !process.group_exiting) stop_group(thread, status);
    thread.exit_status = process.group_exiting ? process.group_status : status;
    thread.exited = true;
    thread.refresh_getpid_cache();
    thread.collect_cached_calls();
    if (thread.clear_child_tid && process.address_space->writable(thread.clear_child_tid, 4)) {
        __atomic_store_n(reinterpret_cast<int *>(thread.clear_child_tid), 0, __ATOMIC_RELEASE);
        wake_futex(thread, thread.clear_child_tid);
    }
    auto &threads = process.threads;
    threads.erase(std::remove(threads.begin(), threads.end(), &thread), threads.end());
    --process.address_space->execution_threads;
    // group leaderが先にexitしても、他スレッドのfd表は残す。独立した表はこの時点で解放する。
    if (process.files == thread.files) process.files.reset();
    if (process.filesystem == thread.filesystem) process.filesystem.reset();
    thread.files.reset();
    thread.filesystem.reset();
    // 最後の実行スレッドが消えるまでは、Linuxプロセスの終了を親へ通知しない。
    if (threads.empty()) {
        process.exit_status = thread.exit_status;
        process_exited(thread);
    }
    runtime_notify();
}

extern "C" [[noreturn]] void zcomp_abort_thread(Thread_state *thread)
{
    runtime_lock();
    exit_thread(*thread, thread->process->group_status, false);
    int status = thread->exit_status;
    runtime_unlock();
    // libpthreadの終了・join経路は飛ばさず、保存済みのnative呼出元へ戻す。
    zcomp_finish(status);
}

void finish_runtime()
{
    runtime_lock();
    // rootのSYS_exitも他スレッドを即破棄しない。停止後もnative Threadの回収完了まで待つ。
    for (;;) {
        bool running = false;
        for (auto const &worker : workers) if (!worker->completed) running = true;
        if (!running) break;
        runtime_wait();
    }
    collect_workers();
    drain_native_children();
    runtime_unlock();
    finish_receiver();
}
}
