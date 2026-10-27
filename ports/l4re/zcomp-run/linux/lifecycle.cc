#include "lifecycle.h"
#include "identity.h"
#include <l4/re/env>
#include <l4/re/protocols.h>
#include <l4/sys/ipc.h>
#include <l4/sys/utcb.h>
#include <pthread-l4.h>
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>

namespace Zcomp {
pthread_mutex_t runtime_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t runtime_changed = PTHREAD_COND_INITIALIZER;
void runtime_lock() { pthread_mutex_lock(&runtime_mutex); }
void runtime_unlock() { pthread_mutex_unlock(&runtime_mutex); }
void runtime_wait() { pthread_cond_wait(&runtime_changed, &runtime_mutex); }
int runtime_wait_until(timespec const &deadline)
{ return pthread_cond_timedwait(&runtime_changed, &runtime_mutex, &deadline); }
void runtime_notify() { pthread_cond_broadcast(&runtime_changed); }

namespace {
struct Watched_child {
    // Linux側でreapしても、native backendが子孫へ供給中のcapを早期に取り消さない。
    std::shared_ptr<Process_state> process;
    std::shared_ptr<Child_task> child;
};
std::vector<Watched_child> watched;
pthread_t receiver_id;
L4::Cap<L4::Thread> receiver_cap;
bool receiver_started = false, receiver_stopping = false;
std::weak_ptr<Process_state> native_process;

bool parent_dead(Process_state const &process)
{
    if (!process.family || !process.parent_pid) return false;
    auto bits = reinterpret_cast<uint32_t const *>(process.family->ids.data) + 1;
    return __atomic_load_n(bits + process.parent_pid / 32, __ATOMIC_ACQUIRE)
           & (uint32_t(1) << (process.parent_pid % 32));
}

void send_up(long protocol, l4_umword_t const *words, unsigned count)
{
    std::memcpy(l4_utcb_mr()->mr, words, count * sizeof(*words));
    auto tag = l4_ipc_call(L4Re::Env::env()->parent().cap(), l4_utcb(),
                          l4_msgtag(protocol, count, 0, 0), L4_IPC_NEVER);
    if (l4_msgtag_has_error(tag)) fail("Cannot forward a process lifecycle event");
}

void adopt(std::shared_ptr<Child_task> const &child)
{
    // 再親子付け後は元のclone終了signalによらず、initの通常のwait対象へ揃える。
    child->clone_child = false;
    auto root = native_process.lock();
    if (root && root->pid == 1) {
        bool present = false;
        for (auto const &record : root->children) if (record->pid == child->pid) present = true;
        if (!present) root->children.push_back(child);
        if (auto local = child->local_process.lock()) {
            local->parent = root; local->parent_pid = 1;
        }
        if (child->exited) child_exited(*root, *child, child->status, child->termination_signal);
    } else {
        l4_umword_t words[] = {child->pid, l4_umword_t(child->status), l4_umword_t(child->termination_signal),
                              l4_umword_t(child->clone_child) | (l4_umword_t(child->exited) << 1)};
        send_up(Adopt_protocol, words, 4);
    }
    runtime_notify();
}

void forwarded_exit(uint32_t pid, int status, int signal)
{
    auto root = native_process.lock();
    if (root && root->pid == 1) {
        for (auto const &record : root->children)
            if (record->pid == pid) { child_exited(*root, *record, status, signal); break; }
    } else {
        l4_umword_t words[] = {pid, l4_umword_t(status), l4_umword_t(signal)};
        send_up(Forward_exit_protocol, words, 3);
    }
}

void *receive_exits(void *)
{
    runtime_lock();
    receiver_cap = L4::Cap<L4::Thread>(pthread_l4_cap(pthread_self()));
    runtime_notify();
    runtime_unlock();
    for (;;) {
        l4_umword_t label = 0;
        auto tag = l4_ipc_wait(l4_utcb(), &label,
            l4_timeout(L4_IPC_TIMEOUT_NEVER, l4_timeout_from_us(100000)));
        // mutex取得もnative IPCを使う。受信直後に退避しないと、競合時だけ終了status等が壊れる。
        l4_umword_t incoming[L4_UTCB_GENERIC_DATA_SIZE];
        std::memcpy(incoming, l4_utcb_mr()->mr, sizeof(incoming));
        runtime_lock();
        if (receiver_stopping) { runtime_unlock(); return nullptr; }
        if (l4_msgtag_has_error(tag)) { runtime_unlock(); continue; }
        std::shared_ptr<Child_task> child;
        std::shared_ptr<Process_state> parent;
        for (auto i = watched.begin(); i != watched.end();) {
            auto candidate = i->child;
            auto owner = i->process;
            if ((uintptr_t(candidate->pid) << 2) == (label & ~uintptr_t(3))) {
                child = candidate; parent = owner;
            }
            ++i;
        }
        auto mr = incoming;
        bool exiting = false;
        std::shared_ptr<Child_task> orphan;
        uint32_t forward_pid = 0;
        int forward_status = 0, forward_signal = 0;
        if (child && l4_msgtag_label(tag) == Fork_ready_protocol && l4_msgtag_words(tag) == 1) {
            child->ready = mr[0] == 0;
        } else if (child && l4_msgtag_label(tag) == Guest_exit_protocol && l4_msgtag_words(tag) == 2) {
            if (parent->exited) {
                child->status = mr[0]; child->termination_signal = mr[1]; child->exited = true;
                forward_pid = child->pid; forward_status = child->status; forward_signal = child->termination_signal;
            } else child_exited(*parent, *child, mr[0], mr[1]);
        } else if (child && l4_msgtag_label(tag) == Adopt_protocol && l4_msgtag_words(tag) == 4) {
            orphan = std::make_shared<Child_task>();
            orphan->pid = mr[0]; orphan->status = mr[1]; orphan->termination_signal = mr[2];
            orphan->clone_child = mr[3] & 1; orphan->exited = mr[3] & 2; orphan->indirect = true;
        } else if (child && l4_msgtag_label(tag) == Forward_exit_protocol && l4_msgtag_words(tag) == 3) {
            // 転送中のIPCは同じUTCBを使うので、入力をCの値へ退避してから上へ送る。
            forward_pid = mr[0]; forward_status = mr[1]; forward_signal = mr[2];
        } else if (child && l4_msgtag_label(tag) == L4RE_PROTO_PARENT
                   && l4_msgtag_words(tag) == 3 && !mr[0] && !mr[1]) {
            if (!child->exited) {
                // guest終了をnative通知へ揃えた子も、親guestが先に消えた場合はPID 1へ転送する。
                if (parent->exited) {
                    child->status = mr[2] & 255; child->termination_signal = 0; child->exited = true;
                    forward_pid = child->pid; forward_status = child->status;
                } else child_exited(*parent, *child, mr[2] & 255);
            }
            exiting = true;
        } else if (child && l4_msgtag_label(tag) == File_fault_protocol && l4_msgtag_words(tag) >= 1) {
            unsigned count = l4_msgtag_words(tag);
            if (!mr[0]) child->file_faults.clear();
            else if (mr[0] == 1 && !((count - 1) % 3) && child->file_faults.size() + (count - 1) / 3 <= Max_mappings) {
                for (unsigned i = 1; i + 2 < count; i += 3)
                    if (mr[i] >= Page_size && mr[i] < mr[i + 1] && mr[i + 1] <= User_address_end
                        && !(mr[i + 2] & ~(PF_R | PF_W | PF_X)))
                        child->file_faults.push_back({mr[i], mr[i + 1], unsigned(mr[i + 2])});
            }
        } else if (child && l4_msgtag_label(tag) == L4_PROTO_EXCEPTION) {
            auto exception = reinterpret_cast<l4_exc_regs_t const *>(incoming);
            int signal = exception->trapno == 6 ? 4 : exception->trapno == 0 ? 8 : 11;
            if (exception->trapno == 14) {
                // EOFまで到達できる保護があるアクセスだけがSIGBUS。W禁止やNXはSIGSEGVのまま。
                unsigned required = exception->err & 2 ? PF_W : exception->err & 16 ? PF_X : PF_R;
                for (auto const &range : child->file_faults)
                    if (exception->pfa >= range.first && exception->pfa < range.last
                        && (range.flags & required)) signal = 7;
            }
            std::printf("[zcomp-process] event=exception pid=%u trap=%lu pc=%#lx signal=%d\n",
                        child->pid, exception->trapno, l4_utcb_exc_pc(exception), signal);
            child_exited(*parent, *child, 0, signal);
            exiting = true;
        } else {
            std::printf("[zcomp-process] event=invalid-notification label=%#lx protocol=%ld\n",
                        label, l4_msgtag_label(tag));
        }
        l4_utcb_mr()->mr[0] = 0;
        l4_ipc_reply(L4_INVALID_CAP, l4_utcb(), l4_msgtag(0, 1, 0, 0), L4_IPC_NEVER);
        // 上位へcallする前に現在の送信元へreplyし、暗黙reply先を入れ子IPCで失わない。
        if (orphan) adopt(orphan);
        if (forward_pid) forwarded_exit(forward_pid, forward_status, forward_signal);
        // guest終了とnative backend終了は別。孤児へ供給中の資源を前者だけで取り消さない。
        if (exiting) {
            child->stop();
            watched.erase(std::remove_if(watched.begin(), watched.end(),
                [&](auto const &record) { return record.child == child; }), watched.end());
        }
        runtime_notify();
        runtime_unlock();
    }
}
}

long create_native_thread(pthread_t *id, void *(*entry)(void *), void *argument)
{
    pthread_attr_t attributes;
    pthread_attr_init(&attributes);
    pthread_attr_setstacksize(&attributes, 65536);
    int error = pthread_create(id, &attributes, entry, argument);
    pthread_attr_destroy(&attributes);
    return error ? -error : 0;
}

void register_thread(Thread_state &thread)
{
    if (native_process.expired()) native_process = thread.process;
    auto &threads = thread.process->threads;
    if (std::find(threads.begin(), threads.end(), &thread) == threads.end()) {
        threads.push_back(&thread);
        ++thread.process->address_space->execution_threads;
    }
    thread.refresh_getpid_cache();
}

void publish_file_faults(Thread_state &thread)
{
    auto native = native_process.lock();
    // rootや共有Taskの個別signal配送はまだない。非共有子の親通知経路だけで終了理由を分類する。
    if ((!native && thread.process->pid == 1) || (native && native->pid == 1)) return;
    auto &space = *thread.process->address_space;
    std::vector<File_fault_range> ranges;
    for (auto const &span : space.mappings.spans)
        if (span.backing->file && span.flags && span.mapped_size() < span.size)
            ranges.push_back({span.address + span.mapped_size(), span.end(), span.flags});
    if (ranges == space.reported_file_faults) return;
    l4_umword_t clear = 0;
    send_up(File_fault_protocol, &clear, 1);
    // UTCBの容量を超えずに公開する。親へ通知を完了してからguestへ戻る。
    for (size_t i = 0; i < ranges.size();) {
        l4_umword_t words[33]; words[0] = 1;
        unsigned count = 1;
        while (i < ranges.size() && count + 3 <= 33) {
            words[count++] = ranges[i].first; words[count++] = ranges[i].last;
            words[count++] = ranges[i++].flags;
        }
        send_up(File_fault_protocol, words, count);
    }
    space.reported_file_faults = std::move(ranges);
}

uint32_t allocate_tid(Process_state &process, long *error)
{
    *error = 0;
    if (!process.family) {
        auto memory = L4Re::Env::env()->get_cap<L4Re::Mem_alloc>("linux_process");
        if (!memory.is_valid()) { *error = -EACCES; return 0; }
        auto family = std::make_shared<Process_family>();
        family->memory = memory;
        long result = family->ids.allocate(Page_size, memory);
        if (result < 0) { *error = -ENOMEM; return 0; }
        *reinterpret_cast<uint32_t *>(family->ids.data) = 2;
        process.family = std::move(family);
    }
    auto ids = reinterpret_cast<uint32_t *>(process.family->ids.data);
    uint32_t id = __atomic_load_n(ids, __ATOMIC_RELAXED);
    do {
        if (id < 2 || id >= (Page_size / sizeof(uint32_t) - 1) * 32) { *error = -EAGAIN; return 0; }
    } while (!__atomic_compare_exchange_n(ids, &id, id + 1, false, __ATOMIC_RELAXED, __ATOMIC_RELAXED));
    return id;
}

L4::Cap<L4::Thread> child_receiver()
{
    if (!receiver_started) {
        long error = create_native_thread(&receiver_id, receive_exits, nullptr);
        if (error < 0) return L4::Cap<L4::Thread>::Invalid;
        receiver_started = true;
    }
    while (!receiver_cap.is_valid()) runtime_wait();
    return receiver_cap;
}

void register_child(std::shared_ptr<Process_state> const &process,
                    std::shared_ptr<Child_task> const &child)
{ watched.push_back({process, child}); }

void unregister_child(std::shared_ptr<Child_task> const &child)
{
    watched.erase(std::remove_if(watched.begin(), watched.end(),
        [&](auto const &record) { return record.child == child; }), watched.end());
}

uint32_t parent_pid(Process_state const &process)
{ return parent_dead(process) ? 1 : process.parent_pid; }

void process_exited(Thread_state &thread)
{
    auto &process = *thread.process;
    process.exited = true;
    if (process.family) {
        auto bits = reinterpret_cast<uint32_t *>(process.family->ids.data) + 1;
        __atomic_fetch_or(bits + process.pid / 32, uint32_t(1) << (process.pid % 32), __ATOMIC_RELEASE);
    }
    // Linuxの親は既に終了した。native backendだけ残し、子の親子関係はPID 1へ移す。
    auto children = std::move(process.children);
    for (auto const &child : children) adopt(child);
    auto native = native_process.lock();
    if (native.get() == &process && process.pid != 1) {
        // 孤児へ資源を供給する場合だけguest終了を先に知らせる。それ以外はnative終了通知に揃え、
        // wait直後のforkが前のTask/Thread/FPU状態と一時的に重なってkernel quotaを使い切らないようにする。
        if (!watched.empty() || process.address_space->execution_threads) {
            l4_umword_t words[] = {l4_umword_t(process.exit_status), 0};
            send_up(Guest_exit_protocol, words, 2);
        }
    } else if (auto parent = process.parent.lock()) {
        if (auto child = process.parent_record.lock()) {
            if (parent->exited) forwarded_exit(child->pid, process.exit_status, 0);
            else child_exited(*parent, *child, process.exit_status);
        }
    }
}

void drain_native_children()
{ while (!watched.empty()) runtime_wait(); }

void child_exited(Process_state &parent, Child_task &child, int status, int signal)
{
    child.status = status;
    child.termination_signal = signal;
    child.exited = true;
    if (!child.clone_child) {
        auto const &action = parent.signal_actions->entries[17];
        if (action.handler != 1 && !(parent.pending_signals & (uint64_t(1) << 16))) {
            parent.pending_signals |= uint64_t(1) << 16;
            parent.child_info = {};
            parent.child_info.signo = 17; parent.child_info.code = signal ? 2 : 1;
            parent.child_info.uid = Guest_uid;
            parent.child_info.pid = child.pid; parent.child_info.status = signal ? signal : status;
        }
        // SIG_DFLと明示的なSIG_IGNは異なる。後者とNOCLDWAITだけはzombieを残さない。
        if (action.handler == 1 || (action.flags & 2)) {
            parent.children.erase(std::remove_if(parent.children.begin(), parent.children.end(),
                [&](auto const &record) { return record.get() == &child; }), parent.children.end());
        }
    }
    // 受信Threadからの通知でも、getpidだけを繰り返す親に次の安全点を作る。
    for (auto thread : parent.threads) thread->refresh_getpid_cache();
    runtime_notify();
}

namespace {
long collect_child(Thread_state &thread, int32_t wanted, uint64_t options,
                   uintptr_t output, bool info)
{
    auto &process = *thread.process;
    auto &space = *process.address_space;
    constexpr uint64_t Wait_clone = 0x80000000, Wait_all = 0x40000000, Nowait = 0x1000000;
    if (wanted != -1 && wanted <= 0) return -EOPNOTSUPP;
    if (output && !space.writable(output, info ? sizeof(Child_info) : sizeof(int))) return -EFAULT;
    for (;;) {
        bool found = false;
        for (auto i = process.children.begin(); i != process.children.end(); ++i) {
            auto child = *i;
            if (wanted != -1 && uint32_t(wanted) != child->pid) continue;
            if (!(options & Wait_all) && child->clone_child != bool(options & Wait_clone)) continue;
            found = true;
            if (!child->exited) continue;
            if (output) {
                if (info) {
                    Child_info result{};
                    result.signo = 17; result.code = child->termination_signal ? 2 : 1;
                    result.pid = child->pid;
                    result.uid = Guest_uid;
                    result.status = child->termination_signal ? child->termination_signal : child->status;
                    std::memcpy(reinterpret_cast<void *>(output), &result, sizeof(result));
                } else {
                    int status = child->termination_signal ? child->termination_signal : child->status << 8;
                    std::memcpy(reinterpret_cast<void *>(output), &status, sizeof(status));
                }
            }
            long pid = child->pid;
            if (!(options & Nowait)) process.children.erase(i);
            return info ? 0 : pid;
        }
        if (!found) return -ECHILD;
        if (options & 1) {
            if (info && output) {
                Child_info empty{};
                std::memcpy(reinterpret_cast<void *>(output), &empty, sizeof(empty));
            }
            return 0;
        }
        if (!thread.exited && (process.group_exiting || signal_ready(thread))) return -EINTR;
        // どのnative Threadからでも同じzombie表を待てる。IPC受信先とLinux親を同一視しない。
        runtime_wait();
    }
}
}

long wait_child(Thread_state &thread, Registers const &r)
{
    if (r.rdx & ~(uint64_t(1) | 0xc0000000) || r.r10) return -EOPNOTSUPP;
    return collect_child(thread, int32_t(r.rdi), r.rdx, r.rsi, false);
}

long wait_child_id(Thread_state &thread, Registers const &r)
{
    // 停止・再開とrusageは未実装。通常終了だけをWEXITEDとして観測する。
    if (r.rdi != 0 && r.rdi != 1) return -EOPNOTSUPP;
    if (!(r.r10 & 4) || (r.r10 & ~(uint64_t(1 | 4 | 0x1000000) | 0xc0000000))) return -EINVAL;
    if (r.r8) return -EOPNOTSUPP;
    if (r.rdi == 1 && (!r.rsi || r.rsi > INT32_MAX)) return -EINVAL;
    return collect_child(thread, r.rdi == 0 ? -1 : int32_t(r.rsi), r.r10, r.rdx, true);
}

void finish_receiver()
{
    runtime_lock();
    bool started = receiver_started;
    receiver_stopping = true;
    runtime_unlock();
    if (started) pthread_join(receiver_id, nullptr);
}
}
