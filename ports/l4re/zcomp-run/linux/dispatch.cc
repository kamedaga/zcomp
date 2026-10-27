#include "../runtime.h"
#include "../task.h"
#include "lifecycle.h"
#include "identity.h"
#include <l4/sys/vcon.h>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstring>

namespace Zcomp {

static long write_output(Thread_state &thread, Registers const &r)
{
    auto &space = *thread.process->address_space;
    auto description = thread.files->get(static_cast<uint32_t>(r.rdi));
    if (!description || description->object->kind != File_object::Kind::Console)
        return -EBADF;
    // 既定のlogへのフォールバックは、明示的な出力権限の不足を隠してしまう。
    if (!description->object->console.is_valid())
        return -EACCES;
    if (r.rdx > LONG_MAX)
        return -EINVAL;
    if (!r.rdx)
        return 0;
    if (!space.readable(r.rsi, r.rdx))
        return -EFAULT;
    size_t written = 0;
    while (written < r.rdx) {
        size_t chunk = r.rdx - written;
        if (chunk > L4_VCON_WRITE_SIZE)
            chunk = L4_VCON_WRITE_SIZE;
        long result = l4_vcon_write(description->object->console.cap(),
            reinterpret_cast<char const *>(r.rsi + written), chunk);
        if (result < 0)
            return written ? static_cast<long>(written) : -EIO;
        if (!result)
            break;
        written += result;
    }
    return static_cast<long>(written);
}

static long write_vector(Thread_state &thread, Registers const &r)
{
    auto &space = *thread.process->address_space;
    // iovec自体もゲストのメモリであり、ネイティブABIのポインタとして盲目的に渡さない。
    struct Iovec { uint64_t base, size; };
    static_assert(sizeof(Iovec) == 16, "Linux x86-64のiovec配置と一致する必要があります。");
    Registers part = r;
    part.rdx = 0;
    long result = write_output(thread, part);
    if (result < 0)
        return result;
    if (r.rdx > 1024)
        return -EINVAL;
    if (!r.rdx)
        return 0;
    if (!space.readable(r.rsi, r.rdx * sizeof(Iovec)))
        return -EFAULT;
    uint64_t total = 0;
    for (uint64_t i = 0; i < r.rdx; ++i) {
        Iovec vector;
        std::memcpy(&vector, reinterpret_cast<void const *>(r.rsi + i * sizeof(Iovec)), sizeof(vector));
        if (vector.size > uint64_t(LONG_MAX) - total)
            return -EINVAL;
        total += vector.size;
        if (vector.size && !space.readable(vector.base, vector.size))
            return -EFAULT;
    }
    long written = 0;
    for (uint64_t i = 0; i < r.rdx; ++i) {
        Iovec vector;
        std::memcpy(&vector, reinterpret_cast<void const *>(r.rsi + i * sizeof(Iovec)), sizeof(vector));
        part.rsi = vector.base;
        part.rdx = vector.size;
        result = write_output(thread, part);
        if (result < 0)
            return written ? written : result;
        written += result;
        if (uint64_t(result) != vector.size)
            break;
    }
    return written;
}

static long ioctl_file(Thread_state &thread, uint64_t fd)
{
    auto description = thread.files->get(static_cast<uint32_t>(fd));
    if (!description)
        return -EBADF;
    if (description->object->kind == File_object::Kind::Console
        && !description->object->console.is_valid())
        return -EACCES;
    // Moe logとROM Dataspaceは端末ではない。成功を偽装せずstdioに非端末として扱わせる。
    return -ENOTTY;
}

static long dispatch_locked(Registers *r, Thread_state *current)
{
    auto &thread = *current;
    auto &space = *thread.process->address_space;
    auto &counters = thread.process->counters;
    ++counters.calls;
    switch (r->rax) {
    case 102:
    case 107:
        return Guest_uid;
    case 104:
    case 108:
        return Guest_gid;
    case 105:
        return set_guest_identity(r->rdi, Guest_uid);
    case 106:
        return set_guest_identity(r->rdi, Guest_gid);
    case 39:
        return thread.process->pid;
    case 56:
    case 57:
        ++counters.clones;
        return clone_process(thread, *r);
    case 61:
        ++counters.waits;
        return wait_child(thread, *r);
    case 247:
        ++counters.waitids;
        return wait_child_id(thread, *r);
    case 13:
    case 14:
    case 127:
    case 128:
        ++counters.signals;
        return signal_call(thread, *r);
    case 15:
        ++counters.signals;
        return restore_signal(thread, *r);
    case 202:
        ++counters.futexes;
        return futex_call(thread, *r);
    case 24:
        runtime_unlock();
        sched_yield();
        runtime_lock();
        return 0;
    case 228: {
        if (r->rdi != CLOCK_REALTIME && r->rdi != CLOCK_MONOTONIC) return -EINVAL;
        if (!space.writable(r->rsi, 16)) return -EFAULT;
        timespec now;
        if (clock_gettime(r->rdi, &now)) return -EIO;
        int64_t values[] = {now.tv_sec, now.tv_nsec};
        std::memcpy(reinterpret_cast<void *>(r->rsi), values, sizeof(values));
        return 0;
    }
    case 110:
        return parent_pid(*thread.process);
    case 95: {
        uint32_t old = thread.filesystem->umask;
        thread.filesystem->umask = r->rdi & 0777;
        return old;
    }
    case 0:
        ++counters.reads;
        return read_file(thread, *r);
    case 1:
        ++counters.writes;
        return write_output(thread, *r);
    case 2: {
        ++counters.legacy_opens;
        // 旧openの名前解決もopenatと同じ公開namespaceに限定し、別経路を作らない。
        Registers translated = *r;
        translated.rdi = static_cast<uint64_t>(-100);
        translated.rsi = r->rdi;
        translated.rdx = r->rsi;
        translated.r10 = r->rdx;
        return open_file(thread, translated);
    }
    case 3:
        ++counters.closes;
        return close_file(thread, r->rdi);
    case 5:
        ++counters.stats;
        return stat_file(thread, *r);
    case 4:
    case 6:
        ++counters.stats;
        return stat_path(thread, *r);
    case 21:
        return access_file(thread, *r);
    case 8:
        ++counters.seeks;
        return seek_file(thread, *r);
    case 9:
        ++counters.mmaps;
        return map_memory(thread, *r);
    case 10:
        ++counters.mprotects;
        return protect_memory(thread, *r);
    case 11:
        ++counters.munmaps;
        return unmap_memory(thread, *r);
    case 16:
        ++counters.ioctls;
        return ioctl_file(thread, r->rdi);
    case 17:
        ++counters.preads;
        return pread_file(thread, *r);
    case 19:
        ++counters.readvs;
        return read_vector(thread, *r);
    case 20:
        ++counters.writevs;
        return write_vector(thread, *r);
    case 158:
        ++counters.arch_prctls;
        return arch_prctl(thread, *r);
    case 186:
        // LinuxのTIDはnativeのCapability selectorやpthread識別子とは別物。
        return thread.tid;
    case 218:
        ++counters.tid_sets;
        thread.clear_child_tid = r->rdi;
        return thread.tid;
    case 257:
        ++counters.opens;
        return open_file(thread, *r);
    case 60:
    case 231:
        exit_thread(thread, r->rdi & 255, r->rax == 231);
        return 0;
    default:
        // Linux番号をそのままFiascoへ渡すと、全く別のカーネル操作になる。
        // 配布済みバイナリの失敗原因を特定できるよう、未対応番号を診断へ残す。
        std::printf("[zcomp-run] Unsupported Linux syscall: number=%llu\n",
                    static_cast<unsigned long long>(r->rax));
        return -ENOSYS;
    }
}

extern "C" long zcomp_l4_dispatch(Registers *r, Thread_state *current)
{
    runtime_lock();
    auto &thread = *current;
    thread.collect_cached_calls();
    if (thread.process->group_exiting) exit_thread(thread, thread.process->group_status, false);
    if (!thread.exited) {
        uint64_t number = r->rax;
        r->rax = dispatch_locked(r, current);
        if (thread.process->group_exiting && !thread.exited)
            exit_thread(thread, thread.process->group_status, false);
        if (!thread.exited) {
            // waitのSA_RESTARTはhandler復帰後に同じcallqを再実行する。futexのtimeout再計算とは分ける。
            if (int64_t(r->rax) == -EINTR && (number == 61 || number == 247) && signal_ready(thread)
                && (thread.process->signal_actions->entries[17].flags & 0x10000000)) {
                r->rax = number;
                *reinterpret_cast<uint64_t *>(thread.execution.guest_rsp) -= 2;
            }
            deliver_signal(thread, *r);
        }
    }
    // signal mask変更やrt_sigreturn後も、保留・終了状態を確認してから再び高速経路を許可する。
    thread.refresh_getpid_cache();
    long result = r->rax;
    runtime_unlock();
    // 非局所復帰でmutexの解放やC++の後始末を飛ばさないよう、入口への復帰は最後に行う。
    if (thread.exited) zcomp_finish(thread.exit_status);
    return result;
}
}
