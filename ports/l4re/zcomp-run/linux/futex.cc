#include "lifecycle.h"
#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstring>

namespace Zcomp {
namespace {
struct Waiter {
    Address_space *space;
    uintptr_t address;
    uint32_t bits;
    bool awakened = false;
};
std::vector<Waiter *> waiters;
struct Linux_time { int64_t seconds, nanoseconds; };

int wake(Address_space *space, uintptr_t address, int count, uint32_t bits)
{
    int woken = 0;
    for (auto waiter : waiters) {
        if (woken == count) break;
        if (!waiter->awakened && waiter->space == space && waiter->address == address
            && (waiter->bits & bits)) { waiter->awakened = true; ++woken; }
    }
    if (woken) runtime_notify();
    return woken;
}
}

void wake_futex(Thread_state &thread, uintptr_t address)
{ wake(thread.process->address_space.get(), address, INT_MAX, UINT32_MAX); }

long futex_call(Thread_state &thread, Registers const &r)
{
    auto &space = *thread.process->address_space;
    if ((r.rdi & 3) || !space.readable(r.rdi, 4)) return r.rdi & 3 ? -EINVAL : -EFAULT;
    if (r.rsi & ~uint64_t(127 | 128 | 256)) return -ENOSYS;
    unsigned command = r.rsi & 127;
    bool bitset = command == 9 || command == 10;
    uint32_t bits = bitset ? uint32_t(r.r9) : UINT32_MAX;
    if (!bits) return -EINVAL;
    if ((r.rsi & 256) && command != 9) return -ENOSYS;
    // 非共有VM間の共有mappingはまだないため、現在の鍵はAddress_spaceと仮想番地で一意。
    if (command == 1 || command == 10) {
        if (int32_t(r.rdx) < 0) return -EINVAL;
        return wake(&space, r.rdi, int32_t(r.rdx), bits);
    }
    if (command == 3 || command == 4) {
        if ((r.r8 & 3) || !space.readable(r.r8, 4)) return r.r8 & 3 ? -EINVAL : -EFAULT;
        if (r.r8 == r.rdi || int32_t(r.rdx) < 0 || int32_t(r.r10) < 0) return -EINVAL;
        if (command == 4 && __atomic_load_n(reinterpret_cast<uint32_t const *>(r.rdi), __ATOMIC_SEQ_CST)
                            != uint32_t(r.r9)) return -EAGAIN;
        int changed = wake(&space, r.rdi, int32_t(r.rdx), UINT32_MAX);
        int moved = 0;
        // muslのcondvarは起床済みwaiterが次のwaiterをmutexへ移す。WAKEだけでは連鎖が止まる。
        for (auto waiter : waiters) {
            if (moved == int32_t(r.r10)) break;
            if (!waiter->awakened && waiter->space == &space && waiter->address == r.rdi) {
                waiter->address = r.r8;
                ++moved;
            }
        }
        return changed + moved;
    }
    if (command != 0 && command != 9) return -ENOSYS;
    timespec deadline{};
    bool timed = r.r10;
    if (timed) {
        if (!space.readable(r.r10, sizeof(Linux_time))) return -EFAULT;
        Linux_time time;
        std::memcpy(&time, reinterpret_cast<void const *>(r.r10), sizeof(time));
        if (time.seconds < 0 || time.nanoseconds < 0 || time.nanoseconds >= 1000000000) return -EINVAL;
        timespec now;
        clock_gettime(CLOCK_REALTIME, &now);
        if (command == 0) {
            if (time.seconds > INT64_MAX - now.tv_sec - 1) return -EINVAL;
            deadline.tv_sec = now.tv_sec + time.seconds;
            deadline.tv_nsec = now.tv_nsec + time.nanoseconds;
        } else if (r.rsi & 256) {
            deadline.tv_sec = time.seconds; deadline.tv_nsec = time.nanoseconds;
        } else {
            timespec monotonic;
            clock_gettime(CLOCK_MONOTONIC, &monotonic);
            if (time.seconds > INT64_MAX - now.tv_sec - 1) return -EINVAL;
            deadline.tv_sec = now.tv_sec + time.seconds - monotonic.tv_sec;
            deadline.tv_nsec = now.tv_nsec + time.nanoseconds - monotonic.tv_nsec;
        }
        if (deadline.tv_nsec >= 1000000000) { ++deadline.tv_sec; deadline.tv_nsec -= 1000000000; }
        if (deadline.tv_nsec < 0) { --deadline.tv_sec; deadline.tv_nsec += 1000000000; }
    }
    // 値の照合と待機登録を同じmutex内で行い、WAKEとの間の取りこぼしを防ぐ。
    if (__atomic_load_n(reinterpret_cast<uint32_t const *>(r.rdi), __ATOMIC_SEQ_CST) != uint32_t(r.rdx))
        return -EAGAIN;
    Waiter waiter{&space, r.rdi, bits};
    waiters.push_back(&waiter);
    long result = 0;
    while (!waiter.awakened) {
        if (thread.process->group_exiting || signal_ready(thread)) { result = -EINTR; break; }
        int error = timed ? runtime_wait_until(deadline) : (runtime_wait(), 0);
        if (error == ETIMEDOUT && !waiter.awakened) { result = -ETIMEDOUT; break; }
    }
    waiters.erase(std::remove(waiters.begin(), waiters.end(), &waiter), waiters.end());
    return result;
}
}
