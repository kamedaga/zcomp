#include "lifecycle.h"
#include <cerrno>
#include <cstring>

namespace Zcomp {
namespace {
constexpr uint64_t Chld = uint64_t(1) << 16;
constexpr uint64_t Unmaskable = (uint64_t(1) << 8) | (uint64_t(1) << 18);
struct Guest_stack { uint64_t pointer; int32_t flags, padding; uint64_t size; };
struct Guest_mcontext { uint64_t registers[23], fpregs, reserved[8]; };
struct Guest_ucontext {
    uint64_t flags, link;
    Guest_stack stack;
    Guest_mcontext machine;
    uint64_t mask[16];
};
struct Signal_frame {
    uint64_t restorer;
    Guest_ucontext context;
    Child_info info;
    // frame基点が8 mod 16なので、FXSAVEの内容はコピーで出し入れする。
    unsigned char fx[512];
};
static_assert(offsetof(Guest_ucontext, machine) == 40 && offsetof(Guest_ucontext, mask) == 296,
              "Linux amd64のucontext配置と一致する必要があります。");

void save_registers(Registers const &r, uint64_t *g, uintptr_t rsp, uintptr_t rip)
{
    uint64_t values[] = {r.r8, r.r9, r.r10, r.r11, r.r12, r.r13, r.r14, r.r15,
        r.rdi, r.rsi, r.rbp, r.rbx, r.rdx, r.rax, r.rcx, rsp, rip, r.flags, 0x33, 0, 0, 0, 0};
    std::memcpy(g, values, sizeof(values));
}
void load_registers(uint64_t const *g, Registers &r)
{
    r.r8=g[0]; r.r9=g[1]; r.r10=g[2]; r.r11=g[3]; r.r12=g[4]; r.r13=g[5]; r.r14=g[6]; r.r15=g[7];
    r.rdi=g[8]; r.rsi=g[9]; r.rbp=g[10]; r.rbx=g[11]; r.rdx=g[12]; r.rax=g[13]; r.rcx=g[14]; r.flags=g[17];
}
}

bool signal_ready(Thread_state const &thread)
{
    return (thread.process->pending_signals & ~thread.signal_mask & Chld)
        && thread.process->signal_actions->entries[17].handler > 1;
}

long signal_call(Thread_state &thread, Registers const &r)
{
    auto &process = *thread.process;
    auto &space = *process.address_space;
    if (r.rax == 13) {
        if (!r.rdi || r.rdi > 64 || r.rdi == 9 || r.rdi == 19 || r.r10 != 8) return -EINVAL;
        if (r.rdx && !space.writable(r.rdx, sizeof(Signal_action))) return -EFAULT;
        Signal_action next{};
        if (r.rsi) {
            if (!space.readable(r.rsi, sizeof(next))) return -EFAULT;
            std::memcpy(&next, reinterpret_cast<void const *>(r.rsi), sizeof(next));
            constexpr uint64_t Supported = 1 | 2 | 4 | 0x04000000 | 0x10000000 | 0x40000000 | 0x80000000;
            if (next.flags & ~Supported) return -EOPNOTSUPP;
        }
        auto &action = process.signal_actions->entries[r.rdi];
        if (r.rdx) std::memcpy(reinterpret_cast<void *>(r.rdx), &action, sizeof(action));
        if (r.rsi) {
            action = next;
            if (r.rdi == 17 && next.handler == 1) process.pending_signals &= ~Chld;
        }
        return 0;
    }
    if (r.rax == 14) {
        if (r.r10 != 8) return -EINVAL;
        if (r.rdx && !space.writable(r.rdx, 8)) return -EFAULT;
        uint64_t mask = 0;
        if (r.rsi) {
            if (!space.readable(r.rsi, 8)) return -EFAULT;
            if (r.rdi > 2) return -EINVAL;
            std::memcpy(&mask, reinterpret_cast<void const *>(r.rsi), 8);
        }
        if (r.rdx) std::memcpy(reinterpret_cast<void *>(r.rdx), &thread.signal_mask, 8);
        if (r.rsi) {
            if (r.rdi == 0) thread.signal_mask |= mask;
            else if (r.rdi == 1) thread.signal_mask &= ~mask;
            else thread.signal_mask = mask;
            thread.signal_mask &= ~Unmaskable;
        }
        return 0;
    }
    if (r.rax == 127) {
        if (r.rsi != 8) return -EINVAL;
        if (!space.writable(r.rdi, 8)) return -EFAULT;
        uint64_t pending = process.pending_signals & thread.signal_mask;
        std::memcpy(reinterpret_cast<void *>(r.rdi), &pending, 8);
        return 0;
    }
    if (r.rax == 128) {
        if (r.r10 != 8) return -EINVAL;
        if (!space.readable(r.rdi, 8) || (r.rsi && !space.writable(r.rsi, sizeof(Child_info)))) return -EFAULT;
        uint64_t set;
        std::memcpy(&set, reinterpret_cast<void const *>(r.rdi), 8);
        if (set & ~Chld) return -EOPNOTSUPP;
        timespec deadline{};
        if (r.rdx) {
            struct Time { int64_t seconds, nanoseconds; } time;
            if (!space.readable(r.rdx, sizeof(time))) return -EFAULT;
            std::memcpy(&time, reinterpret_cast<void const *>(r.rdx), sizeof(time));
            if (time.seconds < 0 || time.nanoseconds < 0 || time.nanoseconds >= 1000000000) return -EINVAL;
            clock_gettime(CLOCK_REALTIME, &deadline);
            if (time.seconds > INT64_MAX - deadline.tv_sec - 1) return -EINVAL;
            deadline.tv_sec += time.seconds; deadline.tv_nsec += time.nanoseconds;
            if (deadline.tv_nsec >= 1000000000) { ++deadline.tv_sec; deadline.tv_nsec -= 1000000000; }
        }
        while (!(process.pending_signals & set)) {
            if (process.group_exiting || signal_ready(thread)) return -EINTR;
            if (r.rdx) { if (runtime_wait_until(deadline) == ETIMEDOUT) return -EAGAIN; }
            else runtime_wait();
        }
        if (r.rsi) std::memcpy(reinterpret_cast<void *>(r.rsi), &process.child_info, sizeof(Child_info));
        process.pending_signals &= ~Chld;
        return 17;
    }
    return -ENOSYS;
}

void deliver_signal(Thread_state &thread, Registers &r)
{
    auto &process = *thread.process;
    if (!(process.pending_signals & ~thread.signal_mask & Chld)) return;
    auto action = process.signal_actions->entries[17];
    process.pending_signals &= ~Chld;
    if (action.handler <= 1) return;
    auto &execution = thread.execution;
    uintptr_t original_rsp = execution.guest_rsp + 8;
    uintptr_t original_rip = *reinterpret_cast<uint64_t const *>(execution.guest_rsp);
    if (original_rsp < sizeof(Signal_frame) + 160) fail("Guest signal stack underflow");
    uintptr_t address = ((original_rsp - 128 - sizeof(Signal_frame)) & ~uintptr_t(15)) - 8;
    if (!process.address_space->writable(address - 8, sizeof(Signal_frame) + 8)
        || !process.address_space->accessible(action.handler, 1, PF_X)
        || !process.address_space->accessible(action.restorer, 1, PF_X)) fail("Invalid guest signal frame");
    Signal_frame frame{};
    frame.context.stack.flags = 2;
    frame.restorer = action.restorer;
    frame.info = process.child_info;
    frame.context.mask[0] = thread.signal_mask;
    save_registers(r, frame.context.machine.registers, original_rsp, original_rip);
    frame.context.machine.fpregs = address + offsetof(Signal_frame, fx);
    std::memcpy(frame.fx, reinterpret_cast<unsigned char const *>(&r) - 512, 512);
    std::memcpy(reinterpret_cast<void *>(address), &frame, sizeof(frame));
    thread.signal_frames.push_back(address);
    thread.signal_mask |= action.mask;
    if (!(action.flags & 0x40000000)) thread.signal_mask |= Chld;
    if (action.flags & 0x80000000) process.signal_actions->entries[17] = {};
    r.rdi = 17; r.rsi = address + offsetof(Signal_frame, info);
    r.rdx = address + offsetof(Signal_frame, context); r.rax = 0;
    r.flags &= ~uint64_t(0x400);
    execution.guest_rsp = address - 8;
    std::memcpy(reinterpret_cast<void *>(execution.guest_rsp), &action.handler, 8);
}

long restore_signal(Thread_state &thread, Registers &r)
{
    uintptr_t address = thread.execution.guest_rsp;
    auto &space = *thread.process->address_space;
    if (thread.signal_frames.empty() || thread.signal_frames.back() != address
        || !space.readable(address, sizeof(Signal_frame))) return -EFAULT;
    Signal_frame frame;
    std::memcpy(&frame, reinterpret_cast<void const *>(address), sizeof(frame));
    auto g = frame.context.machine.registers;
    if (g[15] < 8 || !space.writable(g[15] - 8, 8) || !space.accessible(g[16], 1, PF_X)) return -EFAULT;
    uint32_t mxcsr;
    std::memcpy(&mxcsr, frame.fx + 24, 4);
    if (mxcsr & ~uint32_t(0xffff)) return -EINVAL;
    load_registers(g, r);
    thread.execution.guest_rsp = g[15] - 8;
    std::memcpy(reinterpret_cast<void *>(thread.execution.guest_rsp), &g[16], 8);
    thread.signal_mask = frame.context.mask[0] & ~Unmaskable;
    // カーネルに依存する拡張xstateではなく、現在の入口と同じx87/XMM範囲を復元する。
    std::memcpy(reinterpret_cast<unsigned char *>(&r) - 512, frame.fx, 512);
    thread.signal_frames.pop_back();
    return r.rax;
}
}
