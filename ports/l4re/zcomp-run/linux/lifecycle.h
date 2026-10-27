#pragma once

#include "../task.h"
#include <l4/sys/types.h>
#include <pthread.h>
#include <ctime>

namespace Zcomp {
// 状態操作はこのmutexで直列化する。futex・wait・生成待ちでは必ず解放してから眠る。
extern pthread_mutex_t runtime_mutex;
extern pthread_cond_t runtime_changed;
void runtime_lock();
void runtime_unlock();
void runtime_wait();
int runtime_wait_until(timespec const &deadline);
void runtime_notify();
long create_native_thread(pthread_t *id, void *(*entry)(void *), void *argument);
void register_thread(Thread_state &thread);
void publish_file_faults(Thread_state &thread);
uint32_t allocate_tid(Process_state &process, long *error);
L4::Cap<L4::Thread> child_receiver();
void register_child(std::shared_ptr<Process_state> const &process, std::shared_ptr<Child_task> const &child);
void unregister_child(std::shared_ptr<Child_task> const &child);
uint32_t parent_pid(Process_state const &process);
void process_exited(Thread_state &thread);
void drain_native_children();
void child_exited(Process_state &parent, Child_task &child, int status, int signal = 0);
long clone_shared(Thread_state &thread, Registers const &registers);
void exit_thread(Thread_state &thread, int status, bool group);
extern "C" [[noreturn]] void zcomp_abort_thread(Thread_state *thread);
void finish_runtime();
void finish_receiver();
long futex_call(Thread_state &thread, Registers const &registers);
void wake_futex(Thread_state &thread, uintptr_t address);
long wait_child_id(Thread_state &thread, Registers const &registers);
long signal_call(Thread_state &thread, Registers const &registers);
bool signal_ready(Thread_state const &thread);
void deliver_signal(Thread_state &thread, Registers &registers);
long restore_signal(Thread_state &thread, Registers &registers);
}
