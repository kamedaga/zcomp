#include "state.h"

extern "C" unsigned long long shim_call_count()
{
    uintptr_t address;
    __asm__ volatile("mov %%gs:8, %0" : "=r"(address) :: "memory");
    auto context = reinterpret_cast<Zcomp::Execution_context *>(address);
    // 同じTask内なので実カウンタを直接観測できる。観測用syscallや固定offsetの複製は足さない。
    // getpidの高速入口は通常ディスパッチまで集計されないため、未集計分も含める。
    return __atomic_load_n(&context->thread->process->counters.calls, __ATOMIC_RELAXED)
           + __atomic_load_n(&context->anchor[5], __ATOMIC_RELAXED);
}
