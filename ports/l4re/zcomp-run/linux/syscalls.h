#pragma once

#include <cstdint>

namespace Zcomp {
struct Thread_state;
struct Registers;

// Linux ABIの入口をまとめ、起動処理やRegionの実装にsyscall固有の宣言を混在させない。
long open_file(Thread_state &thread, Registers const &registers);
long read_file(Thread_state &thread, Registers const &registers);
long pread_file(Thread_state &thread, Registers const &registers);
long seek_file(Thread_state &thread, Registers const &registers);
long stat_file(Thread_state &thread, Registers const &registers);
long stat_path(Thread_state &thread, Registers const &registers);
long access_file(Thread_state &thread, Registers const &registers);
long read_vector(Thread_state &thread, Registers const &registers);
long close_file(Thread_state &thread, uint64_t fd);
long map_memory(Thread_state &thread, Registers const &registers);
long unmap_memory(Thread_state &thread, Registers const &registers);
long protect_memory(Thread_state &thread, Registers const &registers);
long arch_prctl(Thread_state &thread, Registers const &registers);
extern "C" long zcomp_l4_dispatch(Registers *registers, Thread_state *thread);
}
