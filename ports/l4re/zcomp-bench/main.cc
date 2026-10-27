#include "bench_measure.h"
#include <l4/re/env>
#include <l4/re/namespace>
#include <l4/re/dataspace>
#include <l4/re/mem_alloc>
#include <l4/re/rm>
#include <l4/re/util/cap_alloc>
#include <l4/re/util/unique_cap>
#include <l4/sys/segment.h>
#include <pthread.h>
#include <cstring>

namespace {
uintptr_t native_fs;
L4::Cap<L4Re::Dataspace> file;
L4::Cap<L4Re::Namespace> files;
L4::Cap<L4Re::Mem_alloc> memory;
L4Re::Util::Unique_cap<L4Re::Dataspace> reusable;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void fs_pair(uint64_t n)
{
    for (uint64_t i = 0; i < n; ++i) {
        bench_require(fiasco_amd64_set_fs(L4_INVALID_CAP, native_fs, l4_utcb()) == 0, "native FS set");
        bench_require(fiasco_amd64_set_fs(L4_INVALID_CAP, native_fs, l4_utcb()) == 0, "native FS restore");
    }
}
void mutex_pair(uint64_t n)
{
    for (uint64_t i = 0; i < n; ++i) {
        bench_require(pthread_mutex_lock(&mutex) == 0, "native mutex lock");
        bench_require(pthread_mutex_unlock(&mutex) == 0, "native mutex unlock");
    }
}
void fx_pair(uint64_t n)
{
    alignas(16) unsigned char state[512]{};
    for (uint64_t i = 0; i < n; ++i)
        // 同じ状態を連続して復元するため、compilerのXMM値を途中で変更しない。
        __asm__ volatile("fxsave64 %0; fxrstor64 %0" : "+m"(state) :: "memory");
}
void ds_info(uint64_t n)
{
    L4Re::Dataspace::Stats stats{};
    for (uint64_t i = 0; i < n; ++i) bench_require(file->info(&stats) == 0, "native dataspace info");
    bench_require(stats.size >= 8, "native file size");
    bench_sink = stats.size;
}
void query_drop(uint64_t n)
{
    auto cap = L4Re::Util::cap_alloc.alloc<L4Re::Dataspace>();
    bench_require(cap.is_valid(), "native cap slot");
    for (uint64_t i = 0; i < n; ++i) {
        bench_require(files->query("public.txt", cap, 0) == 0, "native namespace query");
        // 受領capだけを外し、公開元のDataspaceやnamespaceを取り消さない。
        bench_require(l4_error(L4Re::Env::env()->task()->unmap(cap.fpage(), L4_FP_ALL_SPACES)) == 0,
                      "native cap drop");
    }
    L4Re::Util::cap_alloc.free(cap);
}
void alloc_map_unmap(uint64_t n)
{
    auto env = L4Re::Env::env();
    for (uint64_t i = 0; i < n; ++i) {
        auto cap = L4Re::Util::cap_alloc.alloc<L4Re::Dataspace>();
        bench_require(cap.is_valid() && memory->alloc(4096, cap) == 0
                      && cap->allocate(0, 4096) == 0, "native memory allocation");
        unsigned char *mapped = nullptr;
        bench_require(env->rm()->attach(&mapped, 4096,
            L4Re::Rm::F::Search_addr | L4Re::Rm::F::RW | L4Re::Rm::F::No_eager_map,
            L4::Ipc::make_cap(cap, L4_CAP_FPAGE_RW)) == 0, "native memory attach");
        uintptr_t start = reinterpret_cast<uintptr_t>(mapped);
        bench_require(cap->map_region(0, L4Re::Dataspace::F::RW, start, start + 4096) == 0,
                      "native memory map");
        *static_cast<volatile unsigned char *>(mapped) = 42;
        bench_require(env->rm()->detach(mapped, nullptr) >= 0, "native memory detach");
        L4Re::Util::cap_alloc.free(cap, L4Re::This_task, L4_FP_ALL_SPACES);
    }
}

void reuse_map_unmap(uint64_t n)
{
    auto env = L4Re::Env::env();
    for (uint64_t i = 0; i < n; ++i) {
        unsigned char *mapped = nullptr;
        bench_require(env->rm()->attach(&mapped, 4096,
            L4Re::Rm::F::Search_addr | L4Re::Rm::F::RW | L4Re::Rm::F::No_eager_map,
            L4::Ipc::make_cap(reusable.get(), L4_CAP_FPAGE_RW)) == 0, "native reused attach");
        uintptr_t start = reinterpret_cast<uintptr_t>(mapped);
        bench_require(reusable->map_region(0, L4Re::Dataspace::F::RW, start, start + 4096) == 0,
                      "native reused map");
        // 再利用後の匿名ページもゼロ初期化が必要。解除や接触を省略した対照にはしない。
        std::memset(mapped, 0, 4096);
        *static_cast<volatile unsigned char *>(mapped) = 42;
        bench_require(env->rm()->detach(mapped, nullptr) >= 0, "native reused detach");
    }
}

void profile_memory()
{
    static char const *const names[] = {"mem_cap_slot", "mem_create", "mem_allocate", "mem_attach",
        "mem_map", "mem_touch", "mem_detach", "mem_cap_free"};
    auto env = L4Re::Env::env();
    constexpr unsigned Stages = sizeof(names) / sizeof(names[0]);
    constexpr uint64_t Iterations = 250;
    alloc_map_unmap(26);
    for (unsigned sample = 0; sample < Bench_samples; ++sample) {
        uint64_t totals[Stages]{};
        for (uint64_t i = 0; i < Iterations; ++i) {
            uint64_t ticks = bench_tsc();
            auto cap = L4Re::Util::cap_alloc.alloc<L4Re::Dataspace>();
            uint64_t next = bench_tsc(); totals[0] += next - ticks; ticks = next;
            bench_require(cap.is_valid(), "profile capability slot");
            long result = memory->alloc(4096, cap);
            next = bench_tsc(); totals[1] += next - ticks; ticks = next;
            bench_require(result == 0, "profile dataspace creation");
            result = cap->allocate(0, 4096);
            next = bench_tsc(); totals[2] += next - ticks; ticks = next;
            bench_require(result == 0, "profile physical allocation");
            unsigned char *mapped = nullptr;
            result = env->rm()->attach(&mapped, 4096,
                L4Re::Rm::F::Search_addr | L4Re::Rm::F::RW | L4Re::Rm::F::No_eager_map,
                L4::Ipc::make_cap(cap, L4_CAP_FPAGE_RW));
            next = bench_tsc(); totals[3] += next - ticks; ticks = next;
            bench_require(result == 0, "profile region attach");
            uintptr_t start = reinterpret_cast<uintptr_t>(mapped);
            result = cap->map_region(0, L4Re::Dataspace::F::RW, start, start + 4096);
            next = bench_tsc(); totals[4] += next - ticks; ticks = next;
            bench_require(result == 0, "profile dataspace map");
            *static_cast<volatile unsigned char *>(mapped) = 42;
            next = bench_tsc(); totals[5] += next - ticks; ticks = next;
            result = env->rm()->detach(mapped, nullptr);
            next = bench_tsc(); totals[6] += next - ticks; ticks = next;
            bench_require(result >= 0, "profile region detach");
            L4Re::Util::cap_alloc.free(cap, L4Re::This_task, L4_FP_ALL_SPACES);
            next = bench_tsc(); totals[7] += next - ticks;
        }
        for (unsigned stage = 0; stage < Stages; ++stage)
            bench_record_ticks(names[stage], sample, Iterations, totals[stage]);
    }
}
}
int main()
{
    __asm__ volatile("mov %%fs:0, %0" : "=r"(native_fs));
    files = L4Re::Env::env()->get_cap<L4Re::Namespace>("bench_files");
    memory = L4Re::Env::env()->get_cap<L4Re::Mem_alloc>("bench_memory");
    file = L4Re::Util::cap_alloc.alloc<L4Re::Dataspace>();
    bench_require(memory.is_valid() && files.is_valid() && file.is_valid() && files->query("public.txt", file, 0) == 0,
                  "native fixture");
    bench_run("integer", 10000000, bench_integer);
    bench_run("fs_pair", 20000, fs_pair);
    bench_run("mutex_pair", 20000, mutex_pair);
    bench_run("fx_pair", 20000, fx_pair);
    bench_run("ds_info", 20000, ds_info);
    bench_run("query_drop", 1000, query_drop);
    // guest側の固定番地予約・alias作成を含まない対照で、バックエンド自体の確保経路を分ける。
    bench_run("alloc_map_unmap", 250, alloc_map_unmap);
    profile_memory();
    reusable = L4Re::Util::make_unique_cap<L4Re::Dataspace>();
    bench_require(reusable.is_valid() && memory->alloc(4096, reusable.get()) == 0
                  && reusable->allocate(0, 4096) == 0, "native reused allocation");
    bench_run("reuse_map_unmap", 250, reuse_map_unmap);
    reusable.reset();
    L4Re::Util::cap_alloc.free(file, L4Re::This_task, L4_FP_ALL_SPACES);
    bench_report("native");
    return 0;
}
