#pragma once
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <cpuid.h>

enum { Bench_samples = 7, Bench_capacity = 112 };
struct Bench_result { char const *name; unsigned sample; uint64_t iterations, ns, ticks; };
static struct Bench_result bench_results[Bench_capacity];
static unsigned bench_count;
static volatile uint64_t bench_sink;

static void bench_require(int valid, char const *message)
{
    if (!valid) { fprintf(stderr, "FAIL: benchmark %s\n", message); exit(1); }
}

static uint64_t bench_clock(void)
{
    struct timespec now;
    bench_require(clock_gettime(CLOCK_MONOTONIC, &now) == 0, "monotonic clock");
    return (uint64_t)now.tv_sec * 1000000000 + now.tv_nsec;
}

static uint64_t bench_tsc(void)
{
    uint32_t low, high;
    // TSCはCPUサイクル数ではない。前後の処理が測定区間を越えないよう順序を固定する。
    __asm__ volatile("mfence; lfence; rdtsc; lfence" : "=a"(low), "=d"(high) :: "memory");
    return ((uint64_t)high << 32) | low;
}

static void bench_integer(uint64_t iterations)
{
    uint64_t value = 1;
    for (uint64_t i = 0; i < iterations; ++i)
        // 同一ELFの算術ループを仮想化・スケジューリングの対照にし、コンパイラによる除去を防ぐ。
        __asm__ volatile("imul $1664525, %0, %0; add $1013904223, %0" : "+r"(value));
    bench_sink = value;
}

static void bench_run(char const *name, uint64_t iterations, void (*operation)(uint64_t))
{
    // ロード・最初のpage faultは除外する。出力も全測定が終わるまで行わない。
    operation(iterations / 10 + 1);
    for (unsigned sample = 0; sample < Bench_samples; ++sample) {
        uint64_t ns = bench_clock(), ticks = bench_tsc();
        operation(iterations);
        uint64_t end_ticks = bench_tsc(), end_ns = bench_clock();
        // KIP時計は割込み間で同じ値を返せる。0 nsを高速という結果へ読み替えず、生の値として残す。
        bench_require(end_ticks > ticks && end_ns >= ns, "clock moved backwards");
        bench_require(bench_count < Bench_capacity, "result capacity");
        struct Bench_result result = {name, sample, iterations, end_ns - ns, end_ticks - ticks};
        bench_results[bench_count++] = result;
    }
}

static inline void bench_record_ticks(char const *name, unsigned sample, uint64_t iterations, uint64_t ticks)
{
    // 分解測定は各段階のTSC差分を合算する。粗いKIP時計から架空の段階別nsを作らない。
    bench_require(ticks && bench_count < Bench_capacity, "split result capacity or timer");
    struct Bench_result result = {name, sample, iterations, 0, ticks};
    bench_results[bench_count++] = result;
}

static void bench_report(char const *suite)
{
    unsigned a, b, c, d;
    uint64_t hz = 0;
    if (__get_cpuid(0x15, &a, &b, &c, &d) && a && b && c) hz = (uint64_t)c * b / a;
    printf("BENCH_CLOCK suite=%s tsc_hz=%llu\n", suite, (unsigned long long)hz);
    for (unsigned i = 0; i < bench_count; ++i) {
        struct Bench_result const *r = &bench_results[i];
        printf("BENCH suite=%s name=%s sample=%u iterations=%llu ns=%llu ticks=%llu\n",
               suite, r->name, r->sample, (unsigned long long)r->iterations,
               (unsigned long long)r->ns, (unsigned long long)r->ticks);
    }
    printf("BENCH_DONE suite=%s samples=%u checksum=%llu\n", suite, bench_count,
           (unsigned long long)bench_sink);
}
