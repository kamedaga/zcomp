#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

enum { Threads = 2, Iterations = 100 };
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
static unsigned ready, start, counter;
static long process, tids[Threads];
static _Thread_local unsigned tls_value = 7;

static void require(int ok, char const *step)
{
    if (!ok) { fprintf(stderr, "FAIL: pthread %s (errno=%d)\n", step, errno); _exit(1); }
}

static void *worker(void *argument)
{
    unsigned id = (uintptr_t)argument;
    require(tls_value == 7 && getpid() == process, "initial TLS and shared PID");
    tids[id] = syscall(SYS_gettid);
    tls_value = id + 100;
    require(pthread_mutex_lock(&lock) == 0, "worker lock");
    ++ready;
    require(pthread_cond_broadcast(&condition) == 0, "notify ready");
    while (!start) require(pthread_cond_wait(&condition, &lock) == 0, "wait start");
    require(pthread_mutex_unlock(&lock) == 0, "worker unlock");
    for (unsigned i = 0; i < Iterations; ++i) {
        require(pthread_mutex_lock(&lock) == 0, "counter lock");
        ++counter;
        require(pthread_mutex_unlock(&lock) == 0, "counter unlock");
        require(syscall(SYS_sched_yield) == 0 && tls_value == id + 100, "private TLS after yield");
    }
    return (void *)(uintptr_t)(id + 10);
}

int main(void)
{
    process = getpid();
    pthread_attr_t attributes;
    // 大きい既定stackで資源枠を増やさず、小さい枠でも別TLSと同期を検査する。
    require(pthread_attr_init(&attributes) == 0 && pthread_attr_setstacksize(&attributes, 65536) == 0,
            "thread attributes");
    pthread_t threads[Threads];
    for (unsigned i = 0; i < Threads; ++i)
        require(pthread_create(&threads[i], &attributes, worker, (void *)(uintptr_t)i) == 0, "create");
    require(pthread_attr_destroy(&attributes) == 0 && pthread_mutex_lock(&lock) == 0, "main lock");
    while (ready != Threads) require(pthread_cond_wait(&condition, &lock) == 0, "wait ready");
    start = 1;
    require(pthread_cond_broadcast(&condition) == 0 && pthread_mutex_unlock(&lock) == 0, "start workers");
    for (unsigned i = 0; i < Threads; ++i) {
        void *result;
        require(pthread_join(threads[i], &result) == 0 && (uintptr_t)result == i + 10, "join");
        require(tids[i] > 0 && tids[i] != process, "worker TID");
    }
    require(tids[0] != tids[1] && counter == Threads * Iterations && tls_value == 7, "shared counter and private TLS");
    require(pthread_mutex_destroy(&lock) == 0 && pthread_cond_destroy(&condition) == 0, "destroy synchronization");
    puts("PASS: Pthread create/join, private TLS, mutex, condition variable, and futex.");
    return 0;
}
