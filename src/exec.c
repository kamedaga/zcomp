#include "hook.h"

#include <errno.h>
#include <sys/mman.h>
#include <sys/syscall.h>

/* 壊れたenvpを無制限に走査しないためのプロトタイプ固有の上限。
 * LinuxのARG_MAXとは独立で、注入後の最終的な上限はカーネルも検査する。 */
enum { ENV_ENTRIES = 16384, ENV_BYTES = 2 * 1024 * 1024,
       ENV_STRING = 128 * 1024 };
struct exec_env {
    char *entries[ENV_ENTRIES + 3];
    char preload[ENV_STRING];
    char strings[ENV_BYTES];
};

static size_t length(const char *value)
{
    size_t n = 0;
    while (value[n])
        ++n;
    return n;
}

static int prefix(const char *value, const char *key)
{
    while (*key)
        if (*value++ != *key++)
            return 0;
    return 1;
}

static long copy_string(char *out, size_t capacity, uint64_t remote,
                        size_t *copied)
{
    size_t used = 0;
    while (used < capacity && used < ENV_STRING) {
        if (remote > UINT64_MAX - used)
            return -EFAULT;
        uint64_t address = remote + used;
        /* 終端の次のページが読めなくても有効な文字列を受け入れるため、
         * 1回のコピーではページ境界を越えない。直接のユーザーポインタ参照は避ける。 */
        size_t n = zcomp_page_size - (address & (zcomp_page_size - 1));
        if (n > capacity - used)
            n = capacity - used;
        if (n > ENV_STRING - used)
            n = ENV_STRING - used;
        if (address > UINT64_MAX - (n - 1))
            return -EFAULT;
        long error = zcomp_copy_user(out + used, address, n, 0);
        if (error)
            return error;
        for (size_t i = 0; i < n; ++i) {
            if (!out[used + i]) {
                *copied = used + i + 1;
                return 0;
            }
        }
        used += n;
    }
    return -E2BIG;
}

static int separator(char c)
{
    return c == ' ' || c == ':';
}

static long append_preloads(char *out, size_t *used, const char *value)
{
    size_t self_size = length(zcomp_preload_path);
    while (*value) {
        if (separator(*value)) {
            ++value;
            continue;
        }
        const char *token = value;
        while (*value && !separator(*value))
            ++value;
        size_t n = (size_t)(value - token);
        int self = n == self_size;
        for (size_t i = 0; self && i < n; ++i)
            self = token[i] == zcomp_preload_path[i];
        /* 自分だけは先頭に1回置く。他のライブラリの順序は変えない。 */
        if (self)
            continue;
        if (n + 2 > ENV_STRING - *used)
            return -E2BIG;
        out[(*used)++] = ':';
        for (size_t i = 0; i < n; ++i)
            out[(*used)++] = token[i];
    }
    out[*used] = 0;
    return 0;
}

static long prepare_env(struct exec_env *env, uint64_t remote)
{
    const char key[] = "LD_PRELOAD=";
    size_t preload_size = sizeof(key) - 1;
    for (size_t i = 0; i < preload_size; ++i)
        env->preload[i] = key[i];
    for (size_t i = 0; zcomp_preload_path[i]; ++i)
        env->preload[preload_size++] = zcomp_preload_path[i];
    env->preload[preload_size] = 0;

    size_t used = 0, count = 0;
    int trace_present = 0;
    for (size_t i = 0; remote; ++i) {
        if (remote > UINT64_MAX - i * sizeof(uint64_t) - 7)
            return -EFAULT;
        uint64_t string;
        long error = zcomp_copy_user(&string, remote + i * sizeof(string),
                                      sizeof(string), 0);
        if (error)
            return error;
        if (!string)
            break;
        if (i == ENV_ENTRIES)
            return -E2BIG;
        char *entry = env->strings + used;
        size_t size;
        error = copy_string(entry, ENV_BYTES - used, string, &size);
        if (error)
            return error;
        used += size;
        if (prefix(entry, key)) {
            error = append_preloads(env->preload, &preload_size,
                                    entry + sizeof(key) - 1);
            if (error)
                return error;
        } else {
            env->entries[count++] = entry;
            trace_present |= prefix(entry, "ZCOMP_TRACE=");
        }
    }
    env->entries[count++] = env->preload;
    /* 空のenvpでも実験ログを追えるようにするが、呼び出し側の明示的設定は尊重する。 */
    if (zcomp_trace && !trace_present)
        env->entries[count++] = "ZCOMP_TRACE=1";
    env->entries[count] = NULL;
    return 0;
}

static void note_attempt(long nr)
{
    /* 成功したexecは戻らないため、戻り値のログとは区別して試行を記録する。
     * libcの書式変換は再入と拡張レジスタ破壊を招くので使わない。 */
    const char execve[] = "[zcomp] nr=59 phase=attempt\n";
    const char execveat[] = "[zcomp] nr=322 phase=attempt\n";
    const char *line = nr == SYS_execve ? execve : execveat;
    size_t size = nr == SYS_execve ? sizeof(execve) - 1 : sizeof(execveat) - 1;
    zcomp_raw_syscall(SYS_write, 2, (long)line, size, 0, 0, 0);
}

long zcomp_exec(const struct zcomp_regs *r)
{
    /* 親のenviron・malloc・TLS・ロックを使わず、exec要求ごとの私有コピーを持つ。
     * 成功時は旧マッピングごと消え、失敗時だけここで回収できる。 */
    long allocation = zcomp_raw_syscall(SYS_mmap, 0, sizeof(struct exec_env),
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if ((unsigned long)allocation >= (unsigned long)-4095)
        return allocation;
    struct exec_env *env = (void *)(uintptr_t)allocation;
    long result = prepare_env(env, r->rax == SYS_execve ? r->rdx : r->r10);
    if (!result) {
        if (zcomp_trace)
            note_attempt(r->rax);
        if (r->rax == SYS_execve)
            result = zcomp_raw_syscall(SYS_execve, r->rdi, r->rsi,
                                       (long)env->entries, 0, 0, 0);
        else
            /* FD相対・AT_EMPTY_PATHの意味論を保持するため、パスへ変換しない。 */
            result = zcomp_raw_syscall(SYS_execveat, r->rdi, r->rsi, r->rdx,
                                       (long)env->entries, r->r8, 0);
    }
    zcomp_raw_syscall(SYS_munmap, allocation, sizeof(*env), 0, 0, 0, 0);
    return result;
}
