#include <l4/re/env.h>
#include <l4/re/protocols.h>
#include <l4/sys/task.h>

/* L4ReのヘッダからABI定義だけを使い、攻撃操作はCRT・libc・L4Reライブラリに依存させない。
 * 既知のランタイム配置を持つ動的ELFから、shimを迂回するゲストである。 */
#ifndef ZCOMP_ENV_ADDRESS
#error ランタイムのl4re_global_envのアドレスをビルド時に指定してください
#endif

extern long linux_call(long number, long a1, long a2, long a3, long a4);
extern long native_call(l4_cap_idx_t destination, long tag);
extern unsigned char const *native_instruction_address(void);
extern unsigned long long shim_call_count(void);
extern void report_bypass_counts(unsigned long long, unsigned long long, unsigned long long, unsigned long long);

enum {
    Linux_read = 0, Linux_write = 1, Linux_close = 3,
    Linux_getpid = 39, Linux_exit = 60, Linux_gettid = 186, Linux_openat = 257,
    Linux_AT_FDCWD = -100, Linux_ENOENT = 2,
    File_length = 8,
    // この試験の既知の配置で、ゲストのmmap範囲とスタックの間にある空きページを使う。
    Map_address = 0x68000000
};
static l4_utcb_t *utcb;
static l4_cap_idx_t receive_slot;

static unsigned long length(char const *s)
{
    unsigned long n = 0;
    while (s[n])
        ++n;
    return n;
}

static int equal(char const *a, char const *b)
{
    while (*a && *a == *b) {
        ++a;
        ++b;
    }
    return *a == *b;
}

static void message(char const *s)
{
    unsigned long n = length(s);
    if (linux_call(Linux_write, 1, (long)s, n, 0) != (long)n)
        linux_call(Linux_exit, 2, 0, 0, 0);
}

static void require(int condition, char const *step, long result)
{
    if (condition)
        return;
    message("FAIL: ");
    message(step);
    message(" result=");
    char digits[32];
    unsigned n = 0;
    unsigned long magnitude = result < 0
        ? 0UL - (unsigned long)result : (unsigned long)result;
    do {
        digits[n++] = '0' + magnitude % 10;
        magnitude /= 10;
    } while (magnitude);
    if (result < 0)
        digits[n++] = '-';
    for (unsigned i = 0; i < n / 2; ++i) {
        char t = digits[i];
        digits[i] = digits[n - 1 - i];
        digits[n - 1 - i] = t;
    }
    digits[n] = 0;
    message(digits);
    message("\n");
    linux_call(Linux_exit, 1, 0, 0, 0);
    __builtin_trap();
}

static void check_bytes(char const *bytes, char const *expected)
{
    for (unsigned i = 0; i < File_length; ++i)
        require(bytes[i] == expected[i], "File contents do not match", i);
}

static void shim_file(char const *name, char const *expected, int allowed)
{
    long fd = linux_call(Linux_openat, Linux_AT_FDCWD, (long)name, 0, 0);
    if (!allowed) {
        require(fd == -Linux_ENOENT, "Shim exposed a hidden file or returned an unexpected error", fd);
        return;
    }
    require(fd >= 3, "Shim openat failed", fd);
    char bytes[File_length];
    long result = linux_call(Linux_read, fd, (long)bytes, sizeof(bytes), 0);
    require(result == File_length, "Shim read failed", result);
    check_bytes(bytes, expected);
    result = linux_call(Linux_close, fd, 0, 0, 0);
    require(result == 0, "Shim close failed", result);
}

static l4_msgtag_t invoke(l4_cap_idx_t destination, long protocol, unsigned words)
{
    l4_msgtag_t tag = l4_msgtag(protocol, words, 0, 0);
    tag.raw = native_call(destination, tag.raw);
    // 通信失敗をENOENTと扱うと、壊れたIPC経路を権限制限の成功と誤認する。
    require(!l4_msgtag_has_error(tag), "Native IPC transport failed", l4_utcb_tcr_u(utcb)->error);
    return tag;
}

static long cap_present(l4_cap_idx_t cap)
{
    l4_msg_regs_t *mr = l4_utcb_mr_u(utcb);
    mr->mr[0] = L4_TASK_CAP_INFO_OP;
    mr->mr[1] = cap;
    return l4_msgtag_label(invoke(L4RE_THIS_TASK_CAP, L4_PROTO_TASK, 2));
}

static void unmap(l4_fpage_t page)
{
    l4_msg_regs_t *mr = l4_utcb_mr_u(utcb);
    mr->mr[0] = L4_TASK_UNMAP_OP;
    // DELETE_OBJは使わない。取得した参照だけを捨て、サービスのオブジェクトを壊さない。
    mr->mr[1] = L4_FP_ALL_SPACES;
    mr->mr[2] = page.raw;
    long result = l4_msgtag_label(invoke(L4RE_THIS_TASK_CAP, L4_PROTO_TASK, 3));
    require(result == 0, "Native unmap failed", result);
}

static l4_cap_idx_t named_cap(l4re_env_t const *env, char const *name)
{
    for (l4re_env_cap_entry_t const *cap = env->caps; cap && cap->flags != ~0UL; ++cap)
        if (equal(cap->name, name))
            return cap->cap;
    require(0, "Required named capability is missing", -1);
    return L4_INVALID_CAP;
}

static long query(l4_cap_idx_t ns, char const *name)
{
    require(cap_present(receive_slot) == 0, "Native receive slot is occupied", receive_slot);
    l4_msg_regs_t *mr = l4_utcb_mr_u(utcb);
    l4_buf_regs_t *br = l4_utcb_br_u(utcb);
    // Namespace::queryのopcode(int)の後、unsigned long長を8バイト境界に置く。
    mr->mr[0] = 0;
    mr->mr[1] = length(name);
    char *data = (char *)&mr->mr[2];
    for (unsigned long i = 0; i < mr->mr[1]; ++i)
        data[i] = name[i];
    unsigned words = 2 + (mr->mr[1] + sizeof(long) - 1) / sizeof(long);
    br->bdr = 0;
    br->br[0] = receive_slot | L4_RCV_ITEM_SINGLE_CAP;
    br->br[1] = 0;
    l4_msgtag_t tag = invoke(ns, L4RE_PROTO_NAMESPACE, words);
    long result = l4_msgtag_label(tag);
    if (result == 0) {
        require(l4_msgtag_items(tag) == 1, "Namespace returned no capability item", tag.raw);
        require(cap_present(receive_slot) > 0, "Namespace returned an empty capability slot", receive_slot);
    } else {
        require(cap_present(receive_slot) == 0, "Failed query installed a capability", result);
    }
    return result;
}

static void native_file(l4_cap_idx_t ns, char const *name, char const *expected, int allowed)
{
    long result = query(ns, name);
    if (!allowed) {
        require(result == -L4_ENOENT, "Native IPC exposed a hidden file or returned an unexpected error", result);
        return;
    }
    require(result == 0, "Native namespace query failed", result);
    l4_msg_regs_t *mr = l4_utcb_mr_u(utcb);
    l4_buf_regs_t *br = l4_utcb_br_u(utcb);
    // Dataspace::mapのopcode=0。ページを直接受信し、shimのread/RMを利用せず内容を読む。
    mr->mr[0] = 0;
    mr->mr[1] = 0;
    mr->mr[2] = 0;
    mr->mr[3] = L4_FPAGE_RO;
    br->bdr = 0;
    br->br[0] = L4_ITEM_MAP;
    br->br[1] = l4_fpage(Map_address, L4_LOG2_PAGESIZE, 0).raw;
    br->br[2] = 0;
    l4_msgtag_t tag = invoke(receive_slot, L4RE_PROTO_DATASPACE, 4);
    require(l4_msgtag_label(tag) == 0 && l4_msgtag_items(tag) == 1,
            "Native dataspace mapping failed", tag.raw);
    check_bytes((char const *)Map_address, expected);
    unmap(l4_fpage(Map_address, L4_LOG2_PAGESIZE, L4_FPAGE_RWX));
    unmap(l4_obj_fpage(receive_slot, 0, L4_CAP_FPAGE_RWS));
    require(cap_present(receive_slot) == 0, "Native receive slot was not released", receive_slot);
}

int probe_main(unsigned long argc, char const *const *argv)
{
    require(argc == 3, "Usage: bypass-linux <native|l4|shim> <public|hidden>", argc);
    int on_l4 = equal(argv[1], "l4");
    int shim_only = equal(argv[1], "shim");
    int secret_allowed = equal(argv[2], "public");
    require(on_l4 || shim_only || equal(argv[1], "native"), "Invalid execution mode", -1);
    require(secret_allowed || equal(argv[2], "hidden"), "Invalid file policy", -1);
    shim_file("public.txt", "public!\n", 1);
    shim_file("secret.txt", "secret!\n", secret_allowed);
    message(secret_allowed ? "PASS: route=shim public=readable secret=readable\n"
                           : "PASS: route=shim public=readable secret=hidden\n");
    if (!on_l4) {
        // Linuxのsyscall ABIへL4レジスタを渡す対照試験は意味がなく、実行済みとも報告しない。
        message(shim_only ? "NOTE: Native L4 IPC is skipped in the shim-only control.\n"
                          : "NOTE: Native L4 IPC is skipped on Linux.\n");
        return 0;
    }
    unsigned char const *native_instruction = native_instruction_address();
#ifdef ZCOMP_DYNAMIC_PROBE
    require((unsigned long)native_instruction >= 0x60000000UL
            && (unsigned long)native_instruction < 0x68000000UL,
            "The bypass instruction is not in a guest DSO mapping", (long)native_instruction);
#endif
    require(native_instruction[0] == 0x0f && native_instruction[1] == 0x05,
            "The native IPC instruction was rewritten", -1);
    // 通常入口とキャッシュ入口の両方で増えることを確認し、壊れた観測値の不変を成功扱いにしない。
    unsigned long long shim_before = shim_call_count();
    long tid = linux_call(Linux_gettid, 0, 0, 0, 0);
    long pid = linux_call(Linux_getpid, 0, 0, 0, 0);
    unsigned long long shim_after = shim_call_count();
    require(tid > 0 && pid > 0 && shim_after == shim_before + 2,
            "Shim counter did not count the control syscalls", shim_after - shim_before);
    l4re_env_t *env = *(l4re_env_t **)ZCOMP_ENV_ADDRESS;
    utcb = l4_utcb_direct();
    // 標準cap allocatorが予約済みの範囲より後ろを使い、既存capの上書きを避ける。
    // この単一スレッド試験だけの予約であり、汎用のゲスト用cap allocatorではない。
    receive_slot = env->first_free_cap++ << L4_CAP_SHIFT;
    l4_buf_regs_t saved_buffers = *l4_utcb_br_u(utcb);
    l4_cap_idx_t files = named_cap(env, "linux_files");
    unsigned long long native_before = shim_call_count();
    native_file(files, "public.txt", "public!\n", 1);
    native_file(files, "secret.txt", "secret!\n", secret_allowed);
    l4_cap_idx_t rom = named_cap(env, "rom");
    require(cap_present(rom) == 0, "Startup ROM capability survived guest entry", rom);
    // 名前が残っていてもカーネルslotは空である。shimを通さないIPC自体も拒否されることを確かめる。
    l4_msgtag_t denied;
    denied.raw = native_call(rom, l4_msgtag(L4RE_PROTO_NAMESPACE, 0, 0, 0).raw);
    require(l4_msgtag_has_error(denied) && l4_utcb_tcr_u(utcb)->error == L4_IPC_ENOT_EXISTENT,
            "Native IPC reached the dropped startup ROM", denied.raw);
    // ゲストとランタイムはUTCBも共有する。受信窓を残すと後続の通常IPCを壊し得る。
    *l4_utcb_br_u(utcb) = saved_buffers;
    unsigned long long native_after = shim_call_count();
    // 成功通知のwriteは比較の後に行う。検査失敗時だけ測定区間内から診断を出す。
    require(native_after == native_before, "Native IPC entered the shim", native_after - native_before);
    report_bypass_counts(shim_before, shim_after, native_before, native_after);
    message(secret_allowed ? "PASS: route=native-l4 public=readable secret=readable rom-secret=hidden rom-cap=absent\n"
                           : "PASS: route=native-l4 public=readable secret=hidden rom-secret=hidden rom-cap=absent\n");
    message("PASS: Native L4 IPC used an unpatched overlapping instruction.\n");
    return 0;
}
