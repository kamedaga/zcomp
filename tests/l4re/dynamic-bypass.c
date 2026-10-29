/* muslの通常の動的CRTから既存の攻撃操作を呼び、静的試験と同じ比較を行う。
 * 直接IPCの命令はDT_NEEDEDの別DSOに置き、mmapで追加されたコードの迂回も検査する。 */
#include <stdio.h>

extern int probe_main(unsigned long argc, char const *const *argv);

void report_bypass_counts(unsigned long long shim_before, unsigned long long shim_after,
                          unsigned long long native_before, unsigned long long native_after)
{
    // printf自身もshimを通るため、全snapshotを取得した後でだけ出力する。
    printf("BYPASS_COUNTS shim_before=%llu shim_after=%llu native_before=%llu native_after=%llu\n",
           shim_before, shim_after, native_before, native_after);
}

int main(int argc, char **argv)
{
    return probe_main(argc, (char const *const *)argv);
}
