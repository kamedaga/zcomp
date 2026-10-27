/* muslの通常の動的CRTから既存の攻撃操作を呼び、静的試験と同じ比較を行う。
 * 直接IPCの命令はDT_NEEDEDの別DSOに置き、mmapで追加されたコードの迂回も検査する。 */
extern int probe_main(unsigned long argc, char const *const *argv);

int main(int argc, char **argv)
{
    return probe_main(argc, (char const *const *)argv);
}
