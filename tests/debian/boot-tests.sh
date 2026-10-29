#!/bin/bash
set -uo pipefail
systemctl stop serial-getty@ttyS0.service
exec </dev/null >/dev/ttyS0 2>&1
# cloud-initの出力を、結果転送や測定対象の出力へ混ぜない。
while [[ $(systemctl show -p SubState --value cloud-final.service) == running ]]; do sleep 0.2; done
mkdir -p /mnt/seed /work/results
mountpoint -q /mnt/seed || mount -o ro /dev/sr0 /mnt/seed
mount -o remount,noatime /
# 実行中の起動スクリプトを書き換えると、bashが途中から別の行を読むため除外する。
for source in /mnt/seed/payload/*; do
    [[ ${source##*/} == repro-boot.sh ]] || cp -a "$source" /work/
done
mode=$(< /mnt/seed/mode)
sysctl -w vm.mmap_min_addr=0
echo "TEST_BEGIN mode=$mode"
if [[ "$mode" == prepare ]]; then
    bash /work/prepare.sh
    status=$?
else
    python3 /work/experiment.py "$mode"
    status=$?
fi
echo "TEST_STATUS mode=$mode status=$status"
echo 0 > /proc/sys/kernel/printk
tar -czf /dev/virtio-ports/zcomp.results -C /work/results .
echo TEST_COMPLETE
systemctl poweroff --no-block
