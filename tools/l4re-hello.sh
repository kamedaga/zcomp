#!/usr/bin/env bash
set -euo pipefail

version=26.09.0
archive_sha256=381d5bbb5c650b7ecbe8947a2b311e7e4b129e8a706e286122af4fb3afb01141
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
lab_dir=${L4RE_LAB_DIR:-$project_dir/l4re}
jobs=${L4RE_JOBS:-8}
mode=${1:-run}

fail() {
    printf 'L4Re: %s\n' "$*" >&2
    exit 1
}

# Makeの検索パスとビルド先の解釈が曖昧になる場所は、構築前に拒否する。
[[ "$lab_dir" == /* && "$lab_dir" != / && "$lab_dir" != *[[:space:]:]* ]] \
    || fail 'L4RE_LAB_DIR must be an absolute path without whitespace or colons.'
[[ "$jobs" =~ ^[1-9][0-9]*$ ]] || fail 'L4RE_JOBS must be a positive integer.'
[[ "$mode" == build || "$mode" == run || "$mode" == check ]] \
    || fail 'Usage: bash tools/l4re-hello.sh [build|run|check]'

# 公式Makefileは絶対パスを保持するため、入口のリンクと実体を別の構築先として扱わせない。
lab_dir=$(realpath -m -- "$lab_dir")
snapshot_dir="$lab_dir/l4re-snapshot-$version"
kernel_dir="$lab_dir/build/fiasco-amd64"
l4re_dir="$lab_dir/build/l4re-amd64"
archive="$lab_dir/downloads/l4re-snapshot-$version.tar.xz"
mkdir -p "$lab_dir/downloads" "$lab_dir/logs"

if [[ "$mode" == build ]]; then
    if [[ ! -f "$archive" ]]; then
        curl -fL --retry 2 -o "$archive" \
            "https://l4re.org/download/snapshots/l4re-snapshot-$version.tar.xz"
    fi
    # 配布サイトの更新後も同じソースを使い、既存のソース編集を再展開で消さない。
    printf '%s  %s\n' "$archive_sha256" "$archive" | sha256sum -c -
    if [[ ! -d "$snapshot_dir" ]]; then
        tar -xf "$archive" -C "$lab_dir"
    fi
    [[ -f "$snapshot_dir/src/fiasco/Makefile" ]] || fail 'The official source archive was not fully extracted.'
    make -C "$snapshot_dir/src/l4" check_build_tools
    if [[ ! -f "$kernel_dir/Makefile" ]]; then
        make -C "$snapshot_dir/src/fiasco" B="$kernel_dir"
    fi
    if [[ ! -f "$l4re_dir/Makefile" ]]; then
        make -C "$snapshot_dir/src/l4" B="$l4re_dir"
    fi
    # 全アーキテクチャを構築するスナップショット最上位のmakeは呼ばない。
    rg -q '^CONFIG_AMD64=y$' "$kernel_dir/globalconfig.out" || fail 'The kernel is not configured for amd64.'
    rg -q '^CONFIG_BUILD_ARCH=amd64$' "$l4re_dir/.config" || fail 'L4Re is not configured for amd64.'
    make -C "$kernel_dir" -j"$jobs" 2>&1 | tee "$lab_dir/logs/build-fiasco.log"
    make -C "$l4re_dir" -j"$jobs" 2>&1 | tee "$lab_dir/logs/build-l4re.log"
    printf 'Build complete: Fiasco and L4Re for amd64.\n'
    exit 0
fi

[[ -x "$kernel_dir/fiasco" ]] || fail 'Kernel not found; run build first.'
[[ -x "$l4re_dir/bin/amd64_gen/l4f/hello" ]] || fail 'Official hello not found; run build first.'

# TCGは動作確認の代替であり、KVMと同じ性能条件としては扱わない。
case ${L4RE_ACCEL:-kvm} in
    kvm)
        [[ -r /dev/kvm && -w /dev/kvm ]] || fail '/dev/kvm is unavailable; use L4RE_ACCEL=tcg to try TCG.'
        accelerator=(-accel kvm -cpu host)
        ;;
    tcg) accelerator=(-accel tcg -cpu max) ;;
    *) fail 'L4RE_ACCEL must be kvm or tcg.' ;;
esac

# ホストの他プロジェクト向けラッパーやGUI設定が実験条件に混ざらないよう固定する。
qemu_options="-machine q35 ${accelerator[*]} -m 512 -smp 1 -display none -serial stdio -monitor none -nic none -no-reboot"
# 初回のイメージ生成時間をゲストの起動時間制限に含めない。
make -C "$l4re_dir" E=hello-cfg elfimage \
    "MODULE_SEARCH_PATH=$kernel_dir:$snapshot_dir/src/l4/conf/examples" \
    QEMU_PATH=/usr/bin/qemu-system-x86_64 "QEMU_OPTIONS=$qemu_options" \
    2>&1 | tee "$lab_dir/logs/build-hello-image.log"

# 公式make qemuは内部の再評価でコマンドライン設定を失うため、生成した公式イメージを直接起動する。
command=(/usr/bin/qemu-system-x86_64 -kernel "$l4re_dir/images/l4re_hello-cfg.elf"
    -machine q35 "${accelerator[@]}" -m 512 -smp 1 -display none
    -serial stdio -monitor none -nic none -no-reboot)
if [[ "$mode" == run ]]; then
    printf 'Starting official hello with serial output. Press Ctrl+C to exit.\n'
    exec "${command[@]}"
fi

log="$lab_dir/logs/hello-${L4RE_ACCEL:-kvm}.log"
# helloは終了しない公式サンプルなので、時間制限の終了自体を失敗とは判定しない。
set +e
{
    printf 'QEMU_COMMAND:'
    printf ' %q' "${command[@]}"
    printf '\n'
    # timeoutの別プロセスグループから端末を読むとSIGTTINで停止する。自動試験は入力を使わない。
    timeout --kill-after=5s 25s "${command[@]}" </dev/null 2>&1
} | tee "$log"
pipeline_status=("${PIPESTATUS[@]}")
set -e
[[ ${pipeline_status[1]} == 0 ]] || fail 'Cannot save the boot log.'
[[ ${pipeline_status[0]} == 0 || ${pipeline_status[0]} == 124 ]] || fail "QEMU failed to start. Log: $log"
# ホスト側の表示だけを成功と数えず、ゲストのカーネルと起動管理も確認する。
rg -q 'Welcome to the L4Re Microkernel!' "$log" || fail "Guest kernel boot was not confirmed. Log: $log"
rg -q 'Ned says: Hi World!' "$log" || fail "Ned startup was not confirmed. Log: $log"
count=$(rg -c 'Hello World!' "$log" || true)
[[ ${count:-0} -ge 3 ]] || fail "Official hello produced fewer than 3 messages. Log: $log"
printf 'PASS: Official hello produced %s messages. Log: %s\n' "$count" "$log"
