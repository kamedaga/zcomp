#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
work_dir=${1:?Usage: l4re-busybox.sh <work directory>}
[[ "$work_dir" == /* && "$work_dir" != / ]] || exit 1
cache="$work_dir/busybox-alpine"
mkdir -p "$cache"
fail() { printf 'busybox-demo: %s\n' "$*" >&2; exit 1; }

# 配布済みELFを対象にし、ソース修正・再リンク・取得物の差替えで成功条件を変えない。
# SHA-256は再現性の固定用であり、APK署名を検証したという意味ではない。
fetch_apk() {
    local name=$1 digest=$2 archive="$cache/$1"
    if [[ ! -f "$archive" ]]; then
        local partial
        partial=$(mktemp "$cache/download.XXXXXX")
        curl -fL --retry 2 --connect-timeout 10 --max-time 120 \
            "https://dl-cdn.alpinelinux.org/alpine/v3.23/main/x86_64/$name" -o "$partial"
        printf '%s  %s\n' "$digest" "$partial" | sha256sum -c -
        mv -- "$partial" "$archive"
    fi
    printf '%s  %s\n' "$digest" "$archive" | sha256sum -c -
}
fetch_apk busybox-1.37.0-r30.apk 2fea8c73710994099eaec6832b69a0f70163e0d6ee13848af3a5270a16d15c5c
fetch_apk musl-1.2.5-r24.apk d49d703392f1a6d2fe822db1b57e61735063077e1ad846d5f40d79fe507ec727

# APKのinstall scriptは実行せず、必要な通常ファイルだけを取り出す。
tar --warning=no-unknown-keyword --no-same-owner -xzf "$cache/busybox-1.37.0-r30.apk" -C "$cache" bin/busybox
tar --warning=no-unknown-keyword --no-same-owner -xzf "$cache/musl-1.2.5-r24.apk" -C "$cache" lib/ld-musl-x86_64.so.1
cp -- "$cache/bin/busybox" "$work_dir/busybox"
cp -- "$cache/lib/ld-musl-x86_64.so.1" "$work_dir/busybox-musl"
# L4Reのimage生成器もLinux ELFの依存名を収集するので、同じ配布物を標準名でも用意する。
cp -- "$work_dir/busybox-musl" "$work_dir/libc.musl-x86_64.so.1"
cp -- "$work_dir/busybox-musl" "$work_dir/ld-musl-x86_64.so.1"
printf '%s  %s\n' \
    f3547b3d78d08a028a4833ddb83b77cf012838c078bfd2b76355f53d1d8bba62 "$work_dir/busybox" \
    01e3b793ecda1146c4853dfa350e0515f2137f380fb9fa2370428f7bf9481148 "$work_dir/busybox-musl" \
    > "$work_dir/busybox.sha256"
sha256sum -c "$work_dir/busybox.sha256"
readelf -h "$work_dir/busybox" | rg -q 'Type:.*DYN' || fail 'Expected a PIE executable.'
readelf -l "$work_dir/busybox" | rg -q 'interpreter: /lib/ld-musl-x86_64.so.1' \
    || fail 'Unexpected interpreter path.'

# 非公開ファイルの対照には新しい空ディレクトリを使い、以前のfixtureを拾わない。
empty_dir=$(mktemp -d "$cache/empty.XXXXXX")
trap 'rm -rf -- "$empty_dir"' EXIT
for name in bb-echo bb-cat bb-hide bb-secr bb-full bb-sha bb-wc; do
    directory="$project_dir/tests/l4re/files"
    expected=0
    case "$name" in
        bb-echo) arguments=(echo BusyBox-demo) ;;
        bb-cat) arguments=(cat public.txt) ;;
        bb-hide) arguments=(cat public.txt); directory="$empty_dir"; expected=1 ;;
        bb-secr) arguments=(cat secret.txt); directory="$empty_dir"; expected=1 ;;
        bb-full) arguments=(cat secret.txt) ;;
        bb-sha) arguments=(sha256sum public.txt) ;;
        bb-wc) arguments=(wc -c public.txt) ;;
    esac
    # PT_INTERPを書き換えず、Linux対照でも同じ配布版muslを明示して使う。
    status=0
    (cd "$directory" && env -i "$work_dir/busybox-musl" "$work_dir/busybox" "${arguments[@]}") \
        > "$work_dir/$name.native.out" 2>&1 || status=$?
    [[ "$status" == "$expected" ]] || fail "Unexpected native exit status: $name ($status)."
done
printf 'PASS: Alpine BusyBox and musl hashes verified; seven native cases completed.\n'
