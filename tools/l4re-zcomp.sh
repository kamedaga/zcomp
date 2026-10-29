#!/usr/bin/env bash
set -euo pipefail
project_dir=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
lab_dir=$(realpath -m -- "${L4RE_LAB_DIR:-$project_dir/l4re}")
fail() { printf 'zcomp-run: %s\n' "$*" >&2; exit 1; }
[[ "$lab_dir" == /* && "$lab_dir" != / && "$lab_dir" != *[[:space:]:]* ]] \
    || fail 'L4RE_LAB_DIR must be an absolute path without whitespace or colons.'
source_dir="$lab_dir/l4re-snapshot-26.09.0/src/l4"
l4re_dir="$lab_dir/build/l4re-amd64"
kernel_dir="$lab_dir/build/fiasco-amd64"
port_dir="$project_dir/ports/l4re/zcomp-run"
work_dir="$lab_dir/build/zcomp-tests"
mode=${1:-run}
selected_case=${L4RE_CASE:-all}
jobs=${L4RE_JOBS:-8}
[[ "$mode" == build || "$mode" == run || "$mode" == check ]] || fail 'Usage: l4re-zcomp.sh [build|run|check]'
[[ "$jobs" =~ ^[1-9][0-9]*$ ]] || fail 'L4RE_JOBS must be a positive integer.'
case "$selected_case" in
    all) image_entry=zcomp ;;
    dynamic) image_entry=zcomp_dynamic ;;
    bypass-dynamic) image_entry=zcomp_bypass_dynamic ;;
    busybox) image_entry=zcomp_busybox ;;
    sqlite) image_entry=zcomp_sqlite ;;
    *) fail 'L4RE_CASE must be all, dynamic, bypass-dynamic, busybox, or sqlite.' ;;
esac
[[ -x "$kernel_dir/fiasco" && -f "$l4re_dir/Makefile" ]] || fail 'Build Fiasco and L4Re first: make l4re-build'
mkdir -p "$work_dir" "$lab_dir/logs"
if [[ ! -f "$project_dir/build/_deps/zydis-src/src/Decoder.c" ]]; then
    cmake -S "$project_dir" -B "$project_dir/build" -DCMAKE_BUILD_TYPE=RelWithDebInfo
fi
make -C "$port_dir" "L4DIR=$source_dir" "O=$l4re_dir" "ZCOMP_DIR=$project_dir" -j"$jobs"
cp "$project_dir/tests/l4re/files/"{public,secret}.txt "$work_dir/"

if [[ "$selected_case" == busybox ]]; then
    bash "$project_dir/tools/l4re-busybox.sh" "$work_dir"
elif [[ "$selected_case" == sqlite ]]; then
    bash "$project_dir/tools/l4re-sqlite.sh" "$work_dir"
else
    command -v musl-gcc >/dev/null || fail 'musl-gcc is required; install musl-tools.'
    musl_loader=${L4RE_MUSL_LOADER:-/lib/ld-musl-x86_64.so.1}
    [[ -f "$musl_loader" ]] || fail 'Set L4RE_MUSL_LOADER to the musl interpreter.'
    cp "$musl_loader" "$work_dir/ld-musl-x86_64.so.1"
    if [[ "$selected_case" == all ]]; then
        cc -static -no-pie -nostdlib -O2 -Wall -Wextra -Werror -fno-pie -fno-builtin \
            -fno-stack-protector -fcf-protection=none -mno-red-zone -mgeneral-regs-only \
            -o "$work_dir/policy-linux" "$project_dir/tests/l4re/policy-entry.S" \
            "$project_dir/tests/l4re/policy-linux.c"
        (cd "$project_dir/tests/l4re/files" && timeout 20s env -i "$work_dir/policy-linux" all success) \
            > "$work_dir/cap-ok.native.out"
        for target in resources-linux pthread-linux; do
            musl-gcc -static -no-pie -O2 -Wall -Wextra -Werror -pthread \
                -o "$work_dir/$target" "$project_dir/tests/l4re/$target.c"
            # 同じELFを先にLinuxでも実行し、fixtureや試験器の失敗を互換層の失敗と混同しない。
            (cd "$project_dir/tests/l4re/files" && timeout 20s env -i "$work_dir/$target")
        done
    fi
    if [[ "$selected_case" == all || "$selected_case" == dynamic ]]; then
        musl-gcc -shared -fPIC -O2 -Wall -Wextra -Werror -mno-red-zone \
            -Wl,-soname,libzcomp-example.so -o "$work_dir/libzcomp-example.so" \
            "$project_dir/tests/l4re/dynamic-library.c"
        musl-gcc -fPIE -pie -O2 -Wall -Wextra -Werror -mno-red-zone \
            -Wl,-rpath,/lib -L"$work_dir" -o "$work_dir/dynamic-hello" \
            "$project_dir/tests/l4re/dynamic-hello.c" -lzcomp-example
        env -i LD_LIBRARY_PATH="$work_dir" "$work_dir/dynamic-hello" native
    fi
    if [[ "$selected_case" == all || "$selected_case" == bypass-dynamic ]]; then
        # 実際にリンクしたnative Envの位置を渡す。固定番地や秘密のcap番号を隔離の前提にしない。
        unstripped="$l4re_dir/ext-pkg$port_dir/OBJ-amd64_gen-std-l4f/zcomp-run"
        env_address=$(nm -n "$unstripped" | awk '$3 == "l4re_global_env" { print "0x" $1 }')
        [[ "$env_address" =~ ^0x[[:xdigit:]]+$ ]] || fail 'Cannot locate l4re_global_env.'
        c++ -std=c++17 -O2 -Wall -Wextra -Werror -mno-red-zone -mgeneral-regs-only \
            -fno-exceptions -fno-rtti -fno-stack-protector -fcf-protection=none \
            -I"$port_dir" -c "$project_dir/tests/l4re/bypass-count.cc" -o "$work_dir/bypass-count.o"
        musl-gcc -shared -nostdlib -fPIC -Wl,-soname,libzcomp-native.so \
            -o "$work_dir/libzcomp-native.so" "$project_dir/tests/l4re/bypass-native.S"
        musl-gcc -no-pie -fno-pie -O2 -Wall -Wextra -Werror -fno-builtin -fno-stack-protector \
            -fcf-protection=none -mno-red-zone -mgeneral-regs-only \
            -I"$l4re_dir/include/amd64" -I"$l4re_dir/include" -DZCOMP_ENV_ADDRESS="$env_address" \
            -DZCOMP_DYNAMIC_PROBE -Wl,-rpath,/lib -L"$work_dir" -o "$work_dir/dynamic-bypass" \
            "$project_dir/tests/l4re/dynamic-bypass.c" "$project_dir/tests/l4re/bypass-linux.c" \
            "$project_dir/tests/l4re/bypass-linux-call.S" "$work_dir/bypass-count.o" -lzcomp-native
        (cd "$project_dir/tests/l4re/files" && env -i LD_LIBRARY_PATH="$work_dir" "$work_dir/dynamic-bypass" native public)
        hidden=$(mktemp -d "$work_dir/native-hidden.XXXXXX")
        cp "$project_dir/tests/l4re/files/public.txt" "$hidden/"
        (cd "$hidden" && env -i LD_LIBRARY_PATH="$work_dir" "$work_dir/dynamic-bypass" native hidden)
    fi
fi
if [[ "$mode" == build ]]; then
    printf 'Build complete: zcomp-run and the selected Linux ELFs.\n'
    exit 0
fi

case ${L4RE_ACCEL:-kvm} in
    kvm)
        [[ -r /dev/kvm && -w /dev/kvm ]] || fail '/dev/kvm is unavailable; use L4RE_ACCEL=tcg.'
        accelerator=(-accel kvm -cpu host) ;;
    tcg) accelerator=(-accel tcg -cpu max) ;;
    *) fail 'L4RE_ACCEL must be kvm or tcg.' ;;
esac
make -C "$l4re_dir" "E=$image_entry" elfimage "MODULES_LIST=$port_dir/modules.list" \
    "MODULE_SEARCH_PATH=$kernel_dir:$port_dir:$work_dir"
command=(/usr/bin/qemu-system-x86_64 -kernel "$l4re_dir/images/l4re_$image_entry.elf"
    -machine q35 "${accelerator[@]}" -m 512 -smp 1 -display none
    -serial stdio -monitor none -nic none -no-reboot)
if [[ "$mode" == run ]]; then
    printf 'Starting zcomp-run. Press Ctrl+C to exit.\n'
    exec "${command[@]}"
fi
python3 "$project_dir/tests/l4re/check.py" "$selected_case" "$work_dir" \
    "$lab_dir/logs/zcomp-$selected_case-${L4RE_ACCEL:-kvm}.log" \
    --timeout "${L4RE_CHECK_TIMEOUT:-90}" -- "${command[@]}"
