#!/usr/bin/env bash
set -euo pipefail
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
lab_dir=$(realpath -m -- "${L4RE_LAB_DIR:-$project_dir/l4re}")
[[ "$lab_dir" == /* && "$lab_dir" != / && "$lab_dir" != *[[:space:]:]* ]] \
    || { printf 'benchmark: invalid L4RE_LAB_DIR.\n' >&2; exit 1; }
[[ ${L4RE_ACCEL:-kvm} == kvm ]] \
    || { printf 'benchmark: use KVM; TCG timing is not an OS performance comparison.\n' >&2; exit 1; }
[[ -r /dev/kvm && -w /dev/kvm ]] \
    || { printf 'benchmark: /dev/kvm is unavailable.\n' >&2; exit 1; }
source_dir="$lab_dir/l4re-snapshot-26.09.0/src/l4"
l4re_dir="$lab_dir/build/l4re-amd64"
kernel_dir="$lab_dir/build/fiasco-amd64"
port_dir="$project_dir/ports/l4re/zcomp-bench"
work_dir="$lab_dir/build/zcomp-bench"
output_dir="$project_dir/build/l4re-bench"
mkdir -p "$work_dir" "$output_dir"
for target in zcomp-run zcomp-bench; do
    make -C "$project_dir/ports/l4re/$target" "L4DIR=$source_dir" "O=$l4re_dir" \
        "ZCOMP_DIR=$project_dir" -j8
done
# 既知のcallq red zone制約で測定を壊さない。同じELFを両OSに渡し、ベンチ専用の省略経路は作らない。
musl-gcc -static -no-pie -O2 -Wall -Wextra -Werror -mno-red-zone \
    -o "$work_dir/bench-linux" "$port_dir/bench-linux.c"
cp "$project_dir/tests/l4re/files/public.txt" "$work_dir/public.txt"
make -C "$l4re_dir" E=zcomp_bench elfimage "MODULES_LIST=$port_dir/modules.list" \
    "MODULE_SEARCH_PATH=$kernel_dir:$port_dir:$work_dir"
cpu_arguments=()
if [[ -n ${L4RE_BENCH_CPU:-} ]]; then cpu_arguments=(--cpu "$L4RE_BENCH_CPU"); fi
python3 "$project_dir/tools/l4re-bench.py" --image "$l4re_dir/images/l4re_zcomp_bench.elf" \
    --binary "$work_dir/bench-linux" --fixture-dir "$work_dir" --output-dir "$output_dir" \
    --runs "${L4RE_BENCH_RUNS:-3}" --timeout "${L4RE_BENCH_TIMEOUT:-120}" \
    "${cpu_arguments[@]}"
