#!/usr/bin/env python3
"""同一Linux ELFの対照実行と、独立したL4Reベンチ起動の生データを保存する。"""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import statistics
import subprocess
import time

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
RECORD = re.compile(r"BENCH suite=(linux|native) name=(\w+) sample=(\d+) iterations=(\d+) ns=(\d+) ticks=(\d+)")
DONE = re.compile(r"BENCH_DONE suite=(linux|native) samples=(\d+) checksum=(\d+)")
LINUX_NAMES = {"integer", "getpid", "enosys", "write_zero", "pread8", "fstat", "open_close", "map_touch_unmap"}
NATIVE_NAMES = {"integer", "fs_pair", "mutex_pair", "fx_pair", "ds_info", "query_drop", "alloc_map_unmap"}
NATIVE_NAMES |= {"mem_cap_slot", "mem_create", "mem_allocate", "mem_attach", "mem_map", "mem_touch",
                 "mem_detach", "mem_cap_free", "reuse_map_unmap"}


def parse(data, origin, run):
    plain = ANSI.sub("", data.decode(errors="replace")).replace("\r", "")
    expected = {"linux": LINUX_NAMES} if origin != "vm" else {"linux": LINUX_NAMES, "native": NATIVE_NAMES}
    rows = []
    for suite, names in expected.items():
        records = [m for m in RECORD.finditer(plain) if m[1] == suite]
        completed = [m for m in DONE.finditer(plain) if m[1] == suite]
        if len(records) != len(names) * 7 or len(completed) != 1 or int(completed[0][2]) != len(records):
            raise RuntimeError(f"Incomplete benchmark records: {origin}/{suite}")
        keys = {(m[2], int(m[3])) for m in records}
        if keys != {(name, sample) for name in names for sample in range(7)}:
            raise RuntimeError(f"Unexpected benchmark sample set: {origin}/{suite}")
        role = origin if origin != "vm" else "l4re_zcomp" if suite == "linux" else "l4re_native"
        for m in records:
            iterations, ns, ticks = map(int, m.group(4, 5, 6))
            if min(iterations, ticks) <= 0 or ns < 0:
                raise RuntimeError("Invalid timer or iteration count")
            rows.append(dict(role=role, run=run, name=m[2], sample=int(m[3]), iterations=iterations,
                             ns=ns, ticks=ticks, ns_per_op=ns / iterations, ticks_per_op=ticks / iterations))
    return rows


def native(args, run, when):
    result = subprocess.run(["taskset", "-c", str(args.cpu), "env", "-i", str(args.binary)],
                            cwd=args.fixture_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=40)
    (args.output_dir / f"linux-{when}-{run}.log").write_bytes(result.stdout)
    if result.returncode:
        raise RuntimeError(f"Linux benchmark failed: {result.returncode}")
    return parse(result.stdout, f"linux_{when}", run)


def virtual(args, run):
    command = ["taskset", "-c", str(args.cpu), "/usr/bin/qemu-system-x86_64", "-kernel", str(args.image),
               "-machine", "q35", "-accel", "kvm", "-cpu", "host", "-m", "512", "-smp", "1",
               "-display", "none", "-serial", "stdio", "-monitor", "none", "-nic", "none", "-no-reboot"]
    output = bytearray()
    started = time.monotonic()
    with subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT) as process, selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        try:
            while time.monotonic() - started < args.timeout:
                for key, _ in selector.select(timeout=0.2):
                    data = os.read(key.fd, 65536)
                    if not data:
                        raise RuntimeError(f"QEMU exited before completion: {process.poll()}")
                    output.extend(data)
                plain = ANSI.sub("", output.decode(errors="replace"))
                completed = re.search(r"\[zcomp-bench\] complete status=(\d+)\r?\n", plain)
                if completed and completed[1] == "0":
                    return parse(bytes(output), "vm", run)
                if completed or re.search(r"FAIL: benchmark[^\n]*\n", plain):
                    raise RuntimeError("L4Re benchmark failed")
            raise RuntimeError("L4Re benchmark timed out")
        finally:
            # ベンチ終了後もOSは動き続ける。今回起動したQEMUだけを止め、待ち時間を測定へ混ぜない。
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            (args.output_dir / f"qemu-{run}.log").write_bytes(output)


def calibrate(rows):
    frequencies = {}
    for run in {r["run"] for r in rows}:
        reference = [r for r in rows if r["run"] == run and r["role"].startswith("linux_") and r["name"] == "integer"]
        if not reference or any(r["ns"] <= 0 for r in reference):
            raise RuntimeError("Host reference clock did not advance")
        frequencies[run] = statistics.median(r["ticks"] / r["ns"] * 1e9 for r in reference)
        # 同一KVMの長い区間でも照合し、TSC scalingの違いをnsへ黙って持ち込まない。
        check = [r["ticks"] / r["ns"] * 1e9 for r in rows
                 if r["run"] == run and r["role"] == "l4re_zcomp" and r["ns"] >= 100000000]
        if not check or abs(statistics.median(check) / frequencies[run] - 1) > 0.03:
            raise RuntimeError("Guest TSC rate could not be validated against the host calibration")
    for row in rows:
        row["tsc_ns_per_op"] = row["ticks_per_op"] * 1e9 / frequencies[row["run"]]
    return frequencies


def summarize(rows, destination):
    groups = {}
    for row in rows:
        role = "linux" if row["role"].startswith("linux_") else row["role"]
        groups.setdefault((role, row["name"]), []).append(row)
    fields = ["role", "name", "samples", "median_ns", "min_ns", "max_ns", "median_ticks", "clock_median_ns"]
    with (destination / "summary.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        print("role          operation          samples   median ns/op     min       max   TSC ticks/op")
        for (role, name), items in sorted(groups.items()):
            ns = [r["tsc_ns_per_op"] for r in items]
            ticks = [r["ticks_per_op"] for r in items]
            record = dict(role=role, name=name, samples=len(items), median_ns=statistics.median(ns),
                          min_ns=min(ns), max_ns=max(ns), median_ticks=statistics.median(ticks),
                          clock_median_ns=statistics.median(r["ns_per_op"] for r in items))
            writer.writerow(record)
            print(f"{role:13} {name:18} {len(items):7} {record['median_ns']:14.1f} "
                  f"{min(ns):9.1f} {max(ns):9.1f} {record['median_ticks']:14.1f}")
    # before/afterと各bootはraw CSVに残す。中央値だけで分散や仮想時計の異常を隠さない。
    print("NOTE: WSL Linux vs nested KVM/L4Re is not a matched-virtualization OS comparison.")
    print("NOTE: ns/op is calibrated from ordered TSC ticks, not the coarse L4Re KIP clock.")
    print("NOTE: TSC ticks are not CPU core cycles; elapsed time includes preemption.")
    print(f"Results: {destination}")


def main():
    parser = argparse.ArgumentParser(description="Measure the current L4Re shim and native reference operations.")
    for name in ("image", "binary", "fixture-dir", "output-dir"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--cpu", type=int, default=min(os.sched_getaffinity(0)))
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=120)
    args = parser.parse_args()
    if args.cpu not in os.sched_getaffinity(0) or not 1 <= args.runs <= 30 or not args.timeout > 0:
        parser.error("Invalid CPU, run count, or timeout")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    metadata = dict(platform=platform.platform(), cpu=args.cpu, runs=args.runs, samples_per_case=7,
                    qemu="q35,kvm,cpu=host,512MiB,1vCPU", timing="CLOCK_MONOTONIC and ordered RDTSC",
                    binary_sha256=hashlib.sha256(args.binary.read_bytes()).hexdigest(),
                    image_sha256=hashlib.sha256(args.image.read_bytes()).hexdigest(),
                    git_head=subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
                    git_status=subprocess.check_output(["git", "status", "--short"], text=True))
    (args.output_dir / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")
    rows = []
    for run in range(args.runs):
        print(f"Benchmark run {run + 1}/{args.runs}: Linux before, KVM/L4Re, Linux after", flush=True)
        rows.extend(native(args, run, "before"))
        rows.extend(virtual(args, run))
        rows.extend(native(args, run, "after"))
    metadata["calibrated_tsc_hz"] = calibrate(rows)
    metadata["ns_source"] = "Host monotonic/TSC calibration, checked against guest intervals >=100ms"
    (args.output_dir / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")
    with (args.output_dir / "samples.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    summarize(rows, args.output_dir)


if __name__ == "__main__":
    main()
