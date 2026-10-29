#!/usr/bin/env python3
"""固定した100件を、同じ準備済みVMからnativeとhookedで実行する。"""
import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

PROJECT = Path(__file__).resolve().parents[1]
SOURCE = PROJECT / "tests/debian"


def run(command, **kwargs):
    return subprocess.run([str(x) for x in command], check=True, **kwargs)


def prepare_seed(destination, mode, rows):
    destination.mkdir()
    seed = destination / "seed"
    payload = seed / "payload"
    payload.mkdir(parents=True)
    for name in ("common.py", "fixtures.py", "services.py", "workloads.py", "runner.py"):
        shutil.copyfile(SOURCE / name, payload / name)
    shutil.copyfile(SOURCE / "prepare.sh", payload / "prepare.sh")
    shutil.copyfile(SOURCE / "boot-tests.sh", payload / "repro-boot.sh")
    shutil.copyfile(SOURCE / "run.py", payload / "experiment.py")
    shutil.copyfile(PROJECT / "build/libzcomp.so", payload / "libzcomp.so")
    for name, selected in [("packages.tsv", rows[:30]), ("packages-100.tsv", rows)]:
        with (payload / name).open("w") as output:
            writer = csv.writer(output, delimiter="\t", lineterminator="\n")
            writer.writerow(["popcon_rank", "package", "version", "architecture", "filename", "sha256"])
            for row in selected:
                writer.writerow(
                    [
                        row[key]
                        for key in (
                            "popcon_rank",
                            "package",
                            "version",
                            "architecture",
                            "deb_path",
                            "deb_sha256",
                        )
                    ]
                )
    (seed / "mode").write_text(mode + "\n")
    (seed / "meta-data").write_text(
        "instance-id: zcomp-debian-reproduction\nlocal-hostname: zcomp-debian-test\n"
    )
    (seed / "user-data").write_text((SOURCE / "cloud-init.yaml").read_text())
    return seed, payload


def qemu_command(image, iso, archive, mode):
    return [
        "/usr/bin/qemu-system-x86_64",
        "-machine", "q35", "-accel", "kvm", "-cpu", "host",
        "-m", "3072", "-smp", "2",
        "-display", "none", "-serial", "stdio", "-monitor", "none",
        "-drive", f"file={image},format=qcow2,if=virtio",
        "-cdrom", iso,
        # 比較対象のstdoutとは別のportで、VM内の生データを回収する。
        "-chardev", f"file,id=results,path={archive}",
        "-device", "virtio-serial-pci",
        "-device", "virtserialport,chardev=results,name=zcomp.results",
        "-nic", "user,model=virtio-net-pci" if mode == "prepare" else "none",
        "-no-reboot",
    ]


def collect_results(destination, mode, archive):
    log = (destination / "console.log").read_text(errors="replace")
    if f"TEST_STATUS mode={mode} status=0" not in log or "TEST_COMPLETE" not in log:
        raise RuntimeError(f'The guest did not complete: {destination / "console.log"}')
    result = destination / "results"
    result.mkdir()
    with tarfile.open(archive) as files:
        # 結果は一般ファイルとディレクトリだけを受け取り、VMからの任意パスへの書込みを防ぐ。
        for member in files:
            path = Path(member.name)
            if path.is_absolute() or ".." in path.parts or not (member.isfile() or member.isdir()):
                raise RuntimeError(f"Unexpected archive member: {member.name}")
            files.extract(member, result, filter="data")
    return result


def boot(base, destination, mode, rows):
    seed, payload = prepare_seed(destination, mode, rows)
    image = destination / "disk.qcow2"
    iso = destination / "seed.iso"
    # 元のイメージには書き込まず、毎回新しいoverlayを作る。
    run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", base, image], stdout=subprocess.DEVNULL)
    run(
        ["xorriso", "-as", "mkisofs", "-quiet", "-V", "cidata", "-J", "-r", "-o", iso, seed],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    archive = destination / "results.tar.gz"
    command = qemu_command(image, iso, archive, mode)
    print(f"Running {mode}: {destination}", flush=True)
    with (destination / "console.log").open("wb") as log:
        run(
            ["timeout", "--kill-after=5s", "1800s", *command],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
    result = collect_results(destination, mode, archive)
    manifest = {
        str(p.relative_to(payload)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in payload.iterdir()
        if p.is_file()
    }
    (destination / "inputs.json").write_text(
        json.dumps(dict(base=str(base), files=manifest), indent=2) + "\n"
    )
    return result


def read_guard_evidence(results_directory, case):
    guards, rejected, guard_failed = 0, [], False
    for step in range(len(case["steps"])):
        data = b"\n".join(
            (results_directory / f'{case["number"]:02d}-{step}.{kind}').read_bytes() for kind in ("stdout", "stderr")
        )
        guards += len(re.findall(rb"^zcomp: guard=sud scope=post-init$", data, re.M))
        rejected += re.findall(rb"^zcomp: blocked unhooked syscall[^\n]*", data, re.M)
        guard_failed |= bool(
            re.search(rb"^zcomp: (?:Cannot .*guard|Cannot enable Syscall User Dispatch)", data, re.M)
        )
    return guards, rejected, guard_failed


def compare(native, hooked, destination, rows):
    sys.path.insert(0, str(SOURCE))
    from compare import compare as compare_cases

    result = compare_cases(native, hooked)
    # SUDの拒否なしと、guard自体が有効だったことは別々に確認する。
    raw = json.loads((hooked / "results.json").read_text())
    for record, case, reference in zip(result["cases"], raw["cases"], rows):
        if record["number"] != int(reference["number"]) or record["package"] != reference["package"]:
            raise RuntimeError("The results do not match the fixed package list")
        guards, rejected, guard_failed = read_guard_evidence(hooked, case)
        record.update(guards=guards, rejected=[line.decode() for line in rejected])
        if guard_failed:
            record["status"] = "GUARD_FAILURE"
        elif rejected:
            record["status"] = "BLOCKED_UNHOOKED"
        elif guards < record["initializations"]:
            record["status"] = "NO_GUARD_EVIDENCE"
        record["reference"] = reference["result"]
        record["expected"] = record["status"] in (reference["result"], "MATCH_WITH_HOOKS")
        print(f'{record["number"]:03d} {record["package"]}: {record["status"]}')
    result["summary"] = dict(Counter(row["status"] for row in result["cases"]))
    result["unexpected"] = [row["number"] for row in result["cases"] if not row["expected"]]
    (destination / "comparison.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(dict(summary=result["summary"], unexpected=result["unexpected"]), sort_keys=True))
    return bool(result["unexpected"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "check", "compare"))
    parser.add_argument("image", type=Path, help="Debian cloud image, prepared image, or native results")
    parser.add_argument("--hooked", type=Path, help="Hooked results for compare")
    args = parser.parse_args()
    parent = PROJECT / "build/debian-reproduction"
    parent.mkdir(parents=True, exist_ok=True)
    destination = Path(tempfile.mkdtemp(prefix=args.mode + ".", dir=parent))
    with (PROJECT / "docs/debian-cli.tsv").open() as source:
        rows = list(csv.DictReader(source, delimiter="\t"))
    if len(rows) != 100 or [int(row["number"]) for row in rows] != list(range(1, 101)):
        parser.error("Expected the fixed 100-package manifest")
    if args.mode == "compare":
        if args.hooked is None:
            parser.error("compare requires --hooked")
        return compare(args.image, args.hooked, destination, rows)
    base = args.image.resolve(strict=True)
    if args.mode == "prepare":
        result = boot(base, destination / "prepared", "prepare", rows)
        for name in ("preparation.json", "preparation-100.json"):
            # fixture生成の失敗を環境差や既知の非互換として隠さない。
            if json.loads((result / name).read_text()):
                raise RuntimeError(f"Incomplete fixtures: {result / name}")
        print(f'Prepared image: {destination / "prepared/disk.qcow2"}')
        return 0
    native = boot(base, destination / "native", "native", rows)
    hooked = boot(base, destination / "hooked", "hooked", rows)
    return compare(native, hooked, destination, rows)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"FAIL: {error}")
