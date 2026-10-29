"""公開用の代表ケースを、終了状態・実際の出力・捕捉の証拠で確認する。"""
import argparse
from pathlib import Path
import re
import selectors
import subprocess
import time
from log import normalize

CASES = {
    "all": ("dynamic", "files", "pthread", "db-full", "db-hide",
            "cap-ok", "no-out", "no-file", "low-mem", "no-mem", "no-proc", "lo-proc"),
    "dynamic": ("dynamic",),
    "bypass-dynamic": ("db-full", "db-hide"),
    "busybox": ("bb-echo", "bb-cat", "bb-hide", "bb-secr", "bb-full", "bb-sha", "bb-wc"),
    "sqlite": ("sq-mem", "sq-read"),
}
EXIT_STATUS = {"bb-hide": 1, "bb-secr": 1}
DENIED_CAPS = {"no-out": "linux_stdout", "no-file": "linux_files",
               "no-mem": "linux_memory", "no-proc": "linux_process"}
LIMITED_CAPS = {"low-mem": "linux_memory", "lo-proc": "linux_process"}
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
DONE = re.compile(r"\[zcomp-suite\] complete cases=(\d+) failed=(\d+)")


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def capture(command, path, timeout):
    require(command and timeout > 0, "Expected a QEMU command and positive timeout")
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    data = bytearray()
    deadline = time.monotonic() + timeout
    try:
        with path.open("wb") as output:
            while time.monotonic() < deadline:
                for key, _ in selector.select(0.2):
                    chunk = key.fileobj.read1(65536)
                    require(chunk, "QEMU exited before the suite completed")
                    data.extend(chunk)
                    output.write(chunk)
                    output.flush()
                text = ANSI.sub("", data.decode(errors="replace")).replace("\r", "")
                if DONE.search(text):
                    return normalize(text)
            raise RuntimeError("The suite timed out")
    finally:
        selector.close()
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def validate(text, selected, work):
    expected = CASES[selected]
    require("Welcome to the L4Re Microkernel!" in text, "Guest kernel did not boot")
    results = re.findall(r"\[zcomp-result\] case=([\w-]+) status=(\d+)", text)
    require(sorted(results) == sorted((name, str(EXIT_STATUS.get(name, 0))) for name in expected),
            "Missing, failed, or unexpected guest tasks")
    require(DONE.findall(text) == [(str(len(expected)), "0")], "Incomplete suite")
    for case in expected:
        output = (case + "-out")[:8]
        diagnostic = "\n".join(re.findall(rf"^{case}\s*\| (.*)$", text, re.M))
        actual = "".join(line + "\n" for line in re.findall(rf"^{output}\s*\| (.*)$", text, re.M))
        status = EXIT_STATUS.get(case, 0)
        require(re.search(rf"Guest exited: status={status} calls=[1-9]\d* ", diagnostic), f"No dispatch evidence: {case}")
        require(re.search(r"dropped=rom aliases=\d+ probe=removed", diagnostic), f"Startup ROM remained: {case}")
        if case == "dynamic":
            require("PASS: Dynamic musl auxv, relocation, constructors, TLS, shared-library syscall, and fork." in actual,
                    "Dynamic startup or fork failed")
        elif case == "files":
            require("PASS: File operations, private mappings, zeroing, partial protection, and unmapping." in actual,
                    "Resource operations failed")
        elif case == "pthread":
            require("PASS: Pthread create/join, private TLS, mutex, condition variable, and futex." in actual,
                    "Thread operations failed")
        elif case.startswith("db-"):
            secret = "readable" if case == "db-full" else "hidden"
            require(f"PASS: route=shim public=readable secret={secret}" in actual, f"Shim policy failed: {case}")
            require(f"PASS: route=native-l4 public=readable secret={secret} rom-secret=hidden rom-cap=absent" in actual,
                    f"Native IPC policy failed: {case}")
            require("PASS: Native L4 IPC used an unpatched overlapping instruction." in actual,
                    f"The bypass was not exercised: {case}")
            counts = re.findall(r"^BYPASS_COUNTS shim_before=(\d+) shim_after=(\d+) "
                                r"native_before=(\d+) native_after=(\d+)$", actual, re.M)
            require(len(counts) == 1, f"Missing or duplicate bypass counter comparison: {case}")
            shim_before, shim_after, native_before, native_after = map(int, counts[0])
            require(shim_before > 0 and shim_after == shim_before + 2, f"Shim counter control failed: {case}")
            require(native_before == shim_after and native_after == native_before,
                    f"Native IPC changed the shim call count: {case}")
        elif case in DENIED_CAPS or case in LIMITED_CAPS:
            # 終了0はゲストがerrnoを検査した結果。起動設定も照合し、別の権限での成功を混ぜない。
            require(actual == "", f"Unexpected policy output: {case}")
            if case in DENIED_CAPS:
                require(f"name={DENIED_CAPS[case]} " not in diagnostic, f"Denied capability was supplied: {case}")
            else:
                require(re.search(rf"name={LIMITED_CAPS[case]} quota=65536 used=\d+", diagnostic),
                        f"Expected a 64 KiB allocator: {case}")
        else:
            require(actual == (work / f"{case}.native.out").read_text(), f"Native output mismatch: {case}")
        print(f"PASS: {case}")


def main():
    parser = argparse.ArgumentParser(description="Run the small L4Re test suite")
    parser.add_argument("case", choices=CASES)
    parser.add_argument("work", type=Path)
    parser.add_argument("log", type=Path)
    parser.add_argument("--timeout", type=float, default=90)
    args, command = parser.parse_known_args()
    if command[:1] == ["--"]:
        command = command[1:]
    try:
        validate(capture(command, args.log, args.timeout), args.case, args.work)
    except (OSError, RuntimeError) as error:
        parser.exit(1, f"FAIL: {error}. Log: {args.log}\n")


if __name__ == "__main__":
    main()
