"""ケースを実行して証拠を保存する。対象の操作・成功条件はworkloads.pyを参照。"""

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import struct
import subprocess
import time
import traceback
import common
from services import MissingEnvironment, require
from workloads import cli_steps, cli_expectations, run_service_case
from common import (
    WORK_DIR,
    RESULTS_DIR,
    BASE_ENVIRONMENT,
    write_file,
    run_setup,
    case_directory,
    package_names,
    describe_executable,
    file_snapshot,
    tree_snapshot,
    json_serializable,
)


TRACE = re.compile(rb"(?m)^\[zcomp\] nr=\d+ (?:-> -?\d+|phase=attempt)\n")
INIT = re.compile(
    rb"(?m)^zcomp: segments=\d+ candidates=\d+ accepted=\d+ covered=\d+ ambiguous=\d+ undecodable=\d+ mode=zpoline\n"
)


def clean(data):
    return TRACE.sub(b"", INIT.sub(b"", data))


def execute_cli(mode):
    packages = package_names()[:30]
    RESULTS_DIR.mkdir(exist_ok=True)
    for filename in ("installed.tsv", "debs.sha256", "packages.tsv", "preparation.json"):
        shutil.copy2(WORK_DIR / filename, RESULTS_DIR / filename)
    before = {number: file_snapshot(case_directory(number)) for number in range(1, 31)}
    records = []
    problems = json.loads((WORK_DIR / "preparation.json").read_text())
    # デーモンは対照環境であり、CLI側の捕捉実績へ混ぜない。
    run_setup(["systemctl", "start", "zcomp-probe.service"])
    Path("/run/sshd").mkdir(exist_ok=True)
    sshd = subprocess.Popen(
        ["/usr/sbin/sshd", "-D", "-e", "-f", str(case_directory(18) / "sshd_config")],
        stdout=(RESULTS_DIR / "sshd.stdout").open("wb"),
        stderr=(RESULTS_DIR / "sshd.stderr").open("wb"),
    )
    for number, package in enumerate(packages, 1):
        record = dict(number=number, package=package, steps=[], mode=mode)
        print(f"CASE_BEGIN number={number} package={package} mode={mode}", flush=True)
        try:
            if str(number) in problems:
                raise RuntimeError(problems[str(number)])
            if package == "systemd-sysv" and not Path("/run/utmp").exists():
                raise RuntimeError("The booted system has no /run/utmp runlevel record")
            if package == "dmsetup":
                run_setup(["modprobe", "dm-zero"])
            directory = case_directory(number)
            env = dict(BASE_ENVIRONMENT)
            root = package in ("cron", "systemd", "base-passwd", "passwd", "libpam-modules-bin", "dmsetup")
            if root:
                env.update(HOME="/root", USER="root", LOGNAME="root")
            if package == "sensible-utils":
                env["PAGER"] = "/usr/bin/cat"
            if package == "debconf":
                env["DEBCONF_SYSTEMRC"] = str(directory / "debconf.conf")
            if mode == "hooked":
                env.update(LD_PRELOAD="/work/libzcomp.so", ZCOMP_TRACE="1")
            lock = None
            outputs = []
            for i, (command, expected) in enumerate(cli_steps(package)):
                if package == "util-linux" and i == 0:
                    lock = (directory / "lockfile").open("w")
                    fcntl.flock(lock, fcntl.LOCK_EX)
                elif package == "util-linux" and lock:
                    lock.close()
                    lock = None
                command[0] = shutil.which(command[0]) or command[0]
                stem = RESULTS_DIR / f"{number:02d}-{i}"
                item = dict(
                    command=command,
                    expected_returncode=expected,
                    binary=describe_executable(command[0], directory),
                    uid=0 if root else 1100,
                    epoch_start=time.time(),
                )
                stdin = (
                    b"GET zcomp/probe\nSET zcomp/probe beta\nGET zcomp/probe\n"
                    if package == "debconf"
                    else b""
                )
                launched = command
                launched_env = env
                item.update(
                    common.run_process(
                        launched, launched_env, directory, stem, 12, stdin, None if root else (1100, 1100)
                    )
                )
                item["epoch_end"] = time.time()
                out = Path(str(stem) + ".stdout").read_bytes()
                outputs.append(out)
                err = Path(str(stem) + ".stderr").read_bytes()
                # logsaveのように子のstderrをstdoutへ転送するCLIでも、診断の行き先を
                # 「捕捉がなかった」と取り違えない。生の両streamは別途保存する。
                diagnostic_streams = err + b"\n" + out
                calls = common.TRACE.findall(diagnostic_streams)
                item.update(
                    hook_calls=len(calls),
                    initializations=len(common.INITIALIZATION.findall(diagnostic_streams)),
                    exec_attempts=len(common.EXEC_ATTEMPT.findall(diagnostic_streams)),
                    stdout_sha256=common.digest(out),
                    stderr_sha256=common.digest(err),
                )
                record["steps"].append(item)
                print(
                    f'STEP_END number={number} step={i} rc={item["returncode"]} hooks={len(calls)}',
                    flush=True,
                )
                if item["timeout"] or item["returncode"] != expected:
                    break
            record["files_before"] = before[number]
            record["files_after"] = file_snapshot(directory)
            # 最終DBの状態も出力以外の副作用として残す。
            if package == "cron":
                spool = Path("/var/spool/cron/crontabs/zcomp-fixture")
                if spool.exists():
                    shutil.copy2(spool, RESULTS_DIR / "07-crontab.final")
                # setgidによる素通りを推測だけで済ませず、stdin待ちの同じ配布ELFで
                # カーネルが渡したAT_SECUREと実効GIDを読む。権限bitは変更しない。
                with (RESULTS_DIR / "07-secure-probe.stdout").open("wb") as out, (
                    RESULTS_DIR / "07-secure-probe.stderr"
                ).open("wb") as err:
                    probe = subprocess.Popen(
                        ["/usr/bin/crontab", "-u", "zcomp-fixture", "-"],
                        stdin=subprocess.PIPE,
                        stdout=out,
                        stderr=err,
                        env=env,
                    )
                    try:
                        auxv = Path(f"/proc/{probe.pid}/auxv").read_bytes()
                        values = dict(struct.iter_unpack("<QQ", auxv))
                        status = Path(f"/proc/{probe.pid}/status").read_text()
                        record["secure_execution_probe"] = dict(
                            at_secure=values.get(23),
                            gid_line=next(line for line in status.splitlines() if line.startswith("Gid:")),
                        )
                    finally:
                        probe.communicate((directory / "crontab.txt").read_bytes(), timeout=12)
                    record["secure_execution_probe"]["returncode"] = probe.returncode
            if package == "logsave" and (directory / "capture.log").exists():
                shutil.copy2(directory / "capture.log", RESULTS_DIR / "28-capture.log")
            if package == "dmsetup":
                record["device_removed"] = not Path("/dev/mapper/zcomp-probe").exists()
            record["execution_status"] = (
                "TIMEOUT"
                if any(s["timeout"] for s in record["steps"])
                else (
                    "EXPECTED"
                    if len(record["steps"]) == len(cli_steps(package))
                    and all(s["returncode"] == s["expected_returncode"] for s in record["steps"])
                    else "UNEXPECTED"
                )
            )
            if record["execution_status"] == "EXPECTED":
                record["expectations_met"] = cli_expectations(package, outputs, record)
                if not record["expectations_met"]:
                    record["execution_status"] = "UNEXPECTED_OUTPUT"
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            record.update(execution_status="BLOCKED_ENV", reason=str(error))
        records.append(record)
        (RESULTS_DIR / "results.json").write_text(
            json.dumps(
                dict(
                    mode=mode,
                    kernel=os.uname().release,
                    library=common.describe_binary("/work/libzcomp.so"),
                    environment=BASE_ENVIRONMENT,
                    scope="Aggregate interception evidence is not complete per-image or syscall coverage.",
                    cases=records,
                ),
                indent=2,
            )
            + "\n"
        )
        print(f'CASE_END number={number} status={record["execution_status"]}', flush=True)
    sshd.terminate()
    sshd.wait(timeout=5)


class Case:
    ROOT_PACKAGES = {
        "udisks2",
        "mount",
        "grub2-common",
        "initramfs-tools",
        "cups-daemon",
        "sgml-base",
        "ucf",
        "avahi-daemon",
        "init-system-helpers",
        "adduser",
        "ssl-cert",
        "rtkit",
        "libcap2-bin",
        "logrotate",
        "xml-core",
        "openssh-server",
    }

    def __init__(self, number, mode, package):
        self.number, self.mode, self.package = number, mode, package
        self.directory = WORK_DIR / f"case{number:02d}"
        self.run_as_root = package in self.ROOT_PACKAGES
        self.environment = dict(BASE_ENVIRONMENT)
        if self.run_as_root:
            self.environment.update(HOME="/root", USER="root", LOGNAME="root")
        if mode == "hooked":
            self.environment.update(LD_PRELOAD="/work/libzcomp.so", ZCOMP_TRACE="1")
        self.record = dict(
            number=number,
            package=package,
            mode=mode,
            steps=[],
            observations={},
            files_before=tree_snapshot(self.directory),
            epoch_start=time.time(),
        )

    def check(self, value, message):
        require(value, message)

    def observe(self, key, value):
        self.record["observations"][key] = value

    def file(self, name):
        return self.directory / name

    def read(self, name):
        return self.file(name).read_bytes()

    def run_command(self, command, expected=0, stdin=b"", env=None, comparison="exact", timeout=60):
        command = [str(x) for x in command]
        command[0] = shutil.which(command[0]) or command[0]
        i = len(self.record["steps"])
        stem = RESULTS_DIR / f"{self.number:02d}-{i}"
        item = dict(
            command=command,
            expected_returncode=expected,
            binary=describe_executable(command[0], self.directory),
            uid=0 if self.run_as_root else 1100,
            epoch_start=time.time(),
            comparison=comparison,
        )
        active_env = dict(self.environment, **(env or {}))
        item.update(environment=active_env, stdin_sha256=hashlib.sha256(stdin).hexdigest())
        launched = command
        item.update(
            common.run_process(
                launched,
                active_env,
                self.directory,
                stem,
                timeout,
                stdin,
                None if self.run_as_root else (1100, 1100),
            )
        )
        item["epoch_end"] = time.time()
        out, err = (Path(str(stem) + ".stdout").read_bytes(), Path(str(stem) + ".stderr").read_bytes())
        both = out + b"\n" + err
        item.update(
            hook_calls=len(common.TRACE.findall(both)),
            initializations=len(common.INITIALIZATION.findall(both)),
            stdout_sha256=hashlib.sha256(out).hexdigest(),
            stderr_sha256=hashlib.sha256(err).hexdigest(),
        )
        self.record["steps"].append(item)
        print(
            f'STEP_END number={self.number} step={i} rc={item["returncode"]} hooks={item["hook_calls"]}',
            flush=True,
        )
        if item["timeout"]:
            raise TimeoutError("The target command exceeded the declared timeout")
        self.check(
            item["returncode"] == expected,
            f'Unexpected return code: expected {expected}, got {item["returncode"]}',
        )
        return clean(out), clean(err)

    @contextmanager
    def daemon(self, command):
        command = [str(x) for x in command]
        command[0] = shutil.which(command[0]) or command[0]
        i = len(self.record["steps"])
        stem = RESULTS_DIR / f"{self.number:02d}-{i}"
        item = dict(
            command=command,
            expected_returncode=0,
            comparison="daemon",
            binary=describe_executable(command[0], self.directory),
            uid=0,
            epoch_start=time.time(),
        )
        launched, active_env = command, self.environment
        with Path(str(stem) + ".stdout").open("wb") as out, Path(str(stem) + ".stderr").open("wb") as err:
            target = subprocess.Popen(
                launched,
                cwd=self.directory,
                env=active_env,
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=err,
                start_new_session=True,
            )
            item["pid"] = target.pid
            try:
                yield target
            finally:
                if target.poll() is None:
                    os.killpg(target.pid, signal.SIGTERM)
                try:
                    target.wait(timeout=10)
                    timed_out = False
                except subprocess.TimeoutExpired:
                    os.killpg(target.pid, signal.SIGKILL)
                    target.wait()
                    timed_out = True
                item.update(returncode=target.returncode, timeout=timed_out, epoch_end=time.time())
                data = (
                    Path(str(stem) + ".stdout").read_bytes()
                    + b"\n"
                    + Path(str(stem) + ".stderr").read_bytes()
                )
                item.update(
                    hook_calls=len(common.TRACE.findall(data)),
                    initializations=len(common.INITIALIZATION.findall(data)),
                )
                self.record["steps"].append(item)
                self.check(
                    not timed_out and target.returncode in (0, -signal.SIGTERM),
                    "The daemon did not exit cleanly",
                )


def execute_services(mode):
    data = json.loads((RESULTS_DIR / "results.json").read_text())
    problems = json.loads((WORK_DIR / "preparation-100.json").read_text())
    packages = package_names()
    for filename in (
        "packages-100.tsv",
        "debs-100.sha256",
        "dependency-debs-100.sha256",
        "preparation-100.json",
        "fixture-manifest-100.json",
    ):
        shutil.copy2(WORK_DIR / filename, RESULTS_DIR / filename)
    for number in range(31, 101):
        case = Case(number, mode, packages[number - 1])
        print(f"CASE_BEGIN number={number} package={packages[number - 1]} mode={mode}", flush=True)
        try:
            if str(number) in problems:
                case.record.update(
                    execution_status="PLANNED",
                    reason=problems[str(number)]["reason"],
                    preparation_status="PREPARATION_FAILED",
                )
            else:
                run_service_case(case)
                case.record.update(execution_status="EXPECTED", expectations_met=True)
        except MissingEnvironment as error:
            case.record.update(execution_status="BLOCKED_ENV", reason=str(error))
        except (TimeoutError, subprocess.TimeoutExpired) as error:
            case.record.update(execution_status="TIMEOUT", reason=str(error))
        except AssertionError as error:
            case.record.update(
                execution_status="UNEXPECTED_OUTPUT", reason=str(error), traceback=traceback.format_exc()
            )
        except Exception as error:
            # 検査器の例外を対象CLIの失敗へ混ぜず、未判定のまま原因を残す。
            case.record.update(
                execution_status="HARNESS_ERROR", reason=str(error), traceback=traceback.format_exc()
            )
        case.record.update(files_after=tree_snapshot(case.directory), epoch_end=time.time())
        data["cases"].append(json_serializable(case.record))
        data.update(
            denominator=100,
            scope="One preregistered workload per package; behavior and hook evidence are separate. No claim of complete syscall coverage.",
        )
        write_file(RESULTS_DIR / "results.json", json.dumps(data, indent=2))
        print(f'CASE_END number={number} status={case.record["execution_status"]}', flush=True)


def execute(mode):
    execute_cli(mode)
    execute_services(mode)
