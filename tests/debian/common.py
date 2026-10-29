"""100件で共用するプロセス起動・入力作成・ELFの記録。"""

import hashlib
import os
from pathlib import Path
import re
import resource
import signal
import shutil
import stat
import struct
import subprocess
import time



TRACE = re.compile(rb"^\[zcomp\] nr=(\d+) -> (-?\d+)$", re.MULTILINE)

EXEC_ATTEMPT = re.compile(rb"^\[zcomp\] nr=(59|322) phase=attempt$", re.MULTILINE)

INITIALIZATION = re.compile(rb"^zcomp: .* mode=zpoline$", re.MULTILINE)

WORK_DIR = Path("/work")

RESULTS_DIR = WORK_DIR / "results"

FIXED_EPOCH = 1790812800

BASE_ENVIRONMENT = dict(
    PATH="/usr/sbin:/usr/bin:/sbin:/bin",
    HOME="/home/testuser",
    USER="testuser",
    LOGNAME="testuser",
    LC_ALL="C",
    TZ="UTC",
)


def write_file(path, data, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data.encode() if isinstance(data, str) else data)
    path.chmod(mode)


def run_setup(command, cwd=None, stdin=None, check=True, timeout=90):
    result = subprocess.run(
        [str(x) for x in command],
        cwd=cwd,
        input=stdin,
        capture_output=True,
        timeout=timeout,
        env=dict(os.environ, LC_ALL="C", TZ="UTC"),
    )
    if check and result.returncode:
        raise RuntimeError(f'{command}: {result.returncode}: {result.stderr.decode(errors="replace")}')
    return result


def digest(data):
    return hashlib.sha256(data).hexdigest()


def describe_binary(path):
    data = Path(path).read_bytes()
    # 静的ELFはLD_PRELOADを読まないため、素通りした成功を捕捉の成功と数えない。
    dynamic = False
    if data[:6] == b"\x7fELF\x02\x01" and len(data) >= 64:
        offset = struct.unpack_from("<Q", data, 32)[0]
        size, count = struct.unpack_from("<HH", data, 54)
        for i in range(count):
            at = offset + i * size
            if at + 4 <= len(data) and struct.unpack_from("<I", data, at)[0] == 3:
                dynamic = True
    return {"path": str(Path(path).resolve()), "sha256": digest(data), "has_interpreter": dynamic}


def run_process(command, env, cwd, stem, timeout, stdin, identity=None):
    started = time.monotonic()

    def prepare():
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        # VM内の比較でも管理者権限が対象へ漏れないよう、exec直前に実効・実IDを揃える。
        if identity is not None:
            uid, gid = identity
            os.setgroups([])
            os.setgid(gid)
            os.setuid(uid)

    # 失敗時にコアを残さず、タイムアウトでは子プロセス群も終了させる。
    with Path(str(stem) + ".stdout").open("wb") as out, Path(str(stem) + ".stderr").open("wb") as err:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            stdin=subprocess.PIPE,
            stdout=out,
            stderr=err,
            start_new_session=True,
            preexec_fn=prepare,
        )
        timed_out = False
        try:
            process.communicate(stdin, timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
    return {
        "returncode": process.returncode,
        "timeout": timed_out,
        "seconds": round(time.monotonic() - started, 4),
    }




def case_directory(number):
    return WORK_DIR / f"case{number:02d}"


def package_names():
    return [line.split("\t")[1] for line in (WORK_DIR / "packages-100.tsv").read_text().splitlines()[1:]]


def apt_options():
    directory = case_directory(26)
    return [
        "-o",
        f"Dir::Etc::sourcelist={directory}/sources.list",
        "-o",
        "Dir::Etc::sourceparts=-",
        "-o",
        f"Dir::State::lists={directory}/lists",
        "-o",
        f"Dir::Cache={directory}/cache",
    ]


def describe_executable(command, cwd):
    path = Path(shutil.which(command) or cwd / command).absolute()
    data = path.read_bytes()
    info = describe_binary(path)
    info.update(
        requested_path=str(path),
        mode=oct(path.stat().st_mode & 0o7777),
        owner_uid=path.stat().st_uid,
        owner_gid=path.stat().st_gid,
        package=run_setup(["dpkg-query", "-S", str(path)], check=False).stdout.decode().strip(),
    )
    try:
        info["file_capabilities"] = os.getxattr(path, "security.capability").hex()
    except OSError:
        info["file_capabilities"] = None
    if data.startswith(b"#!"):
        interpreter = data.splitlines()[0][2:].strip().split()[0].decode()
        info["interpreter"] = describe_executable(interpreter, cwd)
    elif data[:6] == b"\x7fELF\x02\x01":
        offset = struct.unpack_from("<Q", data, 32)[0]
        size, count = struct.unpack_from("<HH", data, 54)
        for i in range(count):
            at = offset + i * size
            if struct.unpack_from("<I", data, at)[0] == 3:
                start = struct.unpack_from("<Q", data, at + 8)[0]
                length = struct.unpack_from("<Q", data, at + 32)[0]
                loader = data[start : start + length].rstrip(b"\0").decode()
                info["elf_loader"] = describe_executable(loader, cwd)
    return info


def file_snapshot(directory):
    result = {}
    for path in sorted(directory.rglob("*")):
        if path.is_file():
            result[str(path.relative_to(directory))] = dict(
                sha256=digest(path.read_bytes()), mode=oct(path.stat().st_mode & 0o7777)
            )
    return result


def tree_snapshot(folder):
    result = {}
    for path in sorted(folder.rglob("*")):
        name = str(path.relative_to(folder))
        if path.is_symlink():
            result[name] = dict(link=os.readlink(path))
        elif path.is_file():
            result[name] = dict(
                sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                mode=oct(stat.S_IMODE(path.stat().st_mode)),
            )
    return result


def json_serializable(value):
    if isinstance(value, bytes):
        return value.decode()
    if isinstance(value, dict):
        return {key: json_serializable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_serializable(item) for item in value]
    return value
