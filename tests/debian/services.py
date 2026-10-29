"""サービスの起動・待機と、CLI固有の応答形式を検査する補助処理。"""

from contextlib import contextmanager
from datetime import datetime, timezone
import errno
import fcntl
import hashlib
import os
from pathlib import Path
import pty
import select
import struct
import subprocess
import termios
import time
import common
from common import RESULTS_DIR, FIXED_EPOCH, write_file, run_setup, describe_executable


def require(value, message):
    if not value:
        raise AssertionError(message)


class MissingEnvironment(RuntimeError):
    pass


def wait_for(predicate, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise TimeoutError("The declared readiness condition was not reached")


@contextmanager
def helper(case):
    def identity():
        os.setgroups([])
        os.setgid(1100)
        os.setuid(1100)

    p = subprocess.Popen(
        [str(case.file("zcomp-sleeper"))],
        cwd=case.directory,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=identity,
    )
    try:
        require(select.select([p.stdout], [], [], 5)[0], "The helper did not signal readiness")
        pid, fd = map(int, p.stdout.readline().split())
        require(pid == p.pid and fd >= 0, "Invalid helper identity or file descriptor")
        case.record["runtime_bindings"] = dict(helper_pid=pid, helper_fd=fd)
        yield p, fd
    finally:
        p.communicate(b"x", timeout=5)


def bus(service, path, interface, method, signature=None, *arguments):
    command = ["busctl", "--system", "--timeout=5", "call", service, path, interface, method]
    if signature:
        command.extend([signature, *arguments])
    return run_setup(command)


def service(name):
    p = run_setup(["systemctl", "start", name], check=False, timeout=30)
    if p.returncode:
        raise MissingEnvironment(
            f'The required service could not start: {name}: {p.stderr.decode(errors="replace")}'
        )


def dummy():
    p = run_setup(["ip", "link", "show", "zc0"], check=False)
    if p.returncode:
        p = run_setup(["ip", "link", "add", "zc0", "type", "dummy"], check=False)
        if p.returncode:
            raise MissingEnvironment(
                "The guest kernel cannot create the required dummy interface: " + p.stderr.decode()
            )
        run_setup(["ip", "link", "set", "dev", "zc0", "address", "02:00:00:00:00:36"])
        run_setup(["ip", "addr", "add", "198.18.0.1/24", "dev", "zc0"])
        run_setup(["ip", "link", "set", "zc0", "up"])


def icc(case):
    data = case.read("profile.icc")
    case.check(
        len(data) >= 132 and struct.unpack(">I", data[:4])[0] == len(data) and data[36:40] == b"acsp",
        "The ICC profile header is invalid",
    )
    stamp = struct.unpack(">6H", data[24:36])
    epoch = datetime(*stamp, tzinfo=timezone.utc).timestamp()
    case.check(epoch == FIXED_EPOCH, "The ICC creation date differs from SOURCE_DATE_EPOCH")
    count = struct.unpack(">I", data[128:132])[0]
    tags = {}
    for i in range(count):
        key, offset, length = struct.unpack_from(">4sII", data, 132 + i * 12)
        case.check(offset + length <= len(data), "An ICC tag exceeds the profile")
        tags[key.decode()] = data[offset : offset + length]
    palette = tags.get("ncl2", b"")
    case.check(len(palette) >= 84 and palette[:4] == b"ncl2", "The named color tag is missing")
    colors, coordinates = struct.unpack(">II", palette[12:20])
    case.check(colors == 2, "The ICC named color count differs")
    records = []
    for i in range(colors):
        offset = 84 + i * (38 + coordinates * 2)
        name = palette[offset : offset + 32].split(b"\0")[0].decode()
        values = struct.unpack_from(">3H", palette, offset + 32)
        lab = (values[0] * 100 / 65535, values[1] * 255 / 65535 - 128, values[2] * 255 / 65535 - 128)
        if name == "ZcompRed":
            case.check(
                50 < lab[0] < 60 and 70 < lab[1] < 90 and 60 < lab[2] < 80,
                "The red palette coordinate is outside the expected Lab range",
            )
        elif name == "ZcompBlue":
            case.check(
                20 < lab[0] < 40 and 50 < lab[1] < 90 and -120 < lab[2] < -90,
                "The blue palette coordinate is outside the expected Lab range",
            )
        records.append(name)
    case.check(records == ["ZcompRed", "ZcompBlue"], "The ICC color names differ")
    case.observe("icc_tags", {key: hashlib.sha256(value).hexdigest() for key, value in sorted(tags.items())})
    header = bytearray(data[:128])
    header[24:36] = bytes(12)
    header[84:100] = bytes(16)
    case.observe("icc_header_without_validated_date_and_id", header.hex())
    case.observe("icc_sha256", hashlib.sha256(data).hexdigest())


def pinentry(case):
    master, slave = pty.openpty()
    os.chown(os.ttyname(slave), 1100, 1100)
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    ttyname = os.ttyname(slave)
    command = ["/usr/bin/pinentry-curses", "--ttyname", ttyname, "--ttytype", "xterm"]
    stem = RESULTS_DIR / "61-0"
    item = dict(
        command=command,
        expected_returncode=0,
        comparison="pinentry",
        binary=describe_executable(command[0], case.directory),
        uid=1100,
        epoch_start=time.time(),
    )

    def identity():
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
        os.setgroups([])
        os.setgid(1100)
        os.setuid(1100)

    output, terminal = bytearray(), bytearray()
    with Path(str(stem) + ".stderr").open("wb") as err:
        p = subprocess.Popen(
            command,
            env=dict(case.environment, TERM="xterm"),
            cwd=case.directory,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=err,
            preexec_fn=identity,
            pass_fds=(slave,),
        )
        os.close(slave)
        item["pid"] = p.pid
        deadline = time.monotonic() + 20
        entered, bye = False, False
        try:
            p.stdin.write(b"SETDESC Zcomp PIN fixture\nSETPROMPT PIN:\nGETPIN\n")
            p.stdin.flush()
            while time.monotonic() < deadline and p.poll() is None:
                for fd in select.select([master, p.stdout], [], [], 0.1)[0]:
                    try:
                        data = os.read(fd if isinstance(fd, int) else fd.fileno(), 65536)
                    except OSError as error:
                        if error.errno == errno.EIO:
                            continue
                        raise
                    if fd == master:
                        terminal.extend(data)
                    else:
                        output.extend(data)
                if not entered and b"PIN:" in terminal:
                    os.write(master, b"zcomp-pin\r")
                    entered = True
                if not bye and b"D zcomp-pin\n" in output:
                    p.stdin.write(b"BYE\n")
                    p.stdin.flush()
                    bye = True
            if p.poll() is None:
                p.kill()
                p.wait()
                item["timeout"] = True
            else:
                item["timeout"] = False
            output.extend(p.stdout.read())
        finally:
            if p.poll() is None:
                p.kill()
                p.wait()
            os.close(master)
        item.update(returncode=p.returncode, epoch_end=time.time())
    write_file(Path(str(stem) + ".stdout"), bytes(output))
    write_file(Path(str(stem) + ".pty"), bytes(terminal))
    data = output + Path(str(stem) + ".stderr").read_bytes()
    item.update(
        hook_calls=len(common.TRACE.findall(data)), initializations=len(common.INITIALIZATION.findall(data))
    )
    case.record["steps"].append(item)
    case.check(
        not item["timeout"] and p.returncode == 0 and entered and bye and b"ERR " not in output,
        "The PIN dialog did not complete the declared Assuan exchange",
    )
    case.check(
        b"D zcomp-pin\n" in output and b"Zcomp PIN fixture" in terminal,
        "The PIN reply or dialog prompt differs",
    )
    case.observe("pinentry", dict(prompt_seen=True, pin="zcomp-pin", protocol_ok=True))
