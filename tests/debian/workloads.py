"""パッケージごとの代表操作と成功条件。番号は結果ファイルとの対応にだけ使う。"""

from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import struct
import subprocess
import time
import xml.etree.ElementTree as ET
from services import bus, dummy, helper, icc, MissingEnvironment, pinentry, service, wait_for
from common import (
    WORK_DIR,
    RESULTS_DIR,
    FIXED_EPOCH,
    write_file,
    run_setup,
    case_directory,
    apt_options,
    tree_snapshot,
)


def cli_steps(package):
    return {
        "dash": [(["dash", "shell-case.sh"], 0)],
        "sensible-utils": [(["sensible-pager", "text.txt"], 0)],
        "libpam-runtime": [(["pam_getenv", "ZCOMP_PROBE"], 0)],
        "debconf": [(["debconf-communicate", "zcomp"], 0)],
        "dbus-daemon": [(["dbus-run-session", "--", "./session-client.sh"], 0)],
        "dbus-bin": [(["dbus-uuidgen", "--get=machine-id"], 0)],
        "cron": [
            (["crontab", "-u", "zcomp-fixture", "crontab.txt"], 0),
            (["crontab", "-u", "zcomp-fixture", "-l"], 0),
        ],
        "udev": [
            (
                [
                    "udevadm",
                    "info",
                    "--query=property",
                    "--property=DEVPATH,SUBSYSTEM,MAJOR,MINOR",
                    "--path=/sys/class/mem/null",
                ],
                0,
            )
        ],
        "debianutils": [(["run-parts", "./parts"], 0)],
        "systemd-sysv": [(["runlevel"], 0)],
        "systemd": [
            (
                [
                    "systemctl",
                    "--no-pager",
                    "show",
                    "zcomp-probe.service",
                    "--property=Id,LoadState,ActiveState,Result",
                ],
                0,
            )
        ],
        "perl-base": [(["perl", "aggregate.pl", "numbers.txt"], 0)],
        "base-passwd": [
            (
                [
                    "update-passwd",
                    "--dry-run",
                    "--verbose",
                    "--passwd-master",
                    "passwd.master",
                    "--group-master",
                    "group.master",
                    "--passwd",
                    "passwd",
                    "--group",
                    "group",
                    "--shadow",
                    "shadow",
                ],
                2,
            )
        ],
        "passwd": [(["passwd", "-S", "zcomp-fixture"], 0)],
        "util-linux": [
            (["flock", "-n", "lockfile", "/usr/bin/printf", "lock-ok\n"], 1),
            (["flock", "-n", "lockfile", "/usr/bin/printf", "lock-ok\n"], 0),
        ],
        "libc-bin": [(["iconv", "-f", "UTF-8", "-t", "UTF-16LE", "utf8.txt"], 0)],
        "coreutils": [(["sort", "-n", "numbers.txt"], 0)],
        "openssh-client": [(["ssh", "-F", "ssh_config", "probe"], 0)],
        "tar": [
            (["tar", "-cf", "archive.tar", "input/text.txt"], 0),
            (["tar", "-xf", "archive.tar", "-C", "extracted"], 0),
        ],
        "bash": [(["bash", "shell-case.sh"], 0)],
        "dpkg": [
            (["dpkg-deb", "-f", "fixture.deb", "Package", "Version"], 0),
            (["dpkg-deb", "-x", "fixture.deb", "extracted"], 0),
        ],
        "popularity-contest": [(["popularity-contest"], 0)],
        "diffutils": [
            (["diff", "-u", "--label", "before", "--label", "after", "before.txt", "after.txt"], 1)
        ],
        "libpam-modules-bin": [(["faillock", "--dir", "./tally", "--user", "zcomp-fixture"], 0)],
        "gzip": [(["gzip", "-n", "-c", "text.txt"], 0)],
        "apt": [(["apt-cache", *apt_options(), "show", "zcomp-fixture"], 0)],
        "sqv": [
            (
                [
                    "sqv",
                    "--policy-as-of",
                    "2026-10-01",
                    "--not-before",
                    "2026-10-01",
                    "--not-after",
                    "2026-10-02",
                    "--keyring",
                    "keyring.pgp",
                    "--signature-file",
                    "message.sig",
                    "message.txt",
                ],
                0,
            )
        ],
        "logsave": [(["logsave", "capture.log", "/usr/bin/printf", "log-ok\n"], 0)],
        "e2fsprogs": [(["dumpe2fs", "-h", "ext4.img"], 0)],
        "dmsetup": [
            (["dmsetup", "create", "zcomp-probe", "--table", "0 2048 zero"], 0),
            (["dmsetup", "table", "zcomp-probe"], 0),
            (["dmsetup", "remove", "zcomp-probe"], 0),
        ],
    }[package]


def cli_expectations(package, outputs, record):
    out = b"".join(outputs)
    unchanged = record["files_before"] == record["files_after"]
    expected = {
        "dash": lambda: out == b"sum=7\nALPHA\nBETA\n",
        "sensible-utils": lambda: out == b"alpha\nbeta\n",
        "libpam-runtime": lambda: out.strip() == b"alpha" and unchanged,
        "debconf": lambda: len(out.splitlines()) == 3
        and out.splitlines()[0] == b"0 alpha"
        and out.splitlines()[-1] == b"0 beta"
        and b"Value: beta" in (case_directory(4) / "config.dat").read_bytes(),
        "dbus-daemon": lambda: b"org.freedesktop.DBus" in out and b"array" in out,
        "dbus-bin": lambda: out.strip() == b"0123456789abcdef0123456789abcdef" and unchanged,
        "cron": lambda: out.strip() == b"17 3 * * * /usr/bin/true",
        "udev": lambda: set(out.splitlines())
        == {b"DEVPATH=/devices/virtual/mem/null", b"SUBSYSTEM=mem", b"MAJOR=1", b"MINOR=3"},
        "debianutils": lambda: out == b"10-first\n20-second\n"
        and (case_directory(9) / "record.txt").read_bytes() == out,
        "systemd-sysv": lambda: bool(re.fullmatch(rb"[N0-6S] [0-6S]\n", out)),
        "systemd": lambda: set(out.splitlines())
        == {b"Id=zcomp-probe.service", b"LoadState=loaded", b"ActiveState=active", b"Result=success"},
        "perl-base": lambda: out == b"7\n",
        "base-passwd": lambda: out
        == b'Adding group "daemon" (1)\nAdding user "daemon" (1)\nWould commit 2 changes\n'
        and unchanged,
        "passwd": lambda: out.startswith(b"zcomp-fixture L 2024-10-04 0 99999 7 -1"),
        "util-linux": lambda: out == b"lock-ok\n",
        "libc-bin": lambda: out == "ASCII 日本語 😀\n".encode("utf-16le"),
        "coreutils": lambda: out == b"1\n1\n2\n3\n",
        "openssh-client": lambda: out == b"ssh-ok\n",
        "tar": lambda: (case_directory(19) / "extracted/input/text.txt").is_file()
        and (case_directory(19) / "extracted/input/text.txt").read_bytes() == b"alpha\nbeta\n",
        "bash": lambda: out == b"sum=7\nALPHA\nBETA\n",
        "dpkg": lambda: b"Package: zcomp-fixture" in out
        and b"Version: 1.0" in out
        and (case_directory(21) / "extracted/usr/share/zcomp-fixture/text.txt").is_file(),
        "popularity-contest": lambda: out.startswith(b"POPULARITY-CONTEST-0 ")
        and b"END-POPULARITY-CONTEST-0 " in out
        and len(out.splitlines()) > 10,
        "diffutils": lambda: out == b"--- before\n+++ after\n@@ -1,2 +1,2 @@\n alpha\n-beta\n+gamma\n",
        "libpam-modules-bin": lambda: b"zcomp-fixture:" in out and b"zcomp-failure" in out and unchanged,
        "gzip": lambda: __import__("gzip").decompress(out) == b"alpha\nbeta\n",
        "apt": lambda: b"Package: zcomp-fixture\n" in out and b"Version: 1.0\n" in out,
        "sqv": lambda: any(
            line.split(":")[9].encode() in out
            for line in (case_directory(27) / "fingerprint").read_text().splitlines()
            if line.startswith("fpr:")
        ),
        "logsave": lambda: b"log-ok\n" in out
        and b"log-ok\n" in (case_directory(28) / "capture.log").read_bytes(),
        "e2fsprogs": lambda: b"01234567-89ab-cdef-0123-456789abcdef" in out
        and b"Block size:               4096" in out
        and unchanged,
        "dmsetup": lambda: out.strip() == b"0 2048 zero" and record.get("device_removed", False),
    }
    return expected[package]()


def check_openssl(case):
    out, _ = case.run_command(["openssl", "dgst", "-sha256", "text.txt"])
    digest = hashlib.sha256(case.read("text.txt")).hexdigest().encode()
    case.check(out == b"SHA2-256(text.txt)= " + digest + b"\n", "The SHA-256 output differs")


def check_groff_base(case):
    out, _ = case.run_command(["groff", "-Tascii", "input.roff"])
    case.check(
        out.startswith(b"alpha\nbeta\n") and set(out[11:]) <= {10}, "Unexpected rendered text or page padding"
    )


def check_man_db(case):
    out, _ = case.run_command(
        ["man", "-l", "fixture.1"],
        env={
            "MANPAGER": "/usr/bin/cat",
            "PAGER": "/usr/bin/cat",
            "MANWIDTH": "80",
            "MAN_KEEP_FORMATTING": "0",
            "GROFF_NO_SGR": "1",
        },
    )
    plain = re.sub(rb".\x08", b"", out)
    case.check(
        all(x in plain for x in (b"NAME", b"DESCRIPTION", b"alpha beta", b"2026-10-01")),
        "The local manual was not rendered",
    )


def check_procps(case):
    with helper(case) as (p, _):
        out, _ = case.run_command(["ps", "-p", p.pid, "-o", "comm="])
        case.check(out == b"zcomp-sleeper\n", "The process name does not match the helper")


def check_bsdextrautils(case):
    out, _ = case.run_command(["hexdump", "-v", "-e", '1/1 "%02x "', "bytes.bin"])
    case.check(out == b"00 01 fe ff ", "The byte representation differs")


def check_iproute2(case):
    dummy()
    out, _ = case.run_command(["ip", "-j", "address", "show", "dev", "zc0"])
    records = json.loads(out)
    case.check(len(records) == 1 and records[0]["ifname"] == "zc0", "Unexpected interface list")
    inet = [x for x in records[0]["addr_info"] if x["family"] == "inet"]
    case.check(
        len(inet) == 1 and inet[0]["local"] == "198.18.0.1" and inet[0]["prefixlen"] == 24,
        "Unexpected interface address",
    )


def check_libcap2_bin(case):
    case.run_command(["setcap", "cap_net_bind_service=ep", "fixture-elf"])
    out, _ = case.run_command(["getcap", "fixture-elf"])
    case.check(out == b"fixture-elf cap_net_bind_service=ep\n", "File capabilities were not assigned")
    case.check(
        os.getxattr(case.file("fixture-elf"), "security.capability"), "The file capability xattr is missing"
    )
    case.run_command(["setcap", "-r", "fixture-elf"])
    case.check(
        not run_setup(["getcap", case.file("fixture-elf")]).stdout, "File capabilities were not removed"
    )
    case.observe("assigned_and_removed", True)


def check_kmod(case):
    out, _ = case.run_command(["modinfo", "-F", "vermagic", case.read("module-name").decode()])
    case.check(
        out == case.read("vermagic") and os.uname().release.encode() in out, "Unexpected module vermagic"
    )


def check_sed(case):
    out, _ = case.run_command(["sed", "s/alpha/gamma/; /discard/d"], stdin=b"alpha\ndiscard\nbeta\n")
    case.check(out == b"gamma\nbeta\n", "The substitution or deletion differs")


def check_sudo(case):
    out, _ = case.run_command(["sudo", "-n", "-u", "zcomp-target", "/usr/bin/id", "-u"])
    case.check(out == b"1201\n", "The command did not run with the expected target UID")


def check_init_system_helpers(case):
    case.run_command(["update-rc.d", "zcomp-initfixture", "defaults"])
    links = sorted(
        (str(p.parent.name), p.name, os.readlink(p)) for p in Path("/etc").glob("rc*.d/*zcomp-initfixture")
    )
    case.check(
        len(links) == 7 and all(x[2] == "../init.d/zcomp-initfixture" for x in links),
        "The expected runlevel links were not created",
    )
    case.observe("registered_links", links)
    case.run_command(["update-rc.d", "-f", "zcomp-initfixture", "remove"])
    case.check(not list(Path("/etc").glob("rc*.d/*zcomp-initfixture")), "The runlevel links remain")


def check_grep(case):
    out, _ = case.run_command(["grep", "-n", "^alpha"], stdin=b"alpha\nbeta\nalphabet\n")
    case.check(out == b"1:alpha\n3:alphabet\n", "The matching lines differ")
    out, _ = case.run_command(["grep", "absent"], expected=1, stdin=b"alpha\nbeta\n")
    case.check(not out, "The absent pattern produced a match")


def check_python3_13_minimal(case):
    out, _ = case.run_command(["python3.13", "aggregate.py"])
    case.check(out == b"7\n" and case.read("answer.txt") == out, "The Python aggregate or file differs")


def check_python3(case):
    case.run_command(["pygettext3", "-o", "messages.pot", "messages.py"])
    data = case.read("messages.pot")
    ids = re.findall(rb'^msgid "(.+)"$', data, re.M)
    case.check(
        ids == [b"alpha", b"beta"] and b"messages.py:1" in data and b"messages.py:2" in data,
        "The extracted gettext messages differ",
    )
    match = re.search(rb"POT-Creation-Date: ([^\\]+)\\n", data)
    case.check(match is not None, "POT creation time is missing")
    epoch = datetime.strptime(match[1].decode(), "%Y-%m-%d %H:%M%z").timestamp()
    case.check(
        case.record["epoch_start"] - 60 <= epoch <= time.time() + 60, "POT creation time is outside the run"
    )
    case.observe(
        "pot", re.sub(rb"POT-Creation-Date: [^\\]+\\n", b"POT-Creation-Date: <validated>\\n", data).decode()
    )


def check_gpgconf(case):
    directory = case.directory
    out, _ = case.run_command(["gpgconf", "--list-dirs"], env={"GNUPGHOME": str(directory / "gnupg")})
    paths = dict(line.decode().split(":", 1) for line in out.splitlines())
    case.check(
        paths["homedir"] == str(directory / "gnupg")
        and paths["agent-socket"].startswith(str(directory / "gnupg")),
        "GnuPG directories do not refer to the private home",
    )


def check_gpg(case):
    directory = case.directory
    out, _ = case.run_command(
        [
            "gpg",
            "--homedir",
            directory / "gnupg",
            "--batch",
            "--no-auto-key-retrieve",
            "--status-fd",
            "1",
            "--verify",
            "message.sig",
            "message.txt",
        ]
    )
    fingerprints = [
        x.split(":")[9] for x in case.read("fingerprint").decode().splitlines() if x.startswith("fpr:")
    ]
    case.check(
        any(b"[GNUPG:] VALIDSIG " + x.encode() + b" " in out for x in fingerprints),
        "The OpenPGP signature was not validated",
    )


def check_mount(case):
    directory = case.directory
    case.run_command(["mount", "-t", "tmpfs", "-o", "size=1m,nosuid,nodev", "zcomp-tmpfs", "mountpoint"])
    try:
        lines = [
            x
            for x in Path("/proc/self/mountinfo").read_text().splitlines()
            if x.split()[4] == str(directory / "mountpoint")
        ]
        case.check(
            len(lines) == 1 and " - tmpfs " in lines[0] and "nosuid,nodev" in lines[0],
            "The expected tmpfs mount is missing",
        )
        write_file(directory / "mountpoint/probe", "tmpfs-ok\n")
        case.check(case.read("mountpoint/probe") == b"tmpfs-ok\n", "The tmpfs payload differs")
    finally:
        case.run_command(["umount", "mountpoint"])
    case.check(not os.path.ismount(directory / "mountpoint"), "The tmpfs mount remains")
    case.observe("mounted_written_and_removed", True)


def check_ucf(case):
    directory = case.directory
    env = {"DEBIAN_FRONTEND": "noninteractive", "UCF_FORCE_CONFFOLD": "1"}
    case.run_command(
        ["ucf", "--state-dir", directory / "state", "new.conf", directory / "dest.conf"], env=env
    )
    case.check(case.read("dest.conf") == b"initial configuration\n", "Initial ucf copy differs")
    write_file(directory / "dest.conf", "local configuration\n")
    case.run_command(
        ["ucf", "--state-dir", directory / "state", "update.conf", directory / "dest.conf"], env=env
    )
    case.check(case.read("dest.conf") == b"local configuration\n", "ucf did not preserve local edits")
    case.check(
        str(directory / "dest.conf").encode() in case.read("state/hashfile"),
        "ucf state registration is missing",
    )
    case.observe("preserved_local_config", True)


def check_sysvinit_utils(case):
    with helper(case) as (p, _):
        out, _ = case.run_command(["pidof", "zcomp-sleeper"], comparison="semantic")
        case.check(out.strip() == str(p.pid).encode(), "pidof did not identify exactly the prepared helper")
        case.observe("pidof_exact_helper", True)
    out, _ = case.run_command(["pidof", "zcomp-nonexistent-process"], expected=1)
    case.check(not out, "pidof found an unexpected process")


def check_openssh_server(case):
    directory = case.directory
    with case.daemon(["sshd", "-D", "-e", "-f", "sshd_config"]) as target:
        wait_for(lambda: (directory / "sshd.pid").exists() or target.poll() is not None)
        case.check(target.poll() is None, "sshd exited before becoming ready")
        command = [
            "ssh",
            "-p",
            "2224",
            "-i",
            str(directory / "client"),
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            f"UserKnownHostsFile={directory}/known_hosts",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "testuser@127.0.0.1",
            "/usr/bin/printf 'sshd-ok\\n'",
        ]
        response = run_setup(command, check=False)
        case.record["native_client_returncode"] = response.returncode
        write_file(RESULTS_DIR / "50-client.stdout", response.stdout)
        write_file(RESULTS_DIR / "50-client.stderr", response.stderr)
        case.check(
            response.returncode == 0,
            "The native SSH client could not complete the target server session: "
            + response.stderr.decode(errors="replace"),
        )
        case.check(response.stdout == b"sshd-ok\n", "The server did not execute the authenticated command")
        write_file(RESULTS_DIR / "50-client.stdout", response.stdout)
        write_file(RESULTS_DIR / "50-client.stderr", response.stderr)
        case.observe("authenticated_session", "sshd-ok")


def check_ifupdown(case):
    out, _ = case.run_command(["ifquery", "--interfaces=fixture.interfaces", "zc0"])
    case.check(
        out == b"address: 198.18.0.1\nnetmask: 255.255.255.0\nbroadcast: 198.18.0.255\n",
        "The parsed interface configuration differs",
    )


def check_grub_common(case):
    case.run_command(["grub-editenv", "grubenv", "create"])
    case.run_command(["grub-editenv", "grubenv", "set", "alpha=one", "beta=two"])
    out, _ = case.run_command(["grub-editenv", "grubenv", "list"])
    case.check(set(out.splitlines()) == {b"alpha=one", b"beta=two"}, "The GRUB variables differ")
    case.check(len(case.read("grubenv")) == 1024, "The GRUB environment block has an unexpected size")


def check_grub2_common(case):
    directory = case.directory
    case.run_command(["grub-set-default", f"--boot-directory={directory}/boot", "zcomp-entry"])
    data = run_setup(["grub-editenv", directory / "boot/grub/grubenv", "list"]).stdout
    case.check(data == b"saved_entry=zcomp-entry\n", "The saved GRUB entry differs")
    case.observe("saved_entry", "zcomp-entry")


def check_apparmor(case):
    out, _ = case.run_command(["apparmor_parser", "-p", "profile"])
    case.check(
        b"profile zcomp-fixture {" in out
        and b"/work/zcomp-readable r," in out
        and b"/work/known r," in out
        and not re.search(rb"^\s*#include\s", out, re.M),
        "The AppArmor include was not expanded",
    )


def check_kbd(case):
    out, _ = case.run_command(["psfgettable", "font.psfu"])
    case.check(out.splitlines()[3:5] == [b"0x000\tU+0041", b"0x001\tU+0042"], "The PSF Unicode table differs")


def check_adduser(case):
    directory = case.directory
    case.run_command(
        [
            "adduser",
            "--disabled-password",
            "--comment",
            "Zcomp Fixture",
            "--uid",
            "1202",
            "--gid",
            "1202",
            "--home",
            directory / "home",
            "--conf",
            "adduser.conf",
            "zcomp-created",
        ]
    )
    import pwd

    user = pwd.getpwnam("zcomp-created")
    password = next(
        line.split(":")[1]
        for line in Path("/etc/shadow").read_text().splitlines()
        if line.startswith("zcomp-created:")
    )
    case.check(
        user.pw_uid == user.pw_gid == 1202
        and user.pw_dir == str(directory / "home")
        and user.pw_gecos.startswith("Zcomp Fixture"),
        "The account metadata differs",
    )
    case.check(
        password.startswith("!")
        and case.read("home/welcome.txt") == b"fixed skeleton\n"
        and case.file("home").stat().st_uid == 1202,
        "The password lock or home setup differs",
    )
    case.observe("account", dict(uid=1202, gid=1202, home=user.pw_dir, gecos=user.pw_gecos, locked=True))


def check_gpg_agent(case):
    directory = case.directory
    key = case.read("keygrip").decode()
    out, _ = case.run_command(
        ["gpg-agent", "--homedir", directory / "gnupg", "--server"],
        stdin=f"KEYINFO {key}\nBYE\n".encode(),
        comparison="agent",
    )
    case.check(
        b"S KEYINFO " + key.encode() + b" D " in out and b"ERR " not in out,
        "The key information response differs",
    )
    case.observe("keyinfo", key)


def check_dirmngr(case):
    directory = case.directory
    case.run_command(["dirmngr", "--homedir", directory / "gnupg", "--load-crl", "crl.der"], comparison="crl")
    out, _ = case.run_command(["dirmngr", "--homedir", directory / "gnupg", "--list-crls"], comparison="crl")
    case.check(b"Zcomp Test CA" in out, "The imported CRL issuer is missing")
    index = case.read("gnupg/crls.d/DIR.txt")
    case.check(b"Zcomp Test CA" in index and b"v:1:" in index, "The CRL cache index is missing or invalid")
    case.observe("crl_index", index.decode())


def check_python3_minimal(case):
    directory = case.directory
    case.run_command(["py3compile", "fixture.py"])
    files = list((directory / "__pycache__").glob("fixture*.pyc"))
    case.check(
        len(files) == 1 and files[0].read_bytes()[:4] == importlib.util.MAGIC_NUMBER,
        "The bytecode header differs",
    )
    out = run_setup(["python3", files[0]]).stdout
    case.check(out == b"7\n", "The compiled Python payload differs")
    case.observe("compiled_result", "7")


def check_perl(case):
    out, _ = case.run_command(["json_pp", "-json_opt", "canonical"], stdin=case.read("input.json"))
    case.check(
        json.loads(out) == {"a": 1, "b": 2} and out.index(b'"a"') < out.index(b'"b"'),
        "Canonical JSON differs",
    )


def check_pinentry_curses(case):
    pinentry(case)


def check_findutils(case):
    out, _ = case.run_command(
        ["find", "tree", "-type", "f", "-name", "*.txt", "-print0"], comparison="semantic"
    )
    case.check(
        out.endswith(b"\0") and sorted(out[:-1].split(b"\0")) == [b"tree/a.txt", b"tree/sub/b.txt"],
        "The NUL-delimited path set differs",
    )
    case.observe("found_paths", ["tree/a.txt", "tree/sub/b.txt"])


def check_linux_base(case):
    out, _ = case.run_command(["linux-version", "sort", "6.1.0-10", "6.12.0-1", "6.1.0-9"])
    case.check(out == b"6.1.0-9\n6.1.0-10\n6.12.0-1\n", "Kernel version sorting differs")


def check_initramfs_tools_core(case):
    out, _ = case.run_command(["lsinitramfs", "fixture.img"])
    case.check(
        set(out.splitlines()) == {b"early_cpio", b"early.txt", b"main.txt"},
        "The initramfs member list differs",
    )


def check_wtmpdb(case):
    out, _ = case.run_command(["wtmpdb", "last", "-f", "wtmp.db", "-F", "-w"])
    case.check(
        b"zcomp-fixture" in out and b"pts/9" in out and b"00:10" in out,
        "The imported login/logout record differs",
    )


def check_initramfs_tools_bin(case):
    directory = case.directory
    case.run_command(["unmkinitramfs", "fixture.img", "unpacked"])
    case.check(
        case.read("unpacked/early.txt") == b"early fixture\n"
        and case.read("unpacked/main.txt") == b"main fixture\n"
        and case.read("unpacked/early_cpio") == b"1\n",
        "The extracted early/main payload differs",
    )
    case.observe("unpacked", tree_snapshot(directory / "unpacked"))


def check_initramfs_tools(case):
    directory = case.directory
    case.run_command(
        ["update-initramfs", "-c", "-k", os.uname().release, "-b", directory / "boot"],
        env={"SOURCE_DATE_EPOCH": str(FIXED_EPOCH)},
        timeout=180,
    )
    image = directory / "boot" / ("initrd.img-" + os.uname().release)
    case.check(image.is_file() and image.stat().st_size > 1024, "The generated initrd is missing")
    dest = WORK_DIR / "verify67"
    run_setup(["unmkinitramfs", image, dest], timeout=90)
    manifest = tree_snapshot(dest)
    case.check(any(x.endswith("/init") or x == "init" for x in manifest), "The generated initrd has no init")
    case.observe("initrd_manifest", manifest)
    write_file(RESULTS_DIR / "67-initrd-manifest.json", json.dumps(manifest, indent=2))


def check_sgml_base(case):
    directory = case.directory
    case.run_command(["update-catalog", "--add", directory / "central.cat", directory / "ordinary.cat"])
    registered = case.read("central.cat")
    case.check(
        str(directory / "ordinary.cat").encode() in registered, "The SGML catalog reference is missing"
    )
    case.observe("registered_catalog", registered.decode())
    case.run_command(["update-catalog", "--remove", directory / "central.cat", directory / "ordinary.cat"])
    case.check(
        not case.file("central.cat").exists()
        or str(directory / "ordinary.cat").encode() not in case.read("central.cat"),
        "The SGML reference remains",
    )


def check_xml_core(case):
    directory = case.directory
    command = [
        "update-xmlcatalog",
        "--local",
        directory / "local.xml",
        "--type",
        "public",
        "--id",
        "-//ZCOMP//DTD Test//EN",
        "--file",
        directory / "ordinary.xml",
    ]
    case.run_command([command[0], "--add", *command[1:]])
    root = ET.parse(directory / "local.xml").getroot()
    entries = list(root.iter("{urn:oasis:names:tc:entity:xmlns:xml:catalog}public"))
    case.check(
        len(entries) == 1
        and entries[0].attrib["publicId"] == "-//ZCOMP//DTD Test//EN"
        and entries[0].attrib["uri"] == str(directory / "ordinary.xml"),
        "The XML public identifier differs",
    )
    case.observe("registered_entry", entries[0].attrib)
    case.run_command([command[0], "--del", *command[1:-2]])
    case.check(
        not (directory / "local.xml").exists()
        or not list(
            ET.parse(directory / "local.xml")
            .getroot()
            .iter("{urn:oasis:names:tc:entity:xmlns:xml:catalog}public")
        ),
        "The XML catalog entry remains",
    )


def check_polkitd(case):
    service("polkit.service")
    out, _ = case.run_command(["pkaction", "--action-id", "org.zcomp.probe", "--verbose"])
    case.check(
        b"org.zcomp.probe:" in out and b"Fixed zcomp action" in out, "The policy action was not returned"
    )
    for key, value in ((b"any", b"no"), (b"inactive", b"no"), (b"active", b"yes")):
        case.check(
            re.search(rb"implicit " + key + rb":\s+" + value + rb"\b", out), "The policy default differs"
        )


def check_dmidecode(case):
    directory = case.directory
    out, _ = case.run_command(["dmidecode", "--from-dump", "dmi.bin", "--type", "system"])
    expected = case.read("expected.txt").replace(str(directory / "dmi.bin").encode(), b"dmi.bin")
    case.check(out == expected and b"System Information" in out, "The decoded DMI system record differs")


def check_gpgsm(case):
    directory = case.directory
    out, _ = case.run_command(
        [
            "gpgsm",
            "--homedir",
            directory / "gnupg",
            "--batch",
            "--disable-crl-checks",
            "--disable-policy-checks",
            "--disable-dirmngr",
            "--status-fd",
            "1",
            "--verify",
            "message.p7s",
            "message.txt",
        ]
    )
    case.check(
        b"[GNUPG:] VALIDSIG " + case.read("fingerprint") + b" " in out, "The CMS signature was not validated"
    )


def check_shared_mime_info(case):
    directory = case.directory
    case.run_command(["update-mime-database", directory / "mime"])
    case.check(b"application/x-zcomp:*.zcprobe" in case.read("mime/globs2"), "The MIME glob is missing")
    xml = ET.parse(directory / "mime/application/x-zcomp.xml").getroot()
    case.check(
        xml.attrib["type"] == "application/x-zcomp"
        and case.read("mime/mime.cache")[:4] == b"\x00\x01\x00\x02",
        "The generated MIME database is invalid",
    )
    case.observe("mime_outputs", tree_snapshot(directory / "mime"))


def check_fuse3(case):
    directory = case.directory
    run_setup(["modprobe", "fuse"], check=False)
    if not Path("/dev/fuse").exists():
        raise MissingEnvironment("The guest has no /dev/fuse after loading the fuse module")

    def identity():
        os.setgroups([])
        os.setgid(1100)
        os.setuid(1100)

    with (RESULTS_DIR / "74-helper.stderr").open("wb") as err:
        p = subprocess.Popen(
            [str(directory / "fuse-hello"), "-f", str(directory / "mountpoint")],
            cwd=directory,
            stdout=err,
            stderr=err,
            preexec_fn=identity,
        )
        try:
            mounted = lambda: any(
                line.split()[4] == str(directory / "mountpoint")
                for line in Path("/proc/self/mountinfo").read_text().splitlines()
            )
            wait_for(lambda: mounted() or p.poll() is not None)
            case.check(p.poll() is None and mounted(), "The native FUSE fixture could not mount")
            payload = subprocess.run(
                ["/usr/bin/cat", str(directory / "mountpoint/hello")],
                preexec_fn=identity,
                capture_output=True,
                timeout=5,
            )
            case.check(
                payload.returncode == 0 and payload.stdout == b"Hello World!\n",
                "The native FUSE fixture content differs",
            )
            case.run_command(["fusermount3", "-u", "mountpoint"])
            case.check(not mounted(), "The FUSE mount remains")
            case.observe("fuse_mount_removed", True)
        finally:
            if mounted():
                run_setup(["umount", directory / "mountpoint"], check=False)
            if p.poll() is None:
                p.terminate()
            p.wait(timeout=10)


def check_fontconfig(case):
    out, _ = case.run_command(["fc-query", "--format", "%{family}\n%{style}\n", "font.ttf"])
    case.check(out == b"DejaVu Sans\nBook\n", "The font family or style differs")


def check_logrotate(case):
    directory = case.directory
    case.run_command(["logrotate", "-f", "-s", "state", "logrotate.conf"])
    case.check(
        case.read("current.log.1") == b"alpha\nbeta\n"
        and case.read("current.log") == b""
        and stat.S_IMODE(case.file("current.log").stat().st_mode) == 0o640,
        "The rotated payload or new log mode differs",
    )
    case.check(str(directory / "current.log").encode() in case.read("state"), "The rotation state is missing")
    case.observe(
        "rotated",
        dict(old_hash=hashlib.sha256(case.read("current.log.1")).hexdigest(), new_size=0, new_mode="0640"),
    )


def check_wpasupplicant(case):
    out, _ = case.run_command(["wpa_passphrase", "zcomp-fixture"], stdin=case.read("passphrase.txt"))
    psk = (
        hashlib.pbkdf2_hmac("sha1", case.read("passphrase.txt").strip(), b"zcomp-fixture", 4096, 32)
        .hex()
        .encode()
    )
    case.check(
        b'ssid="zcomp-fixture"' in out and b"\n\tpsk=" + psk + b"\n" in out, "The derived WPA PSK differs"
    )


def check_apt_utils(case):
    out, _ = case.run_command(["apt-ftparchive", "packages", "repo"])
    fields = dict(
        line.split(b": ", 1) for line in out.splitlines() if b": " in line and not line.startswith(b" ")
    )
    case.check(
        fields[b"Package"] == b"zcomp-fixture"
        and fields[b"Version"] == b"1.0"
        and fields[b"SHA256"] == hashlib.sha256(case.read("repo/fixture.deb")).hexdigest().encode(),
        "The repository metadata or checksum differs",
    )
    case.check(
        int(fields[b"Size"]) == case.file("repo/fixture.deb").stat().st_size,
        "The indexed package size differs",
    )


def check_mawk(case):
    out, _ = case.run_command(["mawk", "-f", "aggregate.awk", "numbers.txt"])
    case.check(out == b"sum=7/count=4\n", "The AWK aggregate differs")


def check_gettext_base(case):
    out, _ = case.run_command(
        ["envsubst", "${NAME}"],
        stdin=case.read("input.txt"),
        env={"NAME": "alpha", "UNSET": "must-stay-literal"},
    )
    case.check(out == b"alpha:$UNSET\n", "The substitution whitelist differs")


def check_parted(case):
    out, _ = case.run_command(["parted", "-sm", "gpt.img", "unit", "s", "print"])
    lines = out.splitlines()
    case.check(lines[0] == b"BYT;" and len(lines) == 3, "The machine-readable partition record differs")
    header, part = lines[1].split(b":"), lines[2].split(b":")
    case.check(
        header[1] == b"32768s" and header[3:6] == [b"512", b"512", b"gpt"], "The image geometry differs"
    )
    case.check(
        part[:4] == [b"1", b"2048s", b"6143s", b"4096s"] and part[5] == b"zcomp", "The GPT partition differs"
    )


def check_apt_listchanges(case):
    out, _ = case.run_command(
        [
            "apt-listchanges",
            "--frontend=text",
            "--show-all",
            "--no-network",
            "--save-seen=none",
            "--which=changelogs",
            "--email-address=",
            "fixture.deb",
        ]
    )
    case.check(
        out.count(b"Fixed newer change.") == 1
        and out.count(b"Fixed older change.") == 1
        and out.index(b"(1.0)") < out.index(b"(0.9)"),
        "The changelog entries or order differ",
    )


def check_avahi_daemon(case):
    dummy()
    run_setup(["systemctl", "stop", "avahi-daemon.service", "avahi-daemon.socket"], check=False)
    Path("/run/avahi-daemon/pid").unlink(missing_ok=True)
    with case.daemon(["avahi-daemon", "--no-chroot", "-f", "avahi.conf"]) as target:

        def running():
            if target.poll() is not None:
                return True
            # 起動確認が別daemonを自動起動すると、対象のconstructorが遅い条件だけ
            # pid競合になる。観測側はサービスを生成せず、対象自身の登録を待つ。
            p = run_setup(
                [
                    "busctl",
                    "--system",
                    "--auto-start=no",
                    "--timeout=1",
                    "call",
                    "org.freedesktop.Avahi",
                    "/",
                    "org.freedesktop.Avahi.Server",
                    "GetState",
                ],
                check=False,
            )
            return p.returncode == 0 and p.stdout.strip() == b"i 2"

        wait_for(running)
        case.check(target.poll() is None, "Avahi exited before entering RUNNING")
        response = bus("org.freedesktop.Avahi", "/", "org.freedesktop.Avahi.Server", "GetHostName").stdout
        case.check(response.strip() == b's "zcomp-probe"', "The Avahi hostname differs")
        case.observe("avahi", dict(state=2, hostname="zcomp-probe"))


def check_gtk_update_icon_cache(case):
    case.run_command(["gtk-update-icon-cache", "-f", "theme"])
    case.run_command(["gtk-update-icon-cache", "--validate", "theme"])
    cache = case.read("theme/icon-theme.cache")
    case.check(len(cache) > 16 and b"zcomp-probe\0" in cache, "The icon cache or icon name is missing")
    case.observe("cache_sha256", hashlib.sha256(cache).hexdigest())


def check_ssl_cert(case):
    directory = case.directory
    case.run_command(
        ["make-ssl-cert", "template.cnf", "certificate.pem"], env={"DEBIAN_FRONTEND": "noninteractive"}
    )
    cert = directory / "certificate.pem"
    subject = run_setup(["openssl", "x509", "-in", cert, "-noout", "-subject"]).stdout
    case.check(re.search(rb"CN\s*=\s*zcomp-probe.invalid\b", subject), "The certificate subject differs")
    run_setup(["openssl", "verify", "-CAfile", cert, cert])
    public = run_setup(["openssl", "x509", "-in", cert, "-pubkey", "-noout"]).stdout
    key = run_setup(["openssl", "pkey", "-in", cert, "-pubout"]).stdout
    case.check(
        public == key and stat.S_IMODE(cert.stat().st_mode) == 0o600,
        "The certificate/key correspondence or mode differs",
    )
    details = run_setup(["openssl", "x509", "-in", cert, "-text", "-noout"]).stdout
    case.check(b"Public-Key: (2048 bit)" in details, "The generated key size differs")
    dates = run_setup(["openssl", "x509", "-in", cert, "-noout", "-dates"]).stdout.decode().splitlines()
    begin, end = [
        datetime.strptime(line.split("=", 1)[1], "%b %d %H:%M:%S %Y GMT")
        .replace(tzinfo=timezone.utc)
        .timestamp()
        for line in dates
    ]
    case.check(
        case.record["epoch_start"] - 5 <= begin <= time.time() + 5
        and 3649 * 86400 <= end - begin <= 3651 * 86400,
        "The certificate validity is outside the declared interval",
    )
    case.observe(
        "certificate",
        dict(cn="zcomp-probe.invalid", bits=2048, key_matches=True, self_signed=True, mode="0600"),
    )


def check_udisks2(case):
    directory = case.directory
    service("udisks2.service")
    out, _ = case.run_command(
        ["udisksctl", "loop-setup", "--read-only", "--file", "image.img", "--no-user-interaction"],
        comparison="semantic",
    )
    match = re.search(rb"/dev/loop\d+", out)
    case.check(match is not None, "No loop device was returned")
    device = match[0].decode()
    try:
        info, _ = case.run_command(["udisksctl", "info", "--block-device", device], comparison="semantic")
        sysdir = Path("/sys/class/block") / Path(device).name
        case.check(
            (sysdir / "ro").read_text().strip() == "1"
            and int((sysdir / "size").read_text()) * 512 == case.file("image.img").stat().st_size,
            "The loop size or read-only property differs",
        )
        case.check(
            (sysdir / "loop/backing_file").read_text().strip() == str(directory / "image.img")
            and b"ReadOnly:" in info
            and b"true" in info,
            "The backing file or info response differs",
        )
        case.observe(
            "loop",
            dict(
                backing_file=str(directory / "image.img"),
                size=case.file("image.img").stat().st_size,
                readonly=True,
            ),
        )
    finally:
        case.run_command(
            ["udisksctl", "loop-delete", "--block-device", device, "--no-user-interaction"],
            comparison="semantic",
        )
    case.check(not (sysdir / "loop/backing_file").exists(), "The loop device still has a backing file")


def check_lsof(case):
    directory = case.directory
    with helper(case) as (p, fd):
        out, _ = case.run_command(["lsof", "-a", "-p", p.pid, "-d", fd, "-F", "pfn"], comparison="semantic")
        case.check(
            out.splitlines() == [f"p{p.pid}".encode(), f"f{fd}".encode(), f"n{directory}/held.txt".encode()],
            "The held file descriptor differs",
        )
        case.observe("open_file", dict(fd=fd, path=str(directory / "held.txt"), matched_helper=True))


def check_modemmanager(case):
    service("ModemManager.service")
    out, _ = case.run_command(["mmcli", "--list-modems"])
    case.check(out.strip() == b"No modems were found", "The fixed empty modem list differs")


def check_network_manager(case):
    service("NetworkManager.service")
    run_setup(["nmcli", "connection", "reload"])
    out, _ = case.run_command(
        [
            "nmcli",
            "-t",
            "-f",
            "connection.id,connection.uuid,connection.type",
            "connection",
            "show",
            "zcomp-fixture",
        ]
    )
    case.check(
        set(out.splitlines())
        == {
            b"connection.id:zcomp-fixture",
            b"connection.uuid:01234567-89ab-cdef-0123-456789abcdef",
            b"connection.type:802-3-ethernet",
        },
        "The NetworkManager profile differs",
    )


def check_anacron(case):
    case.run_command(["anacron", "-d", "-n", "-s", "-t", "anacrontab", "-S", "spool"])
    case.check(case.read("marker") == b"anacron-ok", "The scheduled job did not produce the marker")
    day = case.read("spool/zcomp-job").strip()
    case.check(
        day == datetime.now(timezone.utc).strftime("%Y%m%d").encode(), "The anacron spool date is invalid"
    )
    case.observe("job", dict(marker="anacron-ok", date_validated=True))


def check_x11_xkb_utils(case):
    case.run_command(["xkbcomp", "-w", "0", "-xkm", "fixture.xkb", "fixture.xkm"])
    case.run_command(["xkbcomp", "-w", "0", "-xkb", "fixture.xkm", "roundtrip.xkb"])
    text = case.read("roundtrip.xkb")
    case.check(
        re.search(rb"<AD01>\s*=\s*24;", text) and re.search(rb"key\s+<AD01>\s*\{[^}]*\bq\b[^}]*\bQ\b", text),
        "The XKB keycode or keysyms differ",
    )
    case.observe("roundtrip_sha256", hashlib.sha256(text).hexdigest())


def check_git(case):
    directory = case.directory
    env = dict(
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL="/dev/null",
        GIT_AUTHOR_NAME="Zcomp",
        GIT_AUTHOR_EMAIL="test@example.invalid",
        GIT_COMMITTER_NAME="Zcomp",
        GIT_COMMITTER_EMAIL="test@example.invalid",
        GIT_AUTHOR_DATE="2026-10-01T00:00:00+0000",
        GIT_COMMITTER_DATE="2026-10-01T00:00:00+0000",
    )
    case.run_command(
        ["git", "init", "--initial-branch=main", "--object-format=sha1", "--template=", "repo"], env=env
    )
    shutil.copy2(directory / "file.txt", directory / "repo/file.txt")
    case.run_command(["git", "-C", "repo", "add", "file.txt"], env=env)
    case.run_command(["git", "-C", "repo", "commit", "-m", "Fixed commit"], env=env)
    out, _ = case.run_command(["git", "-C", "repo", "cat-file", "-p", "HEAD:file.txt"], env=env)
    case.check(out == b"fixed git payload\n", "The committed blob differs")
    ids, _ = case.run_command(
        ["git", "-C", "repo", "rev-parse", "HEAD", "HEAD^{tree}", "HEAD:file.txt"], env=env
    )
    values = ids.decode().splitlines()
    expected_blob = hashlib.sha1(b"blob " + str(len(out)).encode() + b"\0" + out).hexdigest()
    case.check(
        len(values) == 3
        and values[-1] == expected_blob
        and all(re.fullmatch("[0-9a-f]{40}", x) for x in values),
        "The Git object IDs differ",
    )
    case.observe("git_ids", values)
    index, _ = case.run_command(["git", "-C", "repo", "ls-files", "--stage"], env=env)
    case.check(index == f"100644 {expected_blob} 0\tfile.txt\n".encode(), "The index entries differ")
    case.observe("git_index_entries", index.decode())


def check_acl(case):
    directory = case.directory
    case.run_command(["setfacl", "-m", "u:1201:r--", "file.txt"])
    out, _ = case.run_command(["getfacl", "-cn", "file.txt"])
    case.check(
        set(out.splitlines())
        == {b"user::rw-", b"user:1201:r--", b"group::r--", b"mask::r--", b"other::---", b""},
        "The extended ACL differs",
    )
    case.run_command(["setfacl", "-b", "file.txt"])
    data = run_setup(["getfacl", "-cn", directory / "file.txt"]).stdout
    case.check(
        b"user:1201:" not in data and stat.S_IMODE(case.file("file.txt").stat().st_mode) == 0o640,
        "The ACL was not removed or the base mode differs",
    )
    case.observe("acl_assigned_and_removed", True)


def check_bc(case):
    out, _ = case.run_command(["bc"], stdin=b"2^64+1\n")
    case.check(out == b"18446744073709551617\n", "The arbitrary precision result differs")


def check_lsb_release(case):
    out, _ = case.run_command(["lsb_release", "-is"])
    case.check(out == b"Debian\n", "The distributor ID differs")
    out, _ = case.run_command(["lsb_release", "-cs"])
    case.check(out == b"trixie\n", "The release codename differs")


def check_rtkit(case):
    run_setup(["systemctl", "stop", "rtkit-daemon.service"], check=False)
    case.run_command(["rtkitctl", "--start"])
    case.check(
        bus(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "NameHasOwner",
            "s",
            "org.freedesktop.RealtimeKit1",
        ).stdout.strip()
        == b"b true",
        "The RealtimeKit bus owner did not appear",
    )
    case.run_command(["rtkitctl", "--exit"])
    wait_for(
        lambda: bus(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "NameHasOwner",
            "s",
            "org.freedesktop.RealtimeKit1",
        ).stdout.strip()
        == b"b false"
    )
    case.observe("rtkit_started_and_exited", True)


def check_upower(case):
    service("upower.service")
    out, _ = case.run_command(["upower", "--dump"], comparison="power")
    case.check(
        re.search(rb"on-battery:\s+no\b", out) and re.search(rb"lid-is-present:\s+no\b", out),
        "The fixed VM power state differs",
    )
    case.check(
        re.findall(rb"^Device: (.+)$", out, re.M) == [b"/org/freedesktop/UPower/devices/DisplayDevice"]
        and b"percentage:          0%" in out,
        "An unexpected battery or adapter is present",
    )
    case.observe(
        "power_state",
        dict(on_battery=False, lid_present=False, devices=re.findall(rb"^Device: (.+)$", out, re.M)),
    )


def check_colord(case):
    case.run_command(
        ["cd-create-profile", "--output", "profile.icc", "palette.xml"],
        env={"SOURCE_DATE_EPOCH": str(FIXED_EPOCH)},
    )
    icc(case)


def check_bubblewrap(case):
    probe = run_setup(["unshare", "--user", "--map-root-user", "/usr/bin/true"], check=False)
    if probe.returncode:
        raise MissingEnvironment(
            "The guest does not allow an unprivileged user namespace: " + probe.stderr.decode()
        )
    parent = os.readlink("/proc/self/ns/pid")
    script = 'test "$(readlink /proc/self/ns/pid)" != "$ZCOMP_PARENT_PIDNS" || exit 8; (printf no > /work/case99/forbidden) 2>/dev/null && exit 9; printf "bwrap-ok\\n" > /tmp/probe; /usr/bin/cat /tmp/probe'
    out, _ = case.run_command(
        [
            "bwrap",
            "--unshare-user",
            "--unshare-pid",
            "--ro-bind",
            "/",
            "/",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--",
            "/bin/sh",
            "-c",
            script,
        ],
        env={"ZCOMP_PARENT_PIDNS": parent},
    )
    case.check(
        out == b"bwrap-ok\n" and not case.file("forbidden").exists() and not Path("/tmp/probe").exists(),
        "The namespace payload or read-only/private mounts differ",
    )
    case.observe("namespaces_and_mounts", True)


def check_cups_daemon(case):
    run_setup(["systemctl", "stop", "cups.service", "cups.socket", "cups.path"], check=False)
    sockpath = Path("/run/cups/cups.sock")
    case.check(
        Path("/etc/cups/zcomp-probe.conf").read_bytes() == case.read("cupsd.conf"),
        "The installed dedicated CUPS configuration differs",
    )
    with case.daemon(["cupsd", "-f", "-c", "/etc/cups/zcomp-probe.conf"]) as target:
        wait_for(lambda: sockpath.exists() or target.poll() is not None)
        case.check(
            target.poll() is None and sockpath.exists(), "cupsd exited before creating the UNIX socket"
        )
        import http.client

        request = struct.pack(">BBHI", 2, 0, 0x4002, 7) + b"\x01"
        for tag, name, value in (
            (0x47, b"attributes-charset", b"utf-8"),
            (0x48, b"attributes-natural-language", b"en"),
        ):
            request += (
                bytes([tag]) + struct.pack(">H", len(name)) + name + struct.pack(">H", len(value)) + value
            )
        request += b"\x03"
        connection = http.client.HTTPConnection("localhost", timeout=10)
        connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.sock.connect(str(sockpath))
        connection.request("POST", "/", body=request, headers={"Content-Type": "application/ipp"})
        response = connection.getresponse()
        body = response.read()
        case.check(response.status == 200 and len(body) >= 9, "The CUPS HTTP response is invalid")
        major, minor, status, request_id = struct.unpack(">BBHI", body[:8])
        case.check(
            (major, minor, status, request_id) == (2, 0, 0x0406, 7) and body.endswith(b"\x03"),
            "The CUPS empty printer IPP response differs",
        )
        write_file(RESULTS_DIR / "100-ipp.response", body)
        write_file(RESULTS_DIR / "100-http.headers.json", json.dumps(dict(response.getheaders()), indent=2))
        case.observe("ipp_empty_printers", body.hex())
        connection.close()


# 単純なCLIは上のコマンド表、それ以外は以下の名前付きテストで実行する。
SERVICE_WORKLOADS = {
    "openssl": check_openssl,
    "groff-base": check_groff_base,
    "man-db": check_man_db,
    "procps": check_procps,
    "bsdextrautils": check_bsdextrautils,
    "iproute2": check_iproute2,
    "libcap2-bin": check_libcap2_bin,
    "kmod": check_kmod,
    "sed": check_sed,
    "sudo": check_sudo,
    "init-system-helpers": check_init_system_helpers,
    "grep": check_grep,
    "python3.13-minimal": check_python3_13_minimal,
    "python3": check_python3,
    "gpgconf": check_gpgconf,
    "gpg": check_gpg,
    "mount": check_mount,
    "ucf": check_ucf,
    "sysvinit-utils": check_sysvinit_utils,
    "openssh-server": check_openssh_server,
    "ifupdown": check_ifupdown,
    "grub-common": check_grub_common,
    "grub2-common": check_grub2_common,
    "apparmor": check_apparmor,
    "kbd": check_kbd,
    "adduser": check_adduser,
    "gpg-agent": check_gpg_agent,
    "dirmngr": check_dirmngr,
    "python3-minimal": check_python3_minimal,
    "perl": check_perl,
    "pinentry-curses": check_pinentry_curses,
    "findutils": check_findutils,
    "linux-base": check_linux_base,
    "initramfs-tools-core": check_initramfs_tools_core,
    "wtmpdb": check_wtmpdb,
    "initramfs-tools-bin": check_initramfs_tools_bin,
    "initramfs-tools": check_initramfs_tools,
    "sgml-base": check_sgml_base,
    "xml-core": check_xml_core,
    "polkitd": check_polkitd,
    "dmidecode": check_dmidecode,
    "gpgsm": check_gpgsm,
    "shared-mime-info": check_shared_mime_info,
    "fuse3": check_fuse3,
    "fontconfig": check_fontconfig,
    "logrotate": check_logrotate,
    "wpasupplicant": check_wpasupplicant,
    "apt-utils": check_apt_utils,
    "mawk": check_mawk,
    "gettext-base": check_gettext_base,
    "parted": check_parted,
    "apt-listchanges": check_apt_listchanges,
    "avahi-daemon": check_avahi_daemon,
    "gtk-update-icon-cache": check_gtk_update_icon_cache,
    "ssl-cert": check_ssl_cert,
    "udisks2": check_udisks2,
    "lsof": check_lsof,
    "modemmanager": check_modemmanager,
    "network-manager": check_network_manager,
    "anacron": check_anacron,
    "x11-xkb-utils": check_x11_xkb_utils,
    "git": check_git,
    "acl": check_acl,
    "bc": check_bc,
    "lsb-release": check_lsb_release,
    "rtkit": check_rtkit,
    "upower": check_upower,
    "colord": check_colord,
    "bubblewrap": check_bubblewrap,
    "cups-daemon": check_cups_daemon,
}


def run_service_case(case):
    SERVICE_WORKLOADS[case.package](case)
