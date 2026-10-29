"""固定入力だけを準備する。対象CLIの実行・成功判定はworkloads.pyに置く。"""

import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import traceback
from textwrap import dedent
import common
from services import require
from common import (
    WORK_DIR,
    RESULTS_DIR,
    FIXED_EPOCH,
    write_file,
    run_setup,
    case_directory,
    package_names,
    apt_options,
    file_snapshot,
)


def prepare_cli():
    problems = {}
    for number in range(1, 31):
        directory = case_directory(number)
        directory.mkdir(exist_ok=True)
        write_file(directory / "numbers.txt", "3\n1\n2\n1\n")
        write_file(directory / "text.txt", "alpha\nbeta\n")
        write_file(directory / "utf8.txt", "ASCII 日本語 😀\n")
        write_file(directory / "before.txt", "alpha\nbeta\n")
        write_file(directory / "after.txt", "alpha\ngamma\n")
        write_file(directory / "machine-id", "0123456789abcdef0123456789abcdef\n")
    shell = dedent(
        """\
        s=0
        while IFS= read -r n; do s=$((s+n)); done < numbers.txt
        printf "sum=%s\\n" "$s"
        /usr/bin/cat text.txt | /usr/bin/tr a-z A-Z
        """
    )
    for number in (1, 20):
        write_file(case_directory(number) / "shell-case.sh", shell)
    write_file(
        case_directory(5) / "session-client.sh",
        dedent(
            """\
        #!/bin/sh
        exec /usr/bin/dbus-send --session --dest=org.freedesktop.DBus --type=method_call --print-reply=literal /org/freedesktop/DBus org.freedesktop.DBus.ListNames
        """
        ),
        mode=0o755,
    )
    for name in ("10-first", "20-second"):
        write_file(
            case_directory(9) / "parts" / name,
            dedent(
                f"""\
                  #!/bin/sh
                  printf "{name}\\n"
                  printf "{name}\\n" >> record.txt
                  """
            ),
            mode=0o755,
        )
    write_file(case_directory(12) / "aggregate.pl", 'while (<>) { $s += $_; } print "$s\\n";\n')
    write_file(case_directory(7) / "crontab.txt", "17 3 * * * /usr/bin/true\n")
    directory = case_directory(4)
    write_file(
        directory / "config.dat",
        "Name: zcomp/probe\nTemplate: zcomp/probe\nValue: alpha\nOwners: zcomp\nFlags: seen\n\n",
    )
    write_file(
        directory / "templates.dat",
        "Name: zcomp/probe\nType: string\nDescription: Fixed test value\nOwners: zcomp\n\n",
    )
    write_file(
        directory / "debconf.conf",
        dedent(
            f"""\
        Config: zcomp
        Templates: templates
        
        Name: zcomp
        Driver: File
        Filename: {directory}/config.dat
        
        Name: templates
        Driver: File
        Filename: {directory}/templates.dat
        
        """
        ),
    )
    directory = case_directory(13)
    write_file(directory / "passwd", "root:x:0:0:old:/root:/bin/sh\n")
    write_file(directory / "group", "root:x:0:\n")
    write_file(directory / "shadow", "root:!:20000:0:99999:7:::\n")
    write_file(
        directory / "passwd.master",
        "root:*:0:0:root:/root:/bin/bash\ndaemon:*:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
    )
    write_file(directory / "group.master", "root:*:0:\ndaemon:*:1:\n")
    (case_directory(19) / "input").mkdir(exist_ok=True)
    shutil.copy2(case_directory(19) / "text.txt", case_directory(19) / "input/text.txt")
    (case_directory(19) / "extracted").mkdir(exist_ok=True)
    directory = case_directory(21)
    write_file(
        directory / "debroot/DEBIAN/control",
        dedent(
            """\
        Package: zcomp-fixture
        Version: 1.0
        Architecture: all
        Maintainer: Test <test@example.invalid>
        Description: Fixed offline fixture
        """
        ),
    )
    write_file(directory / "debroot/usr/share/zcomp-fixture/text.txt", "fixed package data\n")
    run_setup(["dpkg-deb", "--build", "debroot", "fixture.deb"], directory)
    shutil.copy2(directory / "fixture.deb", case_directory(26) / "fixture.deb")
    directory = case_directory(26)
    deb = (directory / "fixture.deb").read_bytes()
    write_file(
        directory / "Packages",
        dedent(
            f"""\
        Package: zcomp-fixture
        Version: 1.0
        Architecture: all
        Maintainer: Test <test@example.invalid>
        Description: Fixed offline fixture
        Filename: ./fixture.deb
        Size: {len(deb)}
        SHA256: {common.digest(deb)}
        
        """
        ),
    )
    write_file(directory / "sources.list", f"deb [trusted=yes] file:{directory} ./\n")
    for path in ("lists/partial", "cache/archives/partial"):
        (directory / path).mkdir(parents=True, exist_ok=True)
    run_setup(["apt-get", *apt_options(), "update"])
    directory = case_directory(27)
    (directory / "gnupg").mkdir(mode=0o700, exist_ok=True)
    gpg = [
        "gpg",
        "--homedir",
        str(directory / "gnupg"),
        "--batch",
        "--pinentry-mode",
        "loopback",
        "--passphrase",
        "",
        "--faked-system-time",
        "1790812800",
    ]
    run_setup([*gpg, "--quick-generate-key", "Zcomp Test <test@example.invalid>", "ed25519", "sign", "0"])
    write_file(directory / "keyring.pgp", run_setup([*gpg, "--export"]).stdout)
    write_file(directory / "message.txt", "fixed signed payload\n")
    run_setup([*gpg, "--detach-sign", str(directory / "message.txt")])
    (directory / "message.txt.sig").rename(directory / "message.sig")
    write_file(directory / "fingerprint", run_setup([*gpg, "--with-colons", "--list-keys"]).stdout.decode())
    directory = case_directory(29)
    with (directory / "ext4.img").open("wb") as image:
        image.truncate(16 * 1024 * 1024)
    run_setup(
        [
            "mke2fs",
            "-q",
            "-t",
            "ext4",
            "-b",
            "4096",
            "-N",
            "1024",
            "-U",
            "01234567-89ab-cdef-0123-456789abcdef",
            str(directory / "ext4.img"),
        ]
    )
    directory = case_directory(18)
    run_setup(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(directory / "client")])
    run_setup(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(directory / "host")])
    shutil.copy2(directory / "client.pub", directory / "authorized_keys")
    pub = (directory / "host.pub").read_text().split()
    write_file(directory / "known_hosts", "[127.0.0.1]:2222 " + " ".join(pub[:2]) + "\n")
    write_file(
        directory / "sshd_config",
        dedent(
            f"""\
        Port 2222
        ListenAddress 127.0.0.1
        HostKey {directory}/host
        PidFile {directory}/sshd.pid
        AuthorizedKeysFile {directory}/authorized_keys
        StrictModes no
        PasswordAuthentication no
        KbdInteractiveAuthentication no
        UsePAM no
        AllowUsers testuser
        """
        ),
    )
    write_file(
        directory / "ssh_config",
        dedent(
            f"""\
        Host probe
         HostName 127.0.0.1
         Port 2222
         User testuser
         IdentityFile {directory}/client
         UserKnownHostsFile {directory}/known_hosts
         GlobalKnownHostsFile /dev/null
         StrictHostKeyChecking yes
         BatchMode yes
         IdentitiesOnly yes
         LogLevel ERROR
         RemoteCommand /usr/bin/printf 'ssh-ok\\n'
        """
        ),
    )
    # パスワード認証を無効にした専用sshdだけを使い、個人の鍵や認証設定を継承しない。
    run_setup(["usermod", "-p", "x", "testuser"])
    directory = case_directory(24)
    (directory / "tally").mkdir(exist_ok=True)
    write_file(
        Path("/etc/pam.d/zcomp-failure"),
        dedent(
            f"""\
        auth required pam_deny.so
        auth required pam_faillock.so authfail dir={directory}/tally deny=3 unlock_time=0
        account required pam_permit.so
        """
        ),
    )
    attempt = run_setup(["pamtester", "zcomp-failure", "zcomp-fixture", "authenticate"], check=False)
    (directory / "preparation.stderr").write_bytes(attempt.stderr)
    if not (directory / "tally/zcomp-fixture").exists():
        problems["24"] = "Native PAM did not create the failure tally"
    write_file(
        Path("/etc/systemd/system/zcomp-probe.service"),
        dedent(
            """\
        [Unit]
        Description=Fixed query fixture
        [Service]
        Type=oneshot
        ExecStart=/usr/bin/true
        RemainAfterExit=yes
        [Install]
        WantedBy=multi-user.target
        """
        ),
    )
    run_setup(["systemctl", "daemon-reload"])
    run_setup(["systemctl", "enable", "zcomp-probe.service"])
    write_file(
        Path("/etc/popularity-contest.conf"),
        'PARTICIPATE="no"\nMY_HOSTID="0123456789abcdef0123456789abcdef"\n',
    )
    # 内容と時刻を一度だけ固定し、両実行の前に同じディスクを複製する。
    for number in range(1, 31):
        for path in [case_directory(number), *case_directory(number).rglob("*")]:
            os.chown(path, 1100, 1100)
            os.utime(path, (1790812800, 1790812800))
    (case_directory(18) / "client").chmod(0o600)
    (case_directory(18) / "host").chmod(0o600)
    write_file(WORK_DIR / "preparation.json", json.dumps(problems, indent=2))
    # 準備結果もVM外へ回収し、起動器から同じ判定を確認できるようにする。
    shutil.copy2(WORK_DIR / "preparation.json", RESULTS_DIR / "preparation.json")
    write_file(
        WORK_DIR / "installed.tsv",
        run_setup(["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${Architecture}\n"]).stdout,
    )
    print("FIXTURES_READY", flush=True)


def prepare_services():
    packages = package_names()
    problems = {}
    for number in range(31, 101):
        directory = WORK_DIR / f"case{number:02d}"
        directory.mkdir(exist_ok=True)
        write_file(directory / "text.txt", "alpha\nbeta\n")
        write_file(directory / "numbers.txt", "3\n1\n2\n1\n")
    for number in range(31, 101):
        print(f"PREPARE_BEGIN number={number}", flush=True)
        try:
            prepare_case(number, packages[number - 1])
        except Exception as error:
            # fixtureの作成失敗を、アプリケーションの非互換やkernel不足と決めつけない。
            problems[str(number)] = dict(
                status="PREPARATION_FAILED", reason=str(error), traceback=traceback.format_exc()
            )
            print(f"PREPARE_FAILED number={number} reason={error}", flush=True)
    for number in range(31, 101):
        directory = WORK_DIR / f"case{number:02d}"
        for path in [directory, *directory.rglob("*")]:
            if not path.is_symlink():
                os.chown(path, 1100, 1100)
                os.utime(path, (FIXED_EPOCH, FIXED_EPOCH))
    os.chown(WORK_DIR / "case76/logrotate.conf", 0, 0)
    for path in [WORK_DIR / "case100", *(WORK_DIR / "case100").rglob("*")]:
        os.chown(path, 0, 0)
    write_file(WORK_DIR / "preparation-100.json", json.dumps(problems, indent=2))
    shutil.copy2(WORK_DIR / "preparation-100.json", RESULTS_DIR / "preparation-100.json")
    write_file(
        WORK_DIR / "fixture-manifest-100.json",
        json.dumps(
            {str(number): file_snapshot(WORK_DIR / f"case{number:02d}") for number in range(31, 101)},
            indent=2,
        ),
    )
    shutil.copy2(WORK_DIR / "fixture-manifest-100.json", RESULTS_DIR / "fixture-manifest-100.json")
    archives = sorted(Path("/var/cache/apt/archives").glob("*.deb"))
    write_file(
        WORK_DIR / "dependency-debs-100.sha256",
        "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path}\n" for path in archives),
    )
    shutil.copy2(WORK_DIR / "dependency-debs-100.sha256", RESULTS_DIR / "dependency-debs-100.sha256")
    print("FIXTURES_READY", flush=True)


def prepare_case(number, package):
    directory = WORK_DIR / f"case{number:02d}"
    if package == "groff-base":
        write_file(directory / "input.roff", ".nf\nalpha\nbeta\n")
    elif package == "man-db":
        write_file(
            directory / "fixture.1",
            dedent(
                """\
            .TH ZCOMP 1 "2026-10-01" "Zcomp" "Test Manual"
            .SH NAME
            zcomp \\- fixed CLI fixture
            .SH DESCRIPTION
            alpha beta
            """
            ),
        )
    elif package == "bsdextrautils":
        write_file(directory / "bytes.bin", bytes([0, 1, 254, 255]))
    elif package in ("procps", "sysvinit-utils", "lsof"):
        # 名前やfdを通知してから待ち、sleepによる推測でprocfsを照会しない。
        write_file(
            directory / "helper.c",
            dedent(
                """\
            #include <stdio.h>
            #include <unistd.h>
            #include <sys/prctl.h>
            #include <fcntl.h>
            int main(void) { prctl(PR_SET_NAME,"zcomp-sleeper",0,0,0); int fd=open("held.txt",O_RDONLY); printf("%d %d\\n",getpid(),fd); fflush(stdout); char c; return read(0,&c,1)<0; }
            """
            ),
        )
        write_file(directory / "held.txt", "held fixture\n")
        run_setup(["gcc", "-O2", "-o", directory / "zcomp-sleeper", directory / "helper.c"])
    elif package == "kmod":
        modules = list(Path("/lib/modules").rglob("dm-zero.ko*"))
        require(modules, "No dm-zero module file is available")
        shutil.copy2(modules[0], directory / modules[0].name)
        write_file(directory / "module-name", modules[0].name)
        write_file(directory / "vermagic", run_setup(["modinfo", "-F", "vermagic", modules[0]]).stdout)
    elif package == "libcap2-bin":
        shutil.copy2("/usr/bin/true", directory / "fixture-elf")
    elif package == "sudo":
        run_setup(["groupadd", "--gid", "1201", "zcomp-target"])
        run_setup(["useradd", "--uid", "1201", "--gid", "1201", "--no-create-home", "zcomp-target"])
        write_file(
            Path("/etc/sudoers.d/zcomp-probe"),
            "testuser ALL=(zcomp-target) NOPASSWD: /usr/bin/id -u\n",
            0o440,
        )
        run_setup(["visudo", "-c", "-f", "/etc/sudoers.d/zcomp-probe"])
    elif package == "init-system-helpers":
        write_file(
            Path("/etc/init.d/zcomp-initfixture"),
            dedent(
                """\
            #!/bin/sh
            ### BEGIN INIT INFO
            # Provides: zcomp-initfixture
            # Required-Start: $remote_fs
            # Required-Stop: $remote_fs
            # Default-Start: 2 3 4 5
            # Default-Stop: 0 1 6
            # Short-Description: Fixed inactive fixture
            ### END INIT INFO
            exit 0
            """
            ),
            0o755,
        )
    elif package == "python3.13-minimal":
        write_file(
            directory / "aggregate.py",
            dedent(
                """\
            from pathlib import Path
            s=sum(map(int,Path("numbers.txt").read_text().split()))
            Path("answer.txt").write_text(str(s)+"\\n")
            print(s)
            """
            ),
        )
    elif package == "python3":
        write_file(directory / "messages.py", '_("alpha")\n_("beta")\n')
    elif package in ("gpgconf", "gpg", "gpg-agent", "dirmngr", "gpgsm"):
        (directory / "gnupg").mkdir(mode=0o700, exist_ok=True)
        if package == "gpg":
            for filename in ("message.txt", "message.sig", "keyring.pgp", "fingerprint"):
                shutil.copy2(WORK_DIR / "case27" / filename, directory / filename)
            run_setup(
                ["gpg", "--homedir", directory / "gnupg", "--batch", "--import", directory / "keyring.pgp"]
            )
        if package == "gpg-agent":
            shutil.copytree(
                WORK_DIR / "case27/gnupg/private-keys-v1.d", directory / "gnupg/private-keys-v1.d"
            )
            key = next((directory / "gnupg/private-keys-v1.d").glob("*.key")).stem
            write_file(directory / "keygrip", key)
        if package == "dirmngr":
            prepare_ca(directory)
            # dirmngrのCRL用CAはhomedirではなく、この専用VMの標準CA directoryへ置く。
            shutil.copy2(directory / "ca.der", Path("/etc/gnupg/trusted-certs/zcomp.crt"))
        if package == "gpgsm":
            shutil.copy2(WORK_DIR / "case58/ca.pem", directory / "ca.pem")
            shutil.copy2(WORK_DIR / "case58/ca.key", directory / "ca.key")
            write_file(directory / "message.txt", "fixed CMS payload\n")
            run_setup(
                [
                    "openssl",
                    "cms",
                    "-sign",
                    "-binary",
                    "-in",
                    directory / "message.txt",
                    "-signer",
                    directory / "ca.pem",
                    "-inkey",
                    directory / "ca.key",
                    "-outform",
                    "DER",
                    "-out",
                    directory / "message.p7s",
                ]
            )
            run_setup(
                ["gpgsm", "--homedir", directory / "gnupg", "--batch", "--import", directory / "ca.pem"]
            )
            fingerprint = (
                run_setup(["openssl", "x509", "-in", directory / "ca.pem", "-noout", "-fingerprint", "-sha1"])
                .stdout.decode()
                .strip()
                .split("=")[1]
                .replace(":", "")
            )
            write_file(directory / "fingerprint", fingerprint)
            write_file(directory / "gnupg/trustlist.txt", fingerprint + " S\n")
    elif package == "mount":
        (directory / "mountpoint").mkdir()
    elif package == "ucf":
        (directory / "state").mkdir()
        write_file(directory / "new.conf", "initial configuration\n")
        write_file(directory / "update.conf", "maintainer update\n")
    elif package == "openssh-server":
        for filename in ("client", "client.pub", "host", "host.pub", "authorized_keys"):
            shutil.copy2(WORK_DIR / "case18" / filename, directory / filename)
        write_file(
            directory / "sshd_config",
            dedent(
                f"""\
            Port 2224
            ListenAddress 127.0.0.1
            HostKey {directory}/host
            PidFile {directory}/sshd.pid
            AuthorizedKeysFile {directory}/authorized_keys
            StrictModes no
            PasswordAuthentication no
            KbdInteractiveAuthentication no
            UsePAM no
            AllowUsers testuser
            """
            ),
        )
        pub = (directory / "host.pub").read_text().split()
        write_file(directory / "known_hosts", "[127.0.0.1]:2224 " + " ".join(pub[:2]) + "\n")
        (directory / "client").chmod(0o600)
        (directory / "host").chmod(0o600)
    elif package == "ifupdown":
        write_file(
            directory / "fixture.interfaces",
            "iface zc0 inet static\n address 198.18.0.1/24\n netmask 255.255.255.0\n",
        )
    elif package == "grub2-common":
        (directory / "boot/grub").mkdir(parents=True)
        run_setup(["grub-editenv", directory / "boot/grub/grubenv", "create"])
        with Path("/etc/default/grub").open("a") as output:
            output.write("\nGRUB_DEFAULT=saved\n")
    elif package == "apparmor":
        write_file(directory / "rules", "  /work/zcomp-readable r,\n")
        write_file(
            directory / "profile",
            dedent(
                f"""\
            profile zcomp-fixture {{
            #include "{directory}/rules"
              /work/known r,
            }}
            """
            ),
        )
    elif package == "kbd":
        table = b"".join(
            struct.pack("<HH", 65 + i, 65535) if i < 2 else struct.pack("<H", 65535) for i in range(256)
        )
        write_file(directory / "font.psfu", b"\x36\x04\x02\x01" + bytes(256) + table)
    elif package == "adduser":
        run_setup(["groupadd", "--gid", "1202", "zcomp-created"])
        (directory / "skel").mkdir()
        write_file(directory / "skel/welcome.txt", "fixed skeleton\n")
        write_file(
            directory / "adduser.conf",
            dedent(
                f"""\
            SKEL={directory}/skel
            DIR_MODE=0700
            """
            ),
        )
    elif package == "python3-minimal":
        write_file(directory / "fixture.py", "print(7)\n")
    elif package == "perl":
        write_file(directory / "input.json", '{"b":2,"a":1}\n')
    elif package == "findutils":
        for filename in ("tree/a.txt", "tree/sub/b.txt", "tree/sub/c.bin"):
            write_file(directory / filename, "fixed\n")
    elif package in ("initramfs-tools-core", "initramfs-tools-bin"):
        if package == "initramfs-tools-core":
            (directory / "early").mkdir()
            (directory / "main").mkdir()
            write_file(directory / "early/early.txt", "early fixture\n")
            write_file(directory / "early/early_cpio", "1\n")
            write_file(directory / "main/main.txt", "main fixture\n")
            early = run_setup(
                ["cpio", "-o", "-H", "newc", "--reproducible"],
                directory / "early",
                b"early_cpio\nearly.txt\n",
            ).stdout
            main = run_setup(
                ["cpio", "-o", "-H", "newc", "--reproducible"], directory / "main", b"main.txt\n"
            ).stdout
            import gzip

            write_file(directory / "fixture.img", early + gzip.compress(main, mtime=FIXED_EPOCH))
        else:
            shutil.copy2(WORK_DIR / "case64/fixture.img", directory / "fixture.img")
    elif package == "wtmpdb":
        # 正規のwtmp recordからimportし、SQLiteの内部schemaを手書きしない。
        record_type = ctypes.c_short

        class Exit(ctypes.Structure):
            _fields_ = [("termination", ctypes.c_short), ("exit", ctypes.c_short)]

        class Time(ctypes.Structure):
            _fields_ = [("sec", ctypes.c_int32), ("usec", ctypes.c_int32)]

        class Utmp(ctypes.Structure):
            _fields_ = [
                ("type", record_type),
                ("pid", ctypes.c_int),
                ("line", ctypes.c_char * 32),
                ("id", ctypes.c_char * 4),
                ("user", ctypes.c_char * 32),
                ("host", ctypes.c_char * 256),
                ("exit", Exit),
                ("session", ctypes.c_int32),
                ("tv", Time),
                ("addr", ctypes.c_int32 * 4),
                ("unused", ctypes.c_char * 20),
            ]

        records = []
        for kind, epoch in ((7, FIXED_EPOCH), (8, FIXED_EPOCH + 600)):
            item = Utmp(
                type=kind, pid=321, line=b"pts/9", id=b"ts/9", user=b"zcomp-fixture" if kind == 7 else b""
            )
            item.tv.sec = epoch
            records.append(bytes(item))
        write_file(directory / "legacy.wtmp", b"".join(records))
        run_setup(["wtmpdb", "import", "-f", directory / "wtmp.db", directory / "legacy.wtmp"])
    elif package == "initramfs-tools":
        (directory / "boot").mkdir()
    elif package == "sgml-base":
        write_file(directory / "ordinary.cat", 'PUBLIC "-//ZCOMP//DTD Test//EN" "fixture.dtd"\n')
        write_file(directory / "fixture.dtd", "<!ELEMENT probe (#PCDATA)>\n")
    elif package == "xml-core":
        write_file(
            directory / "ordinary.xml",
            '<?xml version="1.0"?>\n<catalog xmlns="urn:oasis:names:tc:entity:xmlns:xml:catalog"/>\n',
        )
    elif package == "polkitd":
        write_file(
            Path("/usr/share/polkit-1/actions/org.zcomp.probe.policy"),
            '<?xml version="1.0"?><!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN" "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd"><policyconfig><action id="org.zcomp.probe"><description>Fixed zcomp action</description><message>Fixed probe</message><defaults><allow_any>no</allow_any><allow_inactive>no</allow_inactive><allow_active>yes</allow_active></defaults></action></policyconfig>\n',
        )
    elif package == "dmidecode":
        run_setup(["dmidecode", "--dump-bin", directory / "dmi.bin"])
        write_file(
            directory / "expected.txt",
            run_setup(["dmidecode", "--from-dump", directory / "dmi.bin", "--type", "system"]).stdout,
        )
    elif package == "shared-mime-info":
        write_file(
            directory / "mime/packages/zcomp.xml",
            '<?xml version="1.0"?><mime-info xmlns="http://www.freedesktop.org/standards/shared-mime-info"><mime-type type="application/x-zcomp"><comment>Zcomp fixture</comment><glob pattern="*.zcprobe"/></mime-type></mime-info>\n',
        )
    elif package == "fuse3":
        source = Path("/usr/share/doc/libfuse3-dev/examples/hello.c")
        require(source.exists(), "The packaged libfuse hello example is unavailable")
        run_setup(
            [
                "gcc",
                "-O2",
                "-D_FILE_OFFSET_BITS=64",
                "-I/usr/include/fuse3",
                source,
                "-lfuse3",
                "-o",
                directory / "fuse-hello",
            ]
        )
        (directory / "mountpoint").mkdir()
    elif package == "fontconfig":
        shutil.copy2("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", directory / "font.ttf")
    elif package == "logrotate":
        write_file(directory / "current.log", "alpha\nbeta\n")
        write_file(
            directory / "logrotate.conf",
            dedent(
                f"""\
            {directory}/current.log {{
             rotate 1
             missingok
             create 0640 testuser testuser
            }}
            """
            ),
        )
    elif package == "wpasupplicant":
        write_file(directory / "passphrase.txt", "zcomp-test-passphrase\n")
    elif package == "apt-utils":
        (directory / "repo").mkdir()
        shutil.copy2(WORK_DIR / "case21/fixture.deb", directory / "repo/fixture.deb")
    elif package == "mawk":
        write_file(directory / "aggregate.awk", '{ s += $1; n++ } END { printf "sum=%d/count=%d\\n", s,n }\n')
    elif package == "gettext-base":
        write_file(directory / "input.txt", "$NAME:$UNSET\n")
    elif package == "parted":
        with (directory / "gpt.img").open("wb") as image:
            image.truncate(16 * 1024 * 1024)
        run_setup(
            ["parted", "-s", directory / "gpt.img", "mklabel", "gpt", "mkpart", "zcomp", "1MiB", "3MiB"]
        )
    elif package == "apt-listchanges":
        shutil.copytree(WORK_DIR / "case21/debroot", directory / "debroot")
        write_file(
            directory / "debroot/usr/share/doc/zcomp-fixture/changelog.Debian",
            dedent(
                """\
            zcomp-fixture (1.0) unstable; urgency=medium
            
              * Fixed newer change.
            
             -- Test <test@example.invalid>  Thu, 01 Oct 2026 00:00:00 +0000
            
            zcomp-fixture (0.9) unstable; urgency=low
            
              * Fixed older change.
            
             -- Test <test@example.invalid>  Wed, 30 Sep 2026 00:00:00 +0000
            """
            ),
        )
        run_setup(["dpkg-deb", "--build", directory / "debroot", directory / "fixture.deb"])
    elif package == "avahi-daemon":
        write_file(
            directory / "avahi.conf",
            dedent(
                """\
            [server]
            host-name=zcomp-probe
            use-ipv4=yes
            use-ipv6=no
            allow-interfaces=zc0
            enable-dbus=yes
            [wide-area]
            enable-wide-area=no
            [publish]
            disable-publishing=yes
            """
            ),
        )
    elif package == "gtk-update-icon-cache":
        write_file(
            directory / "theme/index.theme",
            dedent(
                """\
            [Icon Theme]
            Name=Zcomp
            Directories=16x16/apps
            
            [16x16/apps]
            Size=16
            Type=Fixed
            Context=Applications
            """
            ),
        )
        import base64

        write_file(
            directory / "theme/16x16/apps/zcomp-probe.png",
            base64.b64decode(
                "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jRZkAAAAASUVORK5CYII="
            ),
        )
    elif package == "ssl-cert":
        write_file(
            directory / "template.cnf",
            dedent(
                """\
            [ req ]
            default_bits=2048
            distinguished_name=req_dn
            prompt=no
            [ req_dn ]
            CN=zcomp-probe.invalid
            """
            ),
        )
    elif package == "udisks2":
        shutil.copy2(WORK_DIR / "case29/ext4.img", directory / "image.img")
    elif package == "network-manager":
        write_file(
            Path("/etc/NetworkManager/system-connections/zcomp-fixture.nmconnection"),
            dedent(
                """\
            [connection]
            id=zcomp-fixture
            uuid=01234567-89ab-cdef-0123-456789abcdef
            type=ethernet
            interface-name=zc0
            autoconnect=false
            [ipv4]
            method=disabled
            [ipv6]
            method=disabled
            """
            ),
            0o600,
        )
        write_file(
            Path("/etc/NetworkManager/conf.d/zcomp-unmanaged.conf"),
            "[keyfile]\nunmanaged-devices=interface-name:*\n",
        )
    elif package == "anacron":
        (directory / "spool").mkdir()
        write_file(
            directory / "anacrontab",
            dedent(
                f"""\
            MAILTO=""
            1 0 zcomp-job /usr/bin/printf anacron-ok > {directory}/marker
            """
            ),
        )
    elif package == "x11-xkb-utils":
        write_file(
            directory / "fixture.xkb",
            'xkb_keymap { xkb_keycodes { include "evdev+aliases(qwerty)" }; xkb_types { include "complete" }; xkb_compatibility { include "complete" }; xkb_symbols { include "pc+us+inet(evdev)" }; };\n',
        )
    elif package == "git":
        write_file(directory / "file.txt", "fixed git payload\n")
    elif package == "acl":
        write_file(directory / "file.txt", "fixed ACL payload\n", 0o640)
    elif package == "colord":
        write_file(directory / "palette.csv", "ZcompRed,255,0,0\nZcompBlue,0,0,255\n")
        # 配布版の実際の入力はXMLであり、古いman pageのCSV用optionは存在しない。
        write_file(
            directory / "palette.xml",
            '<?xml version="1.0"?><profile><description>Zcomp palette</description><copyright>Test fixture</copyright><named><color><name>ZcompRed</name><L>54</L><a>81</a><b>70</b></color><color><name>ZcompBlue</name><L>30</L><a>68</a><b>-112</b></color></named></profile>\n',
        )
    elif package == "cups-daemon":
        # 配布AppArmor profileを無効化せず、許可済みの標準directory内で分離する。
        write_file(
            directory / "cupsd.conf",
            dedent(
                """\
            Listen /run/cups/cups.sock
            Browsing Off
            WebInterface No
            LogLevel warn
            DefaultAuthType None
            <Location />
             Order allow,deny
             Allow all
            </Location>
            """
            ),
        )
        shutil.copy2(directory / "cupsd.conf", "/etc/cups/zcomp-probe.conf")
        shutil.copy2("/etc/cups/cups-files.conf", directory / "packaged-cups-files.conf")


def prepare_ca(directory):
    run_setup(
        [
            "openssl",
            "req",
            "-new",
            "-x509",
            "-nodes",
            "-newkey",
            "rsa:2048",
            "-days",
            "3650",
            "-subj",
            "/CN=Zcomp Test CA",
            "-keyout",
            directory / "ca.key",
            "-out",
            directory / "ca.pem",
        ]
    )
    run_setup(
        ["openssl", "x509", "-in", directory / "ca.pem", "-outform", "DER", "-out", directory / "ca.der"]
    )
    write_file(directory / "index.txt", "")
    write_file(directory / "serial", "01\n")
    write_file(directory / "crlnumber", "01\n")
    write_file(
        directory / "ca.cnf",
        dedent(
            f"""\
        [ca]
        default_ca=local
        [local]
        database={directory}/index.txt
        serial={directory}/serial
        crlnumber={directory}/crlnumber
        private_key={directory}/ca.key
        certificate={directory}/ca.pem
        default_md=sha256
        default_crl_days=365
        """
        ),
    )
    run_setup(["openssl", "ca", "-gencrl", "-config", directory / "ca.cnf", "-out", directory / "crl.pem"])
    run_setup(
        ["openssl", "crl", "-in", directory / "crl.pem", "-outform", "DER", "-out", directory / "crl.der"]
    )
    Path("/etc/gnupg/trusted-certs").mkdir(parents=True, exist_ok=True)
