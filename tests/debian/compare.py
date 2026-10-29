"""既知の非決定性だけを検査して正規化し、動作と捕捉を別々に判定する。"""

from collections import Counter
from datetime import datetime, timezone
import json
import re

import calendar
import time

TRACE = re.compile(rb"\[zcomp\] nr=\d+ (?:-> -?\d+|phase=attempt)\n")
# 正常な検査機構の起動通知だけを除く。拒否・設定失敗のログは差分として残す。
INIT = re.compile(
    rb"zcomp: (?:segments=\d+ candidates=\d+ accepted=\d+ covered=\d+ ambiguous=\d+ undecodable=\d+ mode=zpoline|guard=sud scope=post-init)\n"
)
CTIME = re.compile(
    rb"^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [ 0-9]\d \d\d:\d\d:\d\d \d{4}$"
)


def timestamp_in_range(value, step):
    # ctime形式には小数秒がない。丸めによる境界だけを許し、大きな時計ずれは隠さない。
    return step["epoch_start"] - 1 <= value <= step["epoch_end"] + 1


def normalize_cli_output(case_number, data, step, kind):
    # 子のstderrを転送・保存するCLIでは、既知の観測用出力だけを抽出する。
    # 生bytesは残し、アプリケーションの出力やエラーは削除しない。
    if kind == "stderr" or case_number == 28:
        data = TRACE.sub(b"", INIT.sub(b"", data))
    if kind == "stderr":
        return data
    if case_number == 22 and kind == "stdout":
        lines = data.splitlines()
        assert lines[0].startswith(b"POPULARITY-CONTEST-0 ")
        assert lines[-1].startswith(b"END-POPULARITY-CONTEST-0 ")

        def header(line):
            values = re.findall(rb"\bTIME:(\d+)\b", line)
            assert len(values) == 1 and timestamp_in_range(int(values[0]), step)
            return re.sub(rb"\bTIME:\d+\b", b"TIME:<validated>", line)

        # 同率の列挙順は問わないが、package/path/atime/ctimeの値は消さない。
        body = lines[1:-1]
        assert all(re.fullmatch(rb"\d+ \d+ \S+ \S+(?: <[^>]+>)?", line) for line in body)
        return b"\n".join([header(lines[0]), *sorted(body), header(lines[-1])])
    if case_number == 28 and kind == "file":
        lines = data.splitlines()
        found = 0
        for i, line in enumerate(lines):
            if CTIME.fullmatch(line):
                epoch = calendar.timegm(time.strptime(line.decode(), "%a %b %d %H:%M:%S %Y"))
                assert timestamp_in_range(epoch, step)
                lines[i] = b"<validated timestamp>"
                found += 1
        assert found == 2
        return b"\n".join(lines)
    if case_number == 7 and kind == "file":
        match = re.search(rb"^# \(crontab.txt installed on (.+)\)$", data, re.MULTILINE)
        assert match and CTIME.fullmatch(match[1])
        epoch = calendar.timegm(time.strptime(match[1].decode(), "%a %b %d %H:%M:%S %Y"))
        assert timestamp_in_range(epoch, step)
        return data[: match.start(1)] + b"<validated timestamp>" + data[match.end(1) :]
    return data


# これらの生成物は完全なhash一致の代わりに、実行側で個別の意味検査を行う。
SEMANTIC_FILES = {
    44: ("messages.pot",),
    46: ("gnupg/trustdb.gpg",),
    57: ("gnupg/random_seed",),
    58: ("gnupg/crls.d/",),
    67: ("boot/",),
    76: ("state",),
    83: (),
    85: ("certificate.pem",),
    92: ("repo/.git/index",),
    100: ("cache/", "state/", "log/", "spool/", "tmp/"),
}
MUTABLE_INPUTS = {
    46: ("gnupg/trustdb.gpg",),
    53: ("boot/grub/grubenv",),
    72: ("gnupg/pubring.kbx",),
    76: ("current.log",),
}


def strip_shim_diagnostics(data):
    return TRACE.sub(b"", INIT.sub(b"", data))


def normalize_output(case_number, data, step, kind):
    if case_number <= 30:
        return normalize_cli_output(case_number, data, step, kind)
    if kind == "stderr":
        data = strip_shim_diagnostics(data)
    if case_number in (57, 58) and kind == "stderr":
        data = re.sub(rb"(?m)^(gpg-agent|dirmngr)\[[1-9]\d*(?:\.\d+)?\]:", rb"\1[<pid>]:", data)
    if case_number in (57, 61) and kind == "stdout":
        match = re.match(rb"OK Pleased to meet you, process ([1-9]\d*)\n", data)
        assert match
        if case_number == 61 and "pid" in step:
            assert int(match[1]) == step["pid"]
        data = b"OK Pleased to meet you, process <validated>\n" + data[match.end() :]
    if case_number == 50 and kind == "stderr":

        def port(match):
            value = int(match[1])
            assert 1 <= value <= 65535
            return b"from 127.0.0.1 port <ephemeral>"

        data = re.sub(rb"from 127\.0\.0\.1 port (\d+)", port, data)
        data = re.sub(rb"(Disconnected from user testuser 127\.0\.0\.1 port )\d+", rb"\1<ephemeral>", data)
    if case_number == 83 and kind == "stderr":

        def cookie(match):
            assert 0 <= int(match[1]) <= 0xFFFFFFFF
            return b"Local service cookie is <validated>."

        data = re.sub(rb"Local service cookie is (\d+)\.", cookie, data)
    if case_number == 97 and kind == "stdout":
        match = re.search(rb"(?m)^  updated:\s+(.+) \((\d+) seconds ago\)$", data)
        assert match
        epoch = (
            datetime.strptime(match[1].decode(), "%a %b %d %H:%M:%S %Y")
            .replace(tzinfo=timezone.utc)
            .timestamp()
        )
        elapsed = int(match[2])
        assert step["epoch_start"] - 180 <= epoch <= step["epoch_end"] + 1
        assert abs(step["epoch_end"] - epoch - elapsed) <= 3
        data = (
            data[: match.start()] + b"  updated: <validated daemon timestamp and age>" + data[match.end() :]
        )
    return data


def comparable_files(case_number, files):
    result = dict(files)
    if case_number == 18:
        result.pop("sshd.pid", None)
    if case_number == 28:
        result.pop("capture.log", None)
    if case_number == 50:
        result.pop("sshd.pid", None)
    for name in list(result):
        if any(
            name == prefix or (prefix.endswith("/") and name.startswith(prefix))
            for prefix in SEMANTIC_FILES.get(case_number, ())
        ):
            result.pop(name)
    return result


def compare(native_dir, hooked_dir):
    native = json.loads((native_dir / "results.json").read_text())
    hooked = json.loads((hooked_dir / "results.json").read_text())
    assert native["library"]["sha256"] == hooked["library"]["sha256"]
    assert (native_dir / "installed.tsv").read_bytes() == (hooked_dir / "installed.tsv").read_bytes()
    assert (native_dir / "packages-100.tsv").read_bytes() == (hooked_dir / "packages-100.tsv").read_bytes()
    assert len(native["cases"]) == len(hooked["cases"]) == 100
    records = []
    for native_case, hooked_case in zip(native["cases"], hooked["cases"]):
        case_number = native_case["number"]
        assert case_number == hooked_case["number"] and native_case["package"] == hooked_case["package"]
        record = dict(
            number=case_number,
            package=native_case["package"],
            native_status=native_case["execution_status"],
            hooked_status=hooked_case["execution_status"],
            behavior="NOT_COMPARED",
            interception="NOT_RUN",
            reasons=[],
            comparisons=[],
        )
        record["hook_calls"] = sum(s.get("hook_calls", 0) for s in hooked_case["steps"])
        record["initializations"] = sum(s.get("initializations", 0) for s in hooked_case["steps"])
        record["direct_steps_hooked"] = bool(hooked_case["steps"]) and all(
            s.get("hook_calls", 0) and s.get("initializations", 0) for s in hooked_case["steps"]
        )
        record["interception"] = "PRESENT" if record["hook_calls"] else "ABSENT"
        if native_case["execution_status"] in ("HARNESS_ERROR", "PLANNED") or hooked_case[
            "execution_status"
        ] in ("HARNESS_ERROR", "PLANNED"):
            record.update(status="PLANNED", reason=native_case.get("reason", hooked_case.get("reason")))
        elif (
            native_case["execution_status"] == "BLOCKED_ENV"
            or hooked_case["execution_status"] == "BLOCKED_ENV"
        ):
            record.update(status="BLOCKED_ENV", reason=native_case.get("reason", hooked_case.get("reason")))
        elif native_case["execution_status"] == "TIMEOUT":
            record.update(status="TIMEOUT", reason="Native timeout")
        elif native_case["execution_status"] != "EXPECTED":
            record.update(
                status="NATIVE_FAIL", reason=native_case.get("reason", "The native oracle was not satisfied")
            )
        else:
            same = hooked_case["execution_status"] == "EXPECTED" and len(native_case["steps"]) == len(
                hooked_case["steps"]
            )
            for i, (native_step, hooked_step) in enumerate(zip(native_case["steps"], hooked_case["steps"])):

                def command(case, step):
                    values = list(step["command"])
                    if case_number in (34, 87):
                        bindings = case.get("runtime_bindings", {})
                        pid_at = 2 if case_number == 34 else 3
                        assert int(values[pid_at]) > 0
                        if bindings:
                            assert int(values[pid_at]) == bindings["helper_pid"]
                        values[pid_at] = "<validated helper PID>"
                    return values

                checks = dict(
                    step=i,
                    same_binary=native_step["binary"] == hooked_step["binary"],
                    same_command=command(native_case, native_step) == command(hooked_case, hooked_step),
                    returncode_equal=native_step["returncode"] == hooked_step["returncode"],
                )

                def environment(step):
                    values = {
                        key: value
                        for key, value in step.get("environment", {}).items()
                        if key not in ("LD_PRELOAD", "ZCOMP_TRACE")
                    }
                    if case_number == 99:
                        assert re.fullmatch(r"pid:\[\d+\]", values.get("ZCOMP_PARENT_PIDNS", ""))
                        values["ZCOMP_PARENT_PIDNS"] = "<validated parent namespace>"
                    return values

                checks.update(
                    same_environment=environment(native_step) == environment(hooked_step),
                    same_stdin=native_step.get("stdin_sha256") == hooked_step.get("stdin_sha256"),
                )
                policy = native_step.get("comparison", "exact")
                assert policy == hooked_step.get("comparison", "exact")
                for kind in ("stdout", "stderr"):
                    left = (native_dir / f"{case_number:02d}-{i}.{kind}").read_bytes()
                    right = (hooked_dir / f"{case_number:02d}-{i}.{kind}").read_bytes()
                    checks[kind + "_raw_equal"] = left == right
                    if kind == "stdout" and policy == "semantic":
                        checks[kind + "_equal"] = bool(
                            native_case.get("expectations_met") and hooked_case.get("expectations_met")
                        )
                        checks[kind + "_rule"] = (
                            "Exact per-execution identity oracle and equal semantic observations"
                        )
                    else:
                        try:
                            checks[kind + "_equal"] = normalize_output(
                                case_number, left, native_step, kind
                            ) == normalize_output(case_number, right, hooked_step, kind)
                        except (AssertionError, ValueError, IndexError) as error:
                            checks[kind + "_equal"] = False
                            record["reasons"].append(f"Invalid {kind} normalization: {type(error).__name__}")
                same = same and all(
                    checks[key]
                    for key in (
                        "same_binary",
                        "same_command",
                        "same_environment",
                        "same_stdin",
                        "returncode_equal",
                        "stdout_equal",
                        "stderr_equal",
                    )
                )
                record["comparisons"].append(checks)
            before = native_case.get("files_before") == hooked_case.get("files_before")
            native_files, hooked_files = comparable_files(
                case_number, native_case.get("files_after", {})
            ), comparable_files(case_number, hooked_case.get("files_after", {}))
            differences = [
                path
                for path in sorted(set(native_files) | set(hooked_files))
                if native_files.get(path) != hooked_files.get(path)
            ]
            observations = native_case.get("observations") == hooked_case.get("observations")
            mutated = {}
            if case_number > 30:
                for label, case in (("native", native_case), ("hooked", hooked_case)):
                    mutated[label] = [
                        name
                        for name, info in case.get("files_before", {}).items()
                        if name not in MUTABLE_INPUTS.get(case_number, ())
                        and case.get("files_after", {}).get(name) != info
                    ]
            record.update(
                fixtures_equal=before,
                differing_files=differences,
                observations_equal=observations,
                unexpected_input_mutations=mutated,
            )
            same = same and before and not differences and observations and not any(mutated.values())
            for filename in {7: ["07-crontab.final"], 28: ["28-capture.log"]}.get(case_number, []):
                try:
                    equal = normalize_cli_output(
                        case_number, (native_dir / filename).read_bytes(), native_case["steps"][0], "file"
                    ) == normalize_cli_output(
                        case_number, (hooked_dir / filename).read_bytes(), hooked_case["steps"][0], "file"
                    )
                except (AssertionError, ValueError, FileNotFoundError):
                    equal = False
                record[filename + "_equal"] = equal
                same = same and equal
            if case_number == 30:
                same = (
                    same
                    and native_case.get("device_removed", False)
                    and hooked_case.get("device_removed", False)
                )
            record["behavior"] = "MATCH" if same else "MISMATCH"
            if not same:
                record["reasons"].append(
                    hooked_case.get("reason", "Output, fixture, artifact, or semantic observations differ")
                )
            record["status"] = (
                "TIMEOUT"
                if hooked_case["execution_status"] == "TIMEOUT"
                else (
                    "NO_HOOK"
                    if not record["direct_steps_hooked"]
                    else "MISMATCH" if not same else "MATCH_WITH_HOOKS"
                )
            )
            if native["mode"] == hooked["mode"] == "native":
                record["status"] = "REPEAT_MATCH" if same else "REPEAT_MISMATCH"
        records.append(record)
    return dict(
        kernel=native["kernel"],
        library=native["library"],
        denominator=100,
        summary=dict(Counter(record["status"] for record in records)),
        cases=records,
        scope="One workload per package. Main labels require direct-command hook evidence; Post-init SUD evidence is checked separately; this is not full syscall coverage.",
    )
