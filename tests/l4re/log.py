import re
import sys


def normalize(log):
    cases = set(re.findall(r"\[zcomp-(?:policy|result)\] case=([\w-]+)", log))
    labels = {label for case in cases for label in (case[:8], (case + "-out")[:8])}
    if not labels:
        return log
    # Nedのprintは本文と改行が別IPC。完結した親レコードの直後の既知Moe prefixだけを分離する。
    # 欠落した値や途中で切れた行は復元せず、そのまま検査失敗にする。
    parent = (r"(\[zcomp-result\] case=[\w-]+ status=\d+"
              r"|\[zcomp-authority\] [^\n]*?factory_allow=none"
              r"|\[zcomp-policy\] [^\n]*?allocator_can_create_log=(?:yes|no))")
    prefix = "|".join(re.escape(label) for label in sorted(labels))
    return re.sub(parent + rf"(?=(?:{prefix})\s*\| )", r"\1\n", log)


if __name__ == "__main__":
    sys.stdout.write(normalize(sys.stdin.read()))
