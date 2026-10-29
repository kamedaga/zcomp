"""VM内で固定入力を用意するか、100件の代表操作を実行する。"""

from pathlib import Path
import sys

# 管理コマンドのfixture作成をホストで誤実行させない。通常はVMの起動器から呼ぶ。
if Path(__file__).resolve().parent != Path("/work"):
    raise SystemExit("Run this through tools/debian-cli.py in the experiment VM.")

import fixtures
import runner

mode = sys.argv[1]
if mode == "prepare":
    fixtures.prepare_cli()
    fixtures.prepare_services()
elif mode in ("native", "hooked"):
    runner.execute(mode)
else:
    raise SystemExit("Expected prepare, native, or hooked")
