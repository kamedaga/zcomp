# zcomp

zpolineを用いたLinux syscallディスパッチのプロトタイプです。Linux / x86-64とFiasco.OC＋L4Re向けの実装があります。

## ビルドと実行

### Linux

C11コンパイラ、CMake 3.20以上、Make、Gitが必要です。初回ビルド時にZydisとZycoreを取得します。

```sh
sudo apt-get install build-essential cmake git
make
make check
LD_PRELOAD="$PWD/build/libzcomp.so" /usr/bin/uname -a
```

フックの実行にはアドレス0のマップが必要です。禁止されている環境では終了コード77となり、フックを使うテストはスキップされます。実験用VMなど、低位マップを許可した環境で実行してください。

フック実行ではSUDによる未捕捉syscallの停止を既定で有効にします（対応するLinux kernelが必要）。vDSO内の実syscallも書換え対象です。shim初期化後はnative転送部以外からの発行を拒否し、通常は番号・発行位置を出力して終了コード159で停止します。fork・cloneの子では再設定し、動的なexec先ではshimが再初期化します。`ZCOMP_SCAN_ONLY=1`は書換えも停止機構も使わない対照です。LD_PRELOADが使われる前のローダー初期化、静的ELF・注入できないexec先は検証範囲外であり、同一アドレス空間内の悪意あるコードを隔離する機構ではありません。

実験用の`ZCOMP_DETOUR=1`を併用すると、番号と後続命令の条件を満たす地点をred zoneへ書き込まない`jmp`型へ変更します。ELF別の番地表は使いません。適用外は従来の`call`型のままであり、任意の命令列での安全性を保証する機能ではありません。SUDは有効なままです。

通常の`call`型にはred zoneの破壊と、0番地が読み出せることによる互換性の制約があります。

`make check`は走査器・転送・clone・execの代表試験を実行します。フックを使う試験には、低位マップを許可した環境が必要です。

### Fiasco.OC＋L4Re

上記に加え、Ubuntu 24.04では次のパッケージを用意します。

```sh
sudo apt-get install --no-install-recommends flex bison gawk \
  libncurses-dev libc6-dev-i386 liburi-perl libxml-parser-perl \
  libgit-repository-perl libtemplate-perl pkg-config qemu-system-x86 \
  device-tree-compiler xorriso mtools dialog curl xz-utils ripgrep musl-tools
make l4re-build
make l4re-zcomp-build
make check-l4re-zcomp
make l4re-zcomp
```

公式スナップショット26.09.0を取得し、amd64向けにビルドします。
QEMUは既定でKVMを使用します。KVMを使えない場合は次で確認できます。

```sh
L4RE_ACCEL=tcg make check-l4re-zcomp
```

配布済みバイナリのデモは、ルートディレクトリで`L4RE_CASE=busybox make check-l4re-zcomp`、
`L4RE_CASE=sqlite make check-l4re-zcomp`を使います（初回はAlpineのパッケージを取得）。

通常のL4Re試験は動的musl・資源操作・pthread・Capability迂回の許可／拒否の5ケースです。
BusyBoxはSHA-256、SQLiteは読み取り専用クエリをLinuxの出力と比較します。
性能測定は通常試験と分け、`make bench-l4re-zcomp`で実行します。

対話起動はCtrl+Cで終了します。公式helloだけを確認する場合は`make check-l4re-hello`を使います。
構築先は`L4RE_LAB_DIR`（既定：`l4re/`、空白のない絶対パス）、並列数は`L4RE_JOBS`（既定：8）で変更できます。

## ディレクトリ構成

```text
src/                       Linux参照実装と共通のZydis走査器
ports/l4re/zcomp-run/       L4Re向けELFローダー・実行ランタイム
  linux/                   Linux syscall shim（ファイル・メモリ・TLSなど）
tests/                     Linux側の代表テスト
  l4re/                    L4Reの5ケースとデモの判定
ports/l4re/zcomp-bench/     独立した性能測定
tools/                     Fiasco.OC＋L4Reの構築・QEMU起動スクリプト
build/                     Linux側のビルド生成物（Git管理外）
l4re/                      外部OSのソース・生成物・ログ（Git管理外）
```

## ライセンス

本プロジェクトは[MIT License](LICENSE)で公開します。
Zydis・Zycoreの著作権表示とライセンスは[THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES)に記載しています。
別途取得するFiasco.OC・L4Re・デモ用パッケージには、それぞれのライセンスが適用されます。
