# 再現手順

リポジトリのルートから実行する。ビルド環境は[README](../README.md)を参照。

## Linux

Syscall User Dispatchを使えるx86-64 Linux VM内で実行する。

```sh
sudo sysctl -w vm.mmap_min_addr=0
make check
```

8項目が成功すれば完了。`Skipped`はフック経由の検証ができていないことを表す。

## Debian 100件

必要：Python 3.12、KVM、`qemu-system-x86_64`、`qemu-img`、`xorriso`。
[公式のDebian 13 genericcloud / amd64イメージ](https://cloud.debian.org/images/cloud/trixie/)を取得する。
評価時の版は`20261021-2638`。[対象・操作・期待結果](debian-cli.tsv)は100件で固定している。

```sh
make
python3 tools/debian-cli.py prepare build/debian-13-genericcloud-amd64.qcow2
```

出力された`Prepared image`のパスを指定する。

```sh
python3 tools/debian-cli.py check build/debian-reproduction/prepare.XXXX/prepared/disk.qcow2
```

同じ初期状態からnativeとhookedを実行し、出力・生成物・捕捉・SUDを比較する。
基準結果は一致90件、不一致5件、注入不可4件、環境不足1件。
既知の制約を除く失敗があれば終了値は非0になる。

ログと判定は`build/debian-reproduction/check.*/`の`console.log`、`results/`、`comparison.json`に保存する。
保存済みの出力を再判定する場合：

```sh
python3 tools/debian-cli.py compare build/debian-reproduction/check.XXXX/native/results \
  --hooked build/debian-reproduction/check.XXXX/hooked/results
```

## L4Re

```sh
make l4re-build
make check-l4re-zcomp
L4RE_CASE=busybox make check-l4re-zcomp
L4RE_CASE=sqlite make check-l4re-zcomp
```

通常12ケース、BusyBox 7ケース、SQLite 2ケースを実行する。各コマンドの`PASS`を確認する。
TCGは`L4RE_ACCEL=tcg`を付ける。ケースの説明は[tests/l4re/README.md](../tests/l4re/README.md)を参照。

## 性能

```sh
make bench-l4re-zcomp
```
