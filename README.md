# zcomp

Linux / x86-64上でビルドします。初回は依存ライブラリとOSソースをダウンロードします。
以下はUbuntu 24.04での手順です。

## Linux版

CMake 3.20以上が必要です。

```sh
sudo apt-get install build-essential cmake git
make
```

生成物は`build/`に置かれます。

## Fiasco.OC＋L4Re版

Linux版の依存に加え、次のパッケージをインストールします。

```sh
sudo apt-get install --no-install-recommends flex bison gawk \
  libncurses-dev libc6-dev-i386 liburi-perl libxml-parser-perl \
  libgit-repository-perl libtemplate-perl pkg-config qemu-system-x86 \
  device-tree-compiler xorriso mtools dialog curl xz-utils ripgrep musl-tools
make l4re-build
make l4re-zcomp-build
```

公式スナップショット26.09.0をamd64向けにビルドします。
構築先は既定で`l4re/`です。`L4RE_LAB_DIR`で空白・コロンを含まない絶対パスを指定できます。
並列数は`L4RE_JOBS`で変更できます（既定：8）。
