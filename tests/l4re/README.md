# L4Reのテスト

リポジトリのルートで実行します。

```sh
make check-l4re-zcomp
L4RE_ACCEL=tcg make check-l4re-zcomp
```

通常は次の5ケースを実行します。

| ケース | 確認内容 |
|---|---|
| `dynamic` | 動的musl、PIE、TLS、共有ライブラリ内のsyscall、fork／wait |
| `files` | ファイル操作、private写像、ゼロ化、部分保護・解除 |
| `pthread` | スレッド生成・回収、TLS、mutex／condvar／futex |
| `db-full` | shimと直接L4 IPCの両方で、公開したファイルへアクセスできる |
| `db-hide` | shimを迂回しても、非公開ファイルと破棄済み起動ROMへアクセスできない |

`L4RE_CASE=dynamic`または`L4RE_CASE=bypass-dynamic`で部分実行できます。
同じLinux ELFをnative Linuxでも先に実行します。直接L4 IPCだけはL4Reで確認します。
判定は終了状態・ゲストの検査結果・dispatchの証拠を使い、内部カウンタの固定値には依存しません。

## 配布バイナリと性能測定

```sh
L4RE_CASE=busybox make check-l4re-zcomp
L4RE_CASE=sqlite make check-l4re-zcomp
make bench-l4re-zcomp
```

デモは通常試験に含めません。取得するAlpineの配布物はhashで固定し、
BusyBoxのSHA-256とSQLiteの読み取り専用クエリを、同じ配布ELFによるLinuxの出力と比較します。
ベンチマークは`ports/l4re/zcomp-bench/`で別管理します。

ゲストとshimは同じTaskです。完全な閉じ込めや出力禁止を主張する試験ではありません。
汎用allocatorなどの初期権限も残るため、Capabilityの範囲とLinux syscallの範囲を同一視しません。
