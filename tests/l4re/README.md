# L4Reのテスト

リポジトリのルートで実行します。

```sh
make check-l4re-zcomp
L4RE_ACCEL=tcg make check-l4re-zcomp
```

通常は次の12ケースを実行します。

| ケース | 確認内容 |
|---|---|
| `dynamic` | 動的musl、PIE、TLS、共有ライブラリ内のsyscall、fork／wait |
| `files` | ファイル操作、private写像、ゼロ化、部分保護・解除 |
| `pthread` | スレッド生成・回収、TLS、mutex／condvar／futex |
| `db-full` | shimと直接L4 IPCの両方で、公開したファイルへアクセスできる |
| `db-hide` | shimを迂回しても、非公開ファイルと破棄済み起動ROMへアクセスできない |
| `cap-ok` | 同じ権限試験ELFでwrite、openat／read／close、128 KiBのmmap／munmap、fork／wait4が成功する |
| `no-out`・`no-file` | linux_stdout／linux_filesを渡さず、write／openatがEACCESになる |
| `low-mem`・`no-mem` | linux_memoryが64 KiBなら128 KiBのmmapがENOMEM、未付与ならEACCESになる |
| `no-proc`・`lo-proc` | linux_processが未付与ならforkがEACCES、64 KiBならENOMEMになる |

`L4RE_CASE=dynamic`または`L4RE_CASE=bypass-dynamic`で部分実行できます。
同じLinux ELFをnative Linuxでも先に実行します。capabilityの省略・quotaによる拒否と直接L4 IPCはL4Reで確認します。
拒否試験はゲストが戻り値を検査し、ホストが終了状態と初期capability・quotaを確認します。
迂回試験は通常syscallで呼び出し回数が増えることと、直接L4 IPCの前後で変わらないことも確認します。
判定は終了状態・ゲストの検査結果・dispatchの証拠を使い、内部カウンタの固定値には依存しません。

## 配布バイナリと性能測定

```sh
L4RE_CASE=busybox make check-l4re-zcomp
L4RE_CASE=sqlite make check-l4re-zcomp
make bench-l4re-zcomp
```

デモは通常試験に含めません。取得するAlpineの配布物はhashで固定し、
BusyBoxはecho、公開ファイルのcat、非公開ファイルのcat（2件）、secret公開時のcat、sha256sum、wcの7件です。
SQLiteはメモリ上の表の作成・挿入・更新・COMMIT・集計と、公開DBの読み取りの2件です。
同じ配布ELFによるLinuxの出力と比較し、BusyBoxの拒否2件は終了値1も照合します。
ベンチマークは`ports/l4re/zcomp-bench/`で別管理します。

ゲストとshimは同じTaskです。完全な閉じ込めや出力禁止を主張する試験ではありません。
汎用allocatorなどの初期権限も残るため、Capabilityの範囲とLinux syscallの範囲を同一視しません。
