#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
work_dir=${1:?Usage: l4re-sqlite.sh <work directory>}
[[ "$work_dir" == /* && "$work_dir" != / ]] || exit 1
cache="$work_dir/sqlite-alpine"
mkdir -p "$cache"

# 配布物のバージョンと内容を固定する。APK署名の検証やinstall scriptの実行は行わない。
fetch() {
    local package=$1 digest=$2 member=$3 target=$4 archive="$cache/$1"
    if [[ ! -f "$archive" ]]; then
        local partial
        partial=$(mktemp "$cache/download.XXXXXX")
        curl -fL --retry 2 --connect-timeout 10 --max-time 120 \
            "https://dl-cdn.alpinelinux.org/alpine/v3.23/main/x86_64/$package" -o "$partial"
        printf '%s  %s\n' "$digest" "$partial" | sha256sum -c -
        mv -- "$partial" "$archive"
    fi
    printf '%s  %s\n' "$digest" "$archive" | sha256sum -c -
    tar --warning=no-unknown-keyword --no-same-owner -xzf "$archive" -C "$cache" "$member"
    cp -- "$cache/$member" "$work_dir/$target"
}
fetch sqlite-3.53.4-r0.apk 64a66b08f2e5d6bb5c4c2f3a1dd53725b8564d481fc322f11249b54690f4e9ad usr/bin/sqlite3 sqlite3
fetch musl-1.2.5-r24.apk d49d703392f1a6d2fe822db1b57e61735063077e1ad846d5f40d79fe507ec727 lib/ld-musl-x86_64.so.1 sqlite-musl
fetch readline-8.3.1-r0.apk 6d29b98eafff4aebaed4e61fca8329fbf7b26489a29fefc1d4462610d687303b usr/lib/libreadline.so.8.3 libreadline.so.8
fetch libncursesw-6.5_p20251123-r0.apk 233f20a6d64d87afbc4b03ad3e7508f5d56af747508c395ba7a6c5f1033b15f0 usr/lib/libncursesw.so.6.5 libncursesw.so.6

# image生成器の依存解決用にも標準名を用意する。ゲストへ見せる名前はNedで別途指定する。
cp -- "$work_dir/sqlite-musl" "$work_dir/ld-musl-x86_64.so.1"
cp -- "$work_dir/sqlite-musl" "$work_dir/libc.musl-x86_64.so.1"
(cd "$work_dir" && sha256sum sqlite3 sqlite-musl libreadline.so.8 libncursesw.so.6) > "$work_dir/sqlite.sha256"
cp -- "$project_dir/tests/l4re/sqlite-query.sql" "$work_dir/sqlite-query.sql"

sqlite=(env -i "$work_dir/sqlite-musl" --library-path "$work_dir" "$work_dir/sqlite3" -batch -noinit)
# 毎回新しいDBを作り、過去の実行で残った内容に依存させない。
database_dir=$(mktemp -d "$cache/database.XXXXXX")
"${sqlite[@]}" "$database_dir/sample.db" \
    "CREATE TABLE items(name TEXT, amount INTEGER); INSERT INTO items VALUES ('alpha',10),('beta',25),('gamma',30);"
cp -- "$database_dir/sample.db" "$work_dir/sample.db"
"${sqlite[@]}" "file:$work_dir/sample.db?immutable=1" "$(<"$work_dir/sqlite-query.sql")" > "$work_dir/sq-read.native.out"
printf 'PASS: Unmodified Alpine SQLite completed the native read-only query.\n'
