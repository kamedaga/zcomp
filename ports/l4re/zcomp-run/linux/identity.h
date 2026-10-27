#pragma once
#include <cerrno>
#include <cstdint>

namespace Zcomp {
// Linux側の所有者情報は単一の仮想IDに限定する。nativeの実行権限をUIDへ置き換えない。
constexpr uint32_t Guest_uid = 1000, Guest_gid = 1000;

inline long set_guest_identity(uint64_t requested, uint32_t current)
{
    // BusyBoxの権限放棄処理は同じIDも設定する。成功を返せるのは実際に状態が変わらない場合だけ。
    // saved ID・setuid実行・複数ユーザーは未対応なので、別IDへの変更を成功したことにしない。
    return static_cast<uint32_t>(requested) == current ? 0 : -EPERM;
}
}
