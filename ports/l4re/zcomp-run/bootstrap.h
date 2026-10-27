#pragma once

namespace Zcomp {
// ゲストを動かす前に呼ぶ。Envの名前を消すだけでは、同じオブジェクトの複製が残る。
void drop_startup_capability(char const *name, bool audit = false);
}
