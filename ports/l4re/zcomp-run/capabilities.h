#pragma once
#include <l4/re/mem_alloc>
#include <initializer_list>

namespace Zcomp {
struct Named_allocator { char const *name; L4::Cap<L4Re::Mem_alloc> cap; };

// 監査は明示的に要求されたときの観測だけを担う。ポリシーの設定・合否判定は呼出側の責任。
void describe_initial_capabilities();
void describe_memory_allocators(std::initializer_list<Named_allocator> allocators);
}
