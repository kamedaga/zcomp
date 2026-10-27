#pragma once
#include <cerrno>
#include <string>

namespace Zcomp {
inline long namespace_path(char const *path, std::string &name)
{
    name.clear();
    if (!*path) return -ENOENT;
    // cwdは公開rootに固定する。上位成分を拒否し、ROMやnativeの名前解決には委譲しない。
    while (*path) {
        while (*path == '/') ++path;
        char const *first = path;
        while (*path && *path != '/') ++path;
        size_t size = path - first;
        if (!size || (size == 1 && *first == '.')) continue;
        if (size == 2 && first[0] == '.' && first[1] == '.') return -EACCES;
        if (!name.empty()) name += '/';
        name.append(first, size);
        if (name.size() >= 256) return -ENAMETOOLONG;
    }
    return name.empty() ? -EISDIR : 0;
}
}
