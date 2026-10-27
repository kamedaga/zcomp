#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace Zcomp {
constexpr size_t Max_mappings = 128;

struct File_fault_range {
    uintptr_t first, last;
    unsigned flags;
    bool operator==(File_fault_range const &other) const
    { return first == other.first && last == other.last && flags == other.flags; }
};

template<typename Backing>
struct Mapping_span {
    uintptr_t address;
    size_t size, offset;
    unsigned flags;
    std::shared_ptr<Backing> backing;
    bool prepared = false;

    uintptr_t end() const { return address + size; }
    size_t mapped_size() const
    {
        // ファイル末尾を完全に越すページは、論理的な写像の中でも物理ページを供給しない。
        return offset < backing->size ? std::min(size, backing->size - offset) : 0;
    }
    Mapping_span slice(uintptr_t first, uintptr_t last) const
    {
        auto part = *this;
        part.offset += first - address;
        part.address = first;
        part.size = last - first;
        return part;
    }
};

// OSに依存しない区間操作。新しい表を先に作り、native写像の成功後にだけ現在の表へ交換する。
template<typename Backing>
struct Mapping_layout {
    using Span = Mapping_span<Backing>;
    std::vector<Span> spans;

    bool covers(uintptr_t first, size_t size, unsigned flags = 0, bool physical = false) const
    {
        if (size > UINTPTR_MAX - first) return false;
        uintptr_t last = first + size, cursor = first;
        for (auto const &span : spans) {
            if (span.end() <= cursor) continue;
            if (span.address > cursor || (span.flags & flags) != flags) return false;
            uintptr_t end = physical ? span.address + span.mapped_size() : span.end();
            if (end <= cursor) return false;
            cursor = std::min(last, end);
            if (cursor == last) return true;
        }
        return false;
    }

    uintptr_t find_free(uintptr_t first, uintptr_t limit, size_t size,
                        size_t alignment = 1, uintptr_t bias_origin = 0) const
    {
        if (!alignment || (alignment & (alignment - 1))) return 0;
        first = std::max(first, bias_origin);
        auto align = [&](uintptr_t start) {
            // ELFのp_vaddr先頭が0でなくても、配置番地ではなくload biasをalignmentへ揃える。
            uintptr_t padding = (bias_origin - start) & (alignment - 1);
            return start <= limit && padding <= limit - start ? start + padding : limit;
        };
        first = align(first);
        for (auto const &span : spans) {
            if (span.end() <= first) continue;
            if (span.address >= first && size <= span.address - first) break;
            first = align(span.end());
        }
        return first <= limit && size <= limit - first ? first : 0;
    }

    std::vector<Span> replace(uintptr_t first, size_t size, Span const *replacement = nullptr) const
    {
        uintptr_t last = first + size;
        std::vector<Span> result;
        for (auto const &span : spans) {
            if (span.end() <= first || span.address >= last) result.push_back(span);
            else {
                if (span.address < first) result.push_back(span.slice(span.address, first));
                if (span.end() > last) result.push_back(span.slice(last, span.end()));
            }
        }
        if (replacement) result.push_back(*replacement);
        std::sort(result.begin(), result.end(), [](auto const &a, auto const &b) { return a.address < b.address; });
        return result;
    }

    std::vector<Span> protect(uintptr_t first, size_t size, unsigned flags) const
    {
        uintptr_t last = first + size;
        std::vector<Span> result;
        for (auto const &span : spans) {
            if (span.end() <= first || span.address >= last) { result.push_back(span); continue; }
            if (span.address < first) result.push_back(span.slice(span.address, first));
            auto middle = span.slice(std::max(first, span.address), std::min(last, span.end()));
            middle.flags = flags;
            result.push_back(std::move(middle));
            if (span.end() > last) result.push_back(span.slice(last, span.end()));
        }
        return result;
    }

    static void coalesce(std::vector<Span> &spans)
    {
        // 保護変更の反復だけで表が増え続けないよう、実体とoffsetが連続する区間だけを結合する。
        size_t count = 0;
        for (size_t i = 0; i < spans.size(); ++i) {
            auto &span = spans[i];
            if (count && spans[count - 1].end() == span.address
                && spans[count - 1].backing == span.backing && spans[count - 1].flags == span.flags
                && spans[count - 1].prepared == span.prepared
                && spans[count - 1].offset + spans[count - 1].size == span.offset)
                spans[count - 1].size += span.size;
            else { if (count != i) spans[count] = std::move(span); ++count; }
        }
        spans.resize(count);
    }
};
}
