#include "elf_image.h"
#include <string.h>

static int in_file(uint64_t offset, uint64_t length, size_t size)
{
    /* 足し算してから比較すると、細工されたELFの桁あふれを見逃す。 */
    return offset <= size && length <= size - offset;
}

const char *zcomp_elf_validate_static_pie(const void *bytes,
                                         const struct zcomp_elf_image *image)
{
    /* 範囲検査済みのimageだけを渡す。PIEフラグはtoolchainごとに異なるため必須にしない。 */
    if (image->header.e_type != ET_DYN || image->interpreter[0] || !image->dynamic.p_type)
        return "Expected an ET_DYN static PIE with a dynamic table and no interpreter";
    for (uint64_t offset = 0; offset < image->dynamic.p_filesz; offset += sizeof(Elf64_Dyn)) {
        Elf64_Dyn entry;
        memcpy(&entry, (const char *)bytes + image->dynamic.p_offset + offset, sizeof(entry));
        if (entry.d_tag == DT_NULL) return NULL;
        if (entry.d_tag == DT_NEEDED)
            return "An ELF without an interpreter cannot require shared libraries";
        if (entry.d_tag == DT_TEXTREL || (entry.d_tag == DT_FLAGS && (entry.d_un.d_val & DF_TEXTREL)))
            return "Static PIE text relocations are not supported";
    }
    return "Unterminated static PIE dynamic table";
}

const char *zcomp_elf_validate(const void *bytes, size_t size,
                              struct zcomp_elf_image *image)
{
    memset(image, 0, sizeof(*image));
    image->alignment = 4096;
    if (size < sizeof(Elf64_Ehdr))
        return "Truncated ELF header";
    memcpy(&image->header, bytes, sizeof(image->header));
    const Elf64_Ehdr *h = &image->header;
    if (memcmp(h->e_ident, ELFMAG, SELFMAG)
        || h->e_ident[EI_CLASS] != ELFCLASS64
        || h->e_ident[EI_DATA] != ELFDATA2LSB
        || h->e_ident[EI_VERSION] != EV_CURRENT
        || h->e_machine != EM_X86_64 || h->e_version != EV_CURRENT
        || h->e_ehsize != sizeof(*h))
        return "Expected a little-endian x86-64 ELF";
    if (h->e_type != ET_EXEC && h->e_type != ET_DYN)
        return "Expected an ET_EXEC or ET_DYN image";
    if (!h->e_phnum || h->e_phnum > 64
        || h->e_phentsize != sizeof(Elf64_Phdr)
        || !in_file(h->e_phoff, (uint64_t)h->e_phnum * h->e_phentsize, size))
        return "Invalid program header range or count";

    int entry_found = 0;
    int tls_found = 0;
    Elf64_Phdr tls = {0};
    for (unsigned i = 0; i < h->e_phnum; ++i) {
        Elf64_Phdr p;
        memcpy(&p, (const char *)bytes + h->e_phoff + i * sizeof(p), sizeof(p));
        if (p.p_type == PT_INTERP) {
            if (image->interpreter[0] || p.p_filesz < 2 || p.p_filesz > sizeof(image->interpreter)
                || !in_file(p.p_offset, p.p_filesz, size))
                return "Invalid or duplicate interpreter header";
            const char *path = (const char *)bytes + p.p_offset;
            if (path[0] != '/' || path[p.p_filesz - 1] || memchr(path, 0, p.p_filesz - 1))
                return "Expected a terminated absolute interpreter path";
            memcpy(image->interpreter, path, p.p_filesz);
        }
        if (p.p_type == PT_DYNAMIC) {
            if (image->dynamic.p_type || !p.p_filesz || p.p_filesz % sizeof(Elf64_Dyn)
                || p.p_filesz > p.p_memsz || !in_file(p.p_offset, p.p_filesz, size))
                return "Invalid or duplicate dynamic header";
            int terminated = 0;
            for (uint64_t offset = 0; offset < p.p_filesz; offset += sizeof(Elf64_Dyn)) {
                Elf64_Dyn entry;
                memcpy(&entry, (const char *)bytes + p.p_offset + offset, sizeof(entry));
                if (entry.d_tag == DT_NULL) { terminated = 1; break; }
            }
            if (!terminated) return "Unterminated dynamic table";
            image->dynamic = p;
        }
        if (p.p_type == PT_TLS) {
            if (tls_found++ || p.p_filesz > p.p_memsz || !in_file(p.p_offset, p.p_filesz, size)
                || p.p_memsz > 64 * 1024 * 1024 || p.p_vaddr >= 0x0000800000000000ULL
                || p.p_memsz > 0x0000800000000000ULL - p.p_vaddr
                || p.p_align > 1024 * 1024 || (p.p_align > 1 && (p.p_align & (p.p_align - 1))))
                return "Invalid static TLS template";
            tls = p;
        }
        if (p.p_type == PT_GNU_STACK && (p.p_flags & PF_X))
            return "Executable stacks are not supported";
        if (p.p_type != PT_LOAD || !p.p_memsz)
            continue;
        if (image->count == ZCOMP_MAX_SEGMENTS)
            return "Too many loadable segments for the prototype";
        if (p.p_filesz > p.p_memsz || !in_file(p.p_offset, p.p_filesz, size)
            || (h->e_type == ET_EXEC && p.p_vaddr < 4096) || p.p_memsz > 64 * 1024 * 1024
            || p.p_vaddr >= 0x0000800000000000ULL
            || p.p_memsz > 0x0000800000000000ULL - p.p_vaddr)
            return "Invalid loadable segment address or file range";
        if ((p.p_flags & (PF_W | PF_X)) == (PF_W | PF_X)
            || !(p.p_flags & PF_R))
            return "Writable executable or unreadable segments are not supported";
        if (p.p_align > 1 && ((p.p_align & (p.p_align - 1))
            || (p.p_vaddr % p.p_align != p.p_offset % p.p_align)))
            return "Invalid loadable segment alignment";
        uint64_t begin = p.p_vaddr & ~4095ULL;
        uint64_t end = (p.p_vaddr + p.p_memsz + 4095) & ~4095ULL;
        if (!image->count || begin < image->first_page) image->first_page = begin;
        if (end > image->last_page) image->last_page = end;
        if (p.p_align > image->alignment) image->alignment = p.p_align;
        for (size_t j = 0; j < image->count; ++j) {
            const Elf64_Phdr *q = &image->segments[j];
            uint64_t qbegin = q->p_vaddr & ~4095ULL;
            uint64_t qend = (q->p_vaddr + q->p_memsz + 4095) & ~4095ULL;
            if (begin < qend && qbegin < end)
                return "Page-overlapping loadable segments are not supported";
        }
        if ((p.p_flags & PF_X) && h->e_entry >= p.p_vaddr
            && h->e_entry - p.p_vaddr < p.p_filesz)
            entry_found = 1;
        uint64_t phsize = (uint64_t)h->e_phnum * h->e_phentsize;
        if (h->e_phoff >= p.p_offset && h->e_phoff - p.p_offset <= p.p_filesz
            && phsize <= p.p_filesz - (h->e_phoff - p.p_offset))
            image->phdr_address = p.p_vaddr + h->e_phoff - p.p_offset;
        image->segments[image->count++] = p;
    }
    if (!entry_found)
        return "Entry point is not in the file-backed part of an executable segment";
    if (image->dynamic.p_type) {
        const Elf64_Phdr *d = &image->dynamic;
        int mapped = 0;
        for (size_t i = 0; i < image->count; ++i) {
            const Elf64_Phdr *p = &image->segments[i];
            if (d->p_vaddr >= p->p_vaddr && d->p_vaddr - p->p_vaddr <= p->p_filesz
                && d->p_filesz <= p->p_filesz - (d->p_vaddr - p->p_vaddr)
                && d->p_offset >= p->p_offset && d->p_offset - p->p_offset == d->p_vaddr - p->p_vaddr)
                mapped = 1;
        }
        if (!mapped) return "Dynamic table is not included in a loadable segment";
    }
    if (image->interpreter[0] && !image->dynamic.p_type)
        return "Interpreter requires a dynamic table";
    if (tls_found && tls.p_filesz) {
        int mapped = 0;
        for (size_t i = 0; i < image->count; ++i) {
            const Elf64_Phdr *p = &image->segments[i];
            if (tls.p_vaddr >= p->p_vaddr && tls.p_vaddr - p->p_vaddr <= p->p_filesz
                && tls.p_filesz <= p->p_filesz - (tls.p_vaddr - p->p_vaddr)
                && tls.p_offset >= p->p_offset && tls.p_offset - p->p_offset == tls.p_vaddr - p->p_vaddr)
                mapped = 1;
        }
        /* AT_PHDR経由でmusl自身がコピーする。未写像の初期値を参照させてはいけない。 */
        if (!mapped) return "Static TLS template is not included in a loadable segment";
    }
    return NULL;
}
