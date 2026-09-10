#!/usr/bin/env python3
"""List the undefined (imported) symbols and ObjC metadata of a Mach-O image.

Written for Windows hosts, where nm and otool are unavailable: the fat
header, load commands, LC_SYMTAB and LC_DYSYMTAB are parsed directly.
Two-level namespace binaries record a library ordinal per undefined symbol,
so each import is reported with the dylib dyld will look it up in.

The ObjC side walks __objc_selrefs, __objc_classrefs and the image's own
__objc_classlist / __objc_catlist, which is what tells apart a selector the
image sends to a framework class from one it implements itself.

Written with Claude Code.
"""

import argparse
import json
import struct
import sys

FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
MH_MAGIC = 0xFEEDFACE
MH_CIGAM = 0xCEFAEDFE
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE

LC_SEGMENT = 0x01
LC_SYMTAB = 0x02
LC_DYSYMTAB = 0x0B
LC_SEGMENT_64 = 0x19

SECTION_TYPE = 0x000000FF
S_ZEROFILL = 0x01
S_GB_ZEROFILL = 0x0C
S_NON_LAZY_SYMBOL_POINTERS = 0x06
S_LAZY_SYMBOL_POINTERS = 0x07
S_SYMBOL_STUBS = 0x08
INDIRECT_SYMBOL_LOCAL = 0x80000000
INDIRECT_SYMBOL_ABS = 0x40000000
LC_LOAD_DYLIB = 0x0C
LC_ID_DYLIB = 0x0D
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_REEXPORT_DYLIB = 0x8000001F
LC_LOAD_UPWARD_DYLIB = 0x80000023

DYLIB_COMMANDS = (
    LC_LOAD_DYLIB,
    LC_LOAD_WEAK_DYLIB,
    LC_REEXPORT_DYLIB,
    LC_LOAD_UPWARD_DYLIB,
)

CPU_TYPE_ARM = 12
CPU_TYPE_ARM64 = 0x0100000C
CPU_TYPE_X86 = 7
CPU_TYPE_X86_64 = 0x01000007

ARM_SUBTYPES = {5: "armv4t", 6: "armv6", 9: "armv7", 11: "armv7s", 12: "armv7k"}

N_STAB = 0xE0
N_TYPE = 0x0E
N_UNDF = 0x00
N_PBUD = 0x0C
N_EXT = 0x01
N_WEAK_REF = 0x0040

SELF_LIBRARY_ORDINAL = 0
DYNAMIC_LOOKUP_ORDINAL = 0xFE
EXECUTABLE_ORDINAL = 0xFF


def arch_name(cputype, cpusubtype):
    subtype = cpusubtype & 0x00FFFFFF
    if cputype == CPU_TYPE_ARM:
        return ARM_SUBTYPES.get(subtype, "arm(sub %d)" % subtype)
    if cputype == CPU_TYPE_ARM64:
        return "arm64e" if subtype == 2 else "arm64"
    if cputype == CPU_TYPE_X86:
        return "i386"
    if cputype == CPU_TYPE_X86_64:
        return "x86_64"
    return "cpu%d/%d" % (cputype, subtype)


def list_slices(data):
    """Return [(offset, size, arch, cputype, cpusubtype)] for every slice."""
    if len(data) < 8:
        raise ValueError("file is too small to be Mach-O")
    magic = struct.unpack(">I", data[:4])[0]
    if magic in (FAT_MAGIC, FAT_CIGAM):
        # The fat header is always stored big-endian.
        count = struct.unpack(">I", data[4:8])[0]
        slices = []
        for index in range(count):
            base = 8 + index * 20
            cputype, cpusubtype, offset, size, _align = struct.unpack(
                ">IIIII", data[base:base + 20])
            slices.append((offset, size, arch_name(cputype, cpusubtype),
                cputype, cpusubtype))
        return slices

    header = parse_header(data, 0)
    return [(0, len(data), arch_name(header["cputype"], header["cpusubtype"]),
        header["cputype"], header["cpusubtype"])]


def parse_header(data, offset):
    magic = struct.unpack("<I", data[offset:offset + 4])[0]
    if magic == MH_MAGIC:
        endian, is64 = "<", False
    elif magic == MH_CIGAM:
        endian, is64 = ">", False
    elif magic == MH_MAGIC_64:
        endian, is64 = "<", True
    elif magic == MH_CIGAM_64:
        endian, is64 = ">", True
    else:
        raise ValueError("not a Mach-O slice at offset 0x%x (magic %08x)"
            % (offset, magic))

    cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = struct.unpack(
        endian + "IIIIII", data[offset + 4:offset + 28])
    return {
        "endian": endian,
        "is64": is64,
        "cputype": cputype,
        "cpusubtype": cpusubtype,
        "filetype": filetype,
        "ncmds": ncmds,
        "sizeofcmds": sizeofcmds,
        "flags": flags,
        "commands_offset": offset + (32 if is64 else 28),
    }


def cstring(data, offset):
    end = data.find(b"\x00", offset)
    if end < 0:
        end = len(data)
    return data[offset:end].decode("utf-8", "replace")


def parse_segment_pointer_sections(data, command_offset, endian, cmd):
    """Return the indirect-pointer sections of one segment command.

    Each entry is (section type, reserved1, entry count): reserved1 is the
    section's first index into the indirect symbol table.
    """
    is64 = cmd == LC_SEGMENT_64
    header_size = 72 if is64 else 56
    section_size = 80 if is64 else 68
    nsects_offset = command_offset + (64 if is64 else 48)
    nsects = struct.unpack(
        endian + "I", data[nsects_offset:nsects_offset + 4])[0]

    sections = []
    for index in range(nsects):
        base = command_offset + header_size + index * section_size
        if is64:
            size = struct.unpack(endian + "Q", data[base + 40:base + 48])[0]
            flags_offset = base + 64
        else:
            size = struct.unpack(endian + "I", data[base + 36:base + 40])[0]
            flags_offset = base + 56
        flags, reserved1, reserved2 = struct.unpack(
            endian + "III", data[flags_offset:flags_offset + 12])
        section_type = flags & SECTION_TYPE
        if section_type not in (S_NON_LAZY_SYMBOL_POINTERS,
                S_LAZY_SYMBOL_POINTERS, S_SYMBOL_STUBS):
            continue
        stride = reserved2 if section_type == S_SYMBOL_STUBS else (
            8 if is64 else 4)
        count = size // stride if stride else 0
        sections.append((section_type, reserved1, count))
    return sections


def indirect_bindings(data, slice_offset, endian, dysymtab, pointer_sections):
    """Map symbol table index -> "lazy" / "non-lazy" via indirect symbols."""
    if not dysymtab or not dysymtab.get("nindirectsyms"):
        return {}
    base = slice_offset + dysymtab["indirectsymoff"]
    total = dysymtab["nindirectsyms"]
    entries = struct.unpack(
        endian + "%dI" % total, data[base:base + total * 4])

    bindings = {}
    for section_type, reserved1, count in pointer_sections:
        kind = ("lazy" if section_type in
            (S_LAZY_SYMBOL_POINTERS, S_SYMBOL_STUBS) else "non-lazy")
        for offset in range(count):
            index = reserved1 + offset
            if index >= total:
                break
            value = entries[index]
            if value & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS):
                continue
            # A symbol reached through a stub is bound lazily even if it also
            # has a non-lazy pointer; keep the stricter (lazy) answer.
            if bindings.get(value) != "lazy":
                bindings[value] = kind
    return bindings


def parse_slice(data, slice_offset, slice_size):
    header = parse_header(data, slice_offset)
    endian = header["endian"]
    cursor = header["commands_offset"]

    symtab = None
    dysymtab = None
    dylibs = []
    pointer_sections = []

    for _ in range(header["ncmds"]):
        cmd, cmdsize = struct.unpack(endian + "II", data[cursor:cursor + 8])
        if cmdsize < 8:
            raise ValueError("invalid load command size %d" % cmdsize)
        if cmd == LC_SYMTAB:
            symtab = struct.unpack(
                endian + "IIII", data[cursor + 8:cursor + 24])
        elif cmd == LC_DYSYMTAB:
            values = struct.unpack(
                endian + "18I", data[cursor + 8:cursor + 80])
            dysymtab = {
                "iundefsym": values[4], "nundefsym": values[5],
                "indirectsymoff": values[12], "nindirectsyms": values[13],
            }
        elif cmd in DYLIB_COMMANDS:
            name_offset = struct.unpack(
                endian + "I", data[cursor + 8:cursor + 12])[0]
            dylibs.append(cstring(data, cursor + name_offset))
        elif cmd in (LC_SEGMENT, LC_SEGMENT_64):
            pointer_sections.extend(
                parse_segment_pointer_sections(data, cursor, endian, cmd))
        cursor += cmdsize

    if symtab is None:
        raise ValueError("slice has no LC_SYMTAB")

    symoff, nsyms, stroff, _strsize = symtab
    entry_size = 16 if header["is64"] else 12
    strings_base = slice_offset + stroff
    symbols_base = slice_offset + symoff

    # Undefined symbols are contiguous when LC_DYSYMTAB is present; scan the
    # whole table otherwise.
    if dysymtab and dysymtab["nundefsym"]:
        first = dysymtab["iundefsym"]
        count = dysymtab["nundefsym"]
    else:
        first, count = 0, nsyms

    bindings = indirect_bindings(
        data, slice_offset, endian, dysymtab, pointer_sections)

    undefined = []
    for index in range(first, min(first + count, nsyms)):
        base = symbols_base + index * entry_size
        n_strx, n_type, _n_sect, n_desc = struct.unpack(
            endian + "IBBH", data[base:base + 8])
        if n_type & N_STAB:
            continue
        if (n_type & N_TYPE) not in (N_UNDF, N_PBUD):
            continue
        name = cstring(data, strings_base + n_strx)
        if not name:
            continue
        ordinal = (n_desc >> 8) & 0xFF
        if ordinal == DYNAMIC_LOOKUP_ORDINAL:
            library = "<dynamic lookup>"
        elif ordinal == EXECUTABLE_ORDINAL:
            library = "<executable>"
        elif ordinal == SELF_LIBRARY_ORDINAL:
            library = "<self>"
        elif 1 <= ordinal <= len(dylibs):
            library = dylibs[ordinal - 1]
        else:
            library = "<ordinal %d>" % ordinal
        undefined.append({
            "name": name,
            "library": library,
            "weak": bool(n_desc & N_WEAK_REF),
            "external": bool(n_type & N_EXT),
            "binding": bindings.get(index, "unknown"),
        })

    return {
        "arch": arch_name(header["cputype"], header["cpusubtype"]),
        "filetype": header["filetype"],
        "dylibs": dylibs,
        "undefined": undefined,
    }


class AddressSpace:
    """Maps virtual addresses in one slice back to file offsets."""

    def __init__(self, data, slice_offset):
        self.data = data
        self.slice_offset = slice_offset
        self.sections = []
        self.by_name = {}

    def add_section(self, segment, section, addr, size, offset, flags):
        entry = (addr, size, offset, segment, section, flags)
        self.sections.append(entry)
        # Section names are truncated to 16 bytes and the linker appends the
        # segment for some (__objc_classlist__DATA), so index on the prefix.
        self.by_name.setdefault(section, entry)

    def offset_for(self, address):
        for addr, size, offset, _segment, _section, flags in self.sections:
            if addr <= address < addr + size:
                if (flags & SECTION_TYPE) in (S_ZEROFILL, S_GB_ZEROFILL):
                    return None
                return self.slice_offset + offset + (address - addr)
        return None

    def section(self, prefix):
        for entry in self.sections:
            if entry[4].startswith(prefix):
                return entry
        return None

    def string_at(self, address):
        offset = self.offset_for(address)
        return None if offset is None else cstring(self.data, offset)

    def pointers(self, prefix, endian, pointer_size):
        entry = self.section(prefix)
        if entry is None:
            return []
        _addr, size, offset, _segment, _section, _flags = entry
        base = self.slice_offset + offset
        count = size // pointer_size
        code = "Q" if pointer_size == 8 else "I"
        return list(struct.unpack(
            endian + "%d%s" % (count, code),
            self.data[base:base + count * pointer_size]))


def read_address_space(data, slice_offset, header):
    endian = header["endian"]
    space = AddressSpace(data, slice_offset)
    cursor = header["commands_offset"]
    for _ in range(header["ncmds"]):
        cmd, cmdsize = struct.unpack(endian + "II", data[cursor:cursor + 8])
        if cmd in (LC_SEGMENT, LC_SEGMENT_64):
            is64 = cmd == LC_SEGMENT_64
            segment = cstring(data, cursor + 8)
            header_size = 72 if is64 else 56
            section_size = 80 if is64 else 68
            nsects_offset = cursor + (64 if is64 else 48)
            nsects = struct.unpack(
                endian + "I", data[nsects_offset:nsects_offset + 4])[0]
            for index in range(nsects):
                base = cursor + header_size + index * section_size
                section = cstring(data, base)
                if is64:
                    addr, size = struct.unpack(
                        endian + "QQ", data[base + 32:base + 48])
                    offset = struct.unpack(
                        endian + "I", data[base + 48:base + 52])[0]
                    flags = struct.unpack(
                        endian + "I", data[base + 64:base + 68])[0]
                else:
                    addr, size, offset = struct.unpack(
                        endian + "III", data[base + 32:base + 44])
                    flags = struct.unpack(
                        endian + "I", data[base + 56:base + 60])[0]
                space.add_section(segment, section, addr, size, offset, flags)
        cursor += cmdsize
    return space


def read_method_list(space, endian, pointer_size, address):
    """Return the selector names of one method_list_t."""
    if not address:
        return []
    offset = space.offset_for(address)
    if offset is None:
        return []
    entsize, count = struct.unpack(
        endian + "II", space.data[offset:offset + 8])
    entsize &= 0xFFFF
    if not entsize or count > 0x10000:
        return []
    code = "Q" if pointer_size == 8 else "I"
    names = []
    for index in range(count):
        entry = offset + 8 + index * entsize
        name_pointer = struct.unpack(
            endian + code, space.data[entry:entry + pointer_size])[0]
        name = space.string_at(name_pointer)
        if name:
            names.append(name)
    return names


def read_own_classes(space, endian, pointer_size):
    """Walk __objc_classlist and __objc_catlist for locally defined methods."""
    code = "Q" if pointer_size == 8 else "I"

    def read_pointer(offset):
        return struct.unpack(
            endian + code, space.data[offset:offset + pointer_size])[0]

    def read_class(address, want_metaclass):
        offset = space.offset_for(address)
        if offset is None:
            return None, []
        isa = read_pointer(offset)
        data_field = read_pointer(offset + 4 * pointer_size)
        ro_offset = space.offset_for(data_field & ~3)
        if ro_offset is None:
            return None, []
        name_field = 4 * 4 + pointer_size if pointer_size == 8 else 16
        name = space.string_at(read_pointer(ro_offset + name_field))
        methods = read_method_list(space, endian, pointer_size,
            read_pointer(ro_offset + name_field + pointer_size))
        if want_metaclass and isa:
            _meta_name, meta_methods = read_class(isa, False)
            return name, (methods, meta_methods)
        return name, methods

    classes = []
    for address in space.pointers("__objc_classlist", endian, pointer_size):
        if not address:
            continue
        name, methods = read_class(address, True)
        if name is None:
            continue
        instance_methods, class_methods = methods if isinstance(
            methods, tuple) else (methods, [])
        classes.append({
            "name": name,
            "instance_methods": instance_methods,
            "class_methods": class_methods,
        })

    categories = []
    for address in space.pointers("__objc_catlist", endian, pointer_size):
        if not address:
            continue
        offset = space.offset_for(address)
        if offset is None:
            continue
        name = space.string_at(read_pointer(offset))
        instance_methods = read_method_list(space, endian, pointer_size,
            read_pointer(offset + 2 * pointer_size))
        class_methods = read_method_list(space, endian, pointer_size,
            read_pointer(offset + 3 * pointer_size))
        categories.append({
            "name": name,
            "instance_methods": instance_methods,
            "class_methods": class_methods,
        })
    return classes, categories


def objc_metadata(data, slice_offset, slice_size):
    """Selectors and classes the slice references, plus what it defines."""
    header = parse_header(data, slice_offset)
    endian = header["endian"]
    pointer_size = 8 if header["is64"] else 4
    space = read_address_space(data, slice_offset, header)

    selrefs = []
    for address in space.pointers("__objc_selrefs", endian, pointer_size):
        name = space.string_at(address)
        if name:
            selrefs.append(name)

    # A classref to an external class is left at zero on disk and resolved
    # through the _OBJC_CLASS_$_ undefined symbol, which the symbol table
    # already reports; only locally defined classes can be named here.
    classrefs = []
    for address in space.pointers("__objc_classrefs", endian, pointer_size):
        if not address:
            classrefs.append(None)
            continue
        offset = space.offset_for(address)
        if offset is None:
            classrefs.append(None)
            continue
        data_field = struct.unpack(endian + ("Q" if pointer_size == 8 else "I"),
            data[offset + 4 * pointer_size:
                 offset + 5 * pointer_size])[0]
        ro_offset = space.offset_for(data_field & ~3)
        if ro_offset is None:
            classrefs.append(None)
            continue
        name_field = 4 * 4 + pointer_size if pointer_size == 8 else 16
        name_pointer = struct.unpack(
            endian + ("Q" if pointer_size == 8 else "I"),
            data[ro_offset + name_field:
                 ro_offset + name_field + pointer_size])[0]
        classrefs.append(space.string_at(name_pointer))

    classes, categories = read_own_classes(space, endian, pointer_size)
    own_selectors = set()
    for entry in classes + categories:
        own_selectors.update(entry["instance_methods"])
        own_selectors.update(entry["class_methods"])

    return {
        "arch": arch_name(header["cputype"], header["cpusubtype"]),
        "selrefs": sorted(set(selrefs)),
        "classrefs": sorted({name for name in classrefs if name}),
        "own_classes": classes,
        "own_categories": categories,
        "own_selectors": sorted(own_selectors),
    }


def select_slice(slices, wanted):
    if wanted:
        for entry in slices:
            if entry[2] == wanted:
                return entry
        return None
    for preferred in ("armv7s", "armv7"):
        for entry in slices:
            if entry[2] == preferred:
                return entry
    return slices[0] if len(slices) == 1 else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("--arch", help="slice to read (default: the first "
        "armv7s or armv7 slice, else the only slice)")
    parser.add_argument("--list-arches", action="store_true")
    parser.add_argument("--list-dylibs", action="store_true")
    parser.add_argument("--objc", action="store_true",
        help="report __objc_selrefs / __objc_classrefs and the image's own "
             "classes instead of the undefined symbols")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    with open(args.binary, "rb") as handle:
        data = handle.read()

    slices = list_slices(data)
    if args.list_arches:
        for offset, size, arch, _cputype, _cpusubtype in slices:
            print("%-8s offset=0x%08x size=%d" % (arch, offset, size))
        return 0

    chosen = select_slice(slices, args.arch)
    if chosen is None:
        print("no matching slice; available: %s" % ", ".join(
            entry[2] for entry in slices), file=sys.stderr)
        return 1

    if args.objc:
        metadata = objc_metadata(data, chosen[0], chosen[1])
        if args.json:
            json.dump(metadata, sys.stdout, indent=2, sort_keys=True)
            sys.stdout.write("\n")
            return 0
        print("# arch: %s" % metadata["arch"])
        print("# selrefs: %d, local classrefs: %d, own classes: %d, "
              "own categories: %d" % (
            len(metadata["selrefs"]), len(metadata["classrefs"]),
            len(metadata["own_classes"]), len(metadata["own_categories"])))
        for name in metadata["selrefs"]:
            print(name)
        return 0

    result = parse_slice(data, chosen[0], chosen[1])
    if args.list_dylibs:
        for name in result["dylibs"]:
            print(name)
        return 0
    if args.json:
        json.dump(result, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return 0

    print("# arch: %s" % result["arch"])
    print("# undefined symbols: %d" % len(result["undefined"]))
    for entry in sorted(result["undefined"], key=lambda item: item["name"]):
        print("%s\t%s%s" % (entry["name"], entry["library"],
            "\t(weak)" if entry["weak"] else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
