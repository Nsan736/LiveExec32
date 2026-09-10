#!/usr/bin/env python3
"""List the undefined (imported) symbols of a Mach-O image.

Written for Windows hosts, where nm and otool are unavailable: the fat
header, load commands, LC_SYMTAB and LC_DYSYMTAB are parsed directly.
Two-level namespace binaries record a library ordinal per undefined symbol,
so each import is reported with the dylib dyld will look it up in.
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
