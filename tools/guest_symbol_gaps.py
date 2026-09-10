#!/usr/bin/env python3
"""Cross-check a guest binary's imports and selectors against the shims.

Reports, per framework, which imported symbols are definitely missing and
which cannot be decided from the sources alone.  Macro-generated definitions
(LC32_CG_FONT_METRIC(GetAscent) and friends) and the Objective-C shims that
only exist after `generate-shims` runs cannot be matched textually, so those
land in the undecidable bucket instead of being reported as missing.

With --selectors it does the same for Objective-C: every selector in
__objc_selrefs that the image does not implement itself is looked up in
Generator/templates/generated.plist and in the hand-written shims.

Usage:
  python tools/guest_symbol_gaps.py <guest binary> [--arch armv7]
  python tools/guest_symbol_gaps.py <guest binary> --selectors

Written with Claude Code.
"""

import argparse
import os
import plistlib
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import macho_imports

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GUEST_ROOT = os.path.join(REPO_ROOT, "GuestFrameworks")
GENERATED_ROOT = os.path.join(GUEST_ROOT, ".generated")
SIGNATURES = os.path.join(REPO_ROOT, "Generator", "templates", "generated.plist")
FRAMEWORK_MAP = os.path.join(
    REPO_ROOT, "Generator", "templates", "generated-framework-map.plist")
OPENGLES_SYMBOLS = os.path.join(
    REPO_ROOT, "Generator", "templates", "opengles-supported-symbols.txt")

# Only /System/Library/Frameworks is served by the guest shims; pack-ramdisk.sh
# excludes those from the extracted ramdisk and copies /usr/lib/* verbatim from
# the genuine iOS image.
FRAMEWORK_PATH = re.compile(
    r"^/System/Library/(?:Private)?Frameworks/([A-Za-z0-9_+]+)\.framework/")

# A definition at file scope: a return type, then the name, then '('.  The
# name must start the call, and the line must not be a call or a declaration.
DEFINITION = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_ \t\*&<>:,\.]*?[\s\*]([A-Za-z_][A-Za-z0-9_]*)\s*\(",
    re.MULTILINE)
GLOBAL_DEFINITION = re.compile(
    r"^(?:const\s+|static\s+|extern\s+|__attribute__\(\([^)]*\)\)\s*)*"
    r"[A-Za-z_][A-Za-z0-9_]*(?:\s*\*)*\s+"
    r"\*?(?:const\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\])?\s*=",
    re.MULTILINE)
IMPLEMENTATION = re.compile(r"^@implementation\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE)
# A file-scope macro invocation that expands to a definition.  The name being
# defined is the first argument (LC32_CG_FONT_METRIC(GetAscent),
# LC32_OPENAL_VOID2(alGenBuffers, ...)) or the second one when the macro takes
# a return type first (LC32_OPENAL_RET1(ALCboolean, alcMakeContextCurrent, ...)).
MACRO_DEFINITION = re.compile(
    r"^([A-Z][A-Z0-9_]*)\(([^)\n]*)\)", re.MULTILINE)
PLAIN_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# An explicit assembler name: CFBooleanRef LC32CFBooleanTrue __asm__("_kCF...").
ASM_ALIAS = re.compile(r"__asm__\s*\(\s*\"_?([A-Za-z_][A-Za-z0-9_$]*)\"\s*\)")
# A symbol exported from inline or standalone assembly.
ASM_GLOBAL = re.compile(
    r"\.globa?l\s+_?([A-Za-z_][A-Za-z0-9_$]*)")
TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_$]*")


def read_sources(directory):
    blobs = []
    for root, _dirs, files in os.walk(directory):
        for name in files:
            if not name.endswith((".m", ".mm", ".c", ".h", ".s", ".S")):
                continue
            path = os.path.join(root, name)
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                blobs.append(handle.read())
    return blobs


def index_sources(directory):
    """Return (defined names, every identifier that appears).

    "Defined" covers plain definitions plus the three indirect forms the guest
    shims use: a file-scope macro that expands to a definition, an explicit
    __asm__ symbol name, and a .global in inline assembly.
    """
    defined = set()
    tokens = set()
    for text in read_sources(directory):
        defined.update(DEFINITION.findall(text))
        defined.update(GLOBAL_DEFINITION.findall(text))
        defined.update(IMPLEMENTATION.findall(text))
        defined.update(ASM_ALIAS.findall(text))
        defined.update(ASM_GLOBAL.findall(text))
        for macro, arguments in MACRO_DEFINITION.findall(text):
            for argument in [part.strip()
                    for part in arguments.split(",")[:2]]:
                if not PLAIN_IDENTIFIER.match(argument):
                    continue
                # The argument itself, and the "prefix + argument" spelling
                # (LC32_CG_FONT_METRIC(GetAscent) defines CGFontGetAscent).
                defined.add(argument)
                defined.add(("macro:%s" % macro, argument))
        tokens.update(TOKEN.findall(text))
    return defined, tokens


def macro_suffix_match(name, defined):
    """True when `name` ends with a macro argument recorded by index_sources."""
    for entry in defined:
        if isinstance(entry, tuple) and name.endswith(entry[1]) \
                and len(entry[1]) < len(name):
            return entry[0]
    return None


METHOD_DEFINITION = re.compile(
    r"^([-+])\s*\(([^)]*)\)([^;{]*)\{", re.MULTILINE)
SELECTOR_PART = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*:")
BARE_SELECTOR = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*$")


def selector_from_signature(signature):
    """Rebuild a selector from the text between the return type and body."""
    parts = SELECTOR_PART.findall(signature)
    if parts:
        return "".join(part + ":" for part in parts)
    bare = BARE_SELECTOR.match(signature)
    return bare.group(1) if bare else None


def shim_selectors(directory):
    """Selectors the hand-written shims implement, as (kind, selector)."""
    found = set()
    for text in read_sources(directory):
        for kind, _return_type, signature in METHOD_DEFINITION.findall(text):
            selector = selector_from_signature(signature)
            if selector:
                found.add((kind, selector))
    return found


def generated_selectors():
    """Selectors generated.plist declares, mapped to Framework/Class owners."""
    if not os.path.exists(SIGNATURES):
        return {}
    with open(SIGNATURES, "rb") as handle:
        signatures = plistlib.load(handle)

    owners = {}
    for framework, classes in signatures.items():
        for class_name, methods in classes.items():
            for kind in ("+", "-"):
                for selector in methods.get(kind, {}):
                    owners.setdefault((kind, selector), []).append(
                        "%s/%s" % (framework, class_name))
    return owners


def generated_classes():
    """Class names the shim generator emits, keyed by owning framework."""
    if not os.path.exists(SIGNATURES):
        return {}, set()
    with open(SIGNATURES, "rb") as handle:
        signatures = plistlib.load(handle)

    overrides = {}
    if os.path.exists(FRAMEWORK_MAP):
        with open(FRAMEWORK_MAP, "rb") as handle:
            overrides = plistlib.load(handle)

    per_framework = {}
    every = set()
    for framework, classes in signatures.items():
        for class_name in classes:
            target = overrides.get("%s/%s" % (framework, class_name), framework)
            per_framework.setdefault(target, set()).add(class_name)
            every.add(class_name)
    return per_framework, every


def opengles_symbols():
    if not os.path.exists(OPENGLES_SYMBOLS):
        return set()
    with open(OPENGLES_SYMBOLS, "r", encoding="utf-8") as handle:
        return {line.strip() for line in handle if line.strip()}


def classify(binary, arch):
    with open(binary, "rb") as handle:
        data = handle.read()
    slices = macho_imports.list_slices(data)
    chosen = macho_imports.select_slice(slices, arch)
    if chosen is None:
        raise SystemExit("no matching slice; available: %s" % ", ".join(
            entry[2] for entry in slices))
    image = macho_imports.parse_slice(data, chosen[0], chosen[1])

    shim_dirs = sorted(name for name in os.listdir(GUEST_ROOT)
        if os.path.isdir(os.path.join(GUEST_ROOT, name))
        and not name.startswith("."))

    # Index every shim once: reexports (Foundation -> CoreFoundation) mean a
    # symbol recorded against one framework can legitimately live in another.
    defined_by = {}
    tokens_by = {}
    all_defined = set()
    all_tokens = set()
    for name in shim_dirs:
        defined, tokens = index_sources(os.path.join(GUEST_ROOT, name))
        defined_by[name] = defined
        tokens_by[name] = tokens
        all_defined |= defined
        all_tokens |= tokens

    generated_available = os.path.isdir(GENERATED_ROOT)
    if generated_available:
        generated_defined, generated_tokens = index_sources(GENERATED_ROOT)
        all_defined |= generated_defined
        all_tokens |= generated_tokens
    _per_framework_classes, template_classes = generated_classes()
    gl_symbols = opengles_symbols()

    rows = []
    for entry in image["undefined"]:
        match = FRAMEWORK_PATH.match(entry["library"])
        if not match:
            rows.append((entry, "out-of-scope", "provided by the iOS ramdisk"))
            continue
        framework = match.group(1)
        raw = entry["name"]
        name = raw[1:] if raw.startswith("_") else raw

        kind = "function"
        lookup = name
        if name.startswith("OBJC_CLASS_$_"):
            kind, lookup = "class", name[len("OBJC_CLASS_$_"):]
        elif name.startswith("OBJC_METACLASS_$_"):
            kind, lookup = "class", name[len("OBJC_METACLASS_$_"):]
        elif name.startswith("OBJC_EHTYPE_$_"):
            # The exception typeinfo is emitted alongside the class.
            kind, lookup = "class", name[len("OBJC_EHTYPE_$_"):]
        elif name.startswith("OBJC_IVAR_$_"):
            kind, lookup = "ivar", name[len("OBJC_IVAR_$_"):].split(".")[0]

        if framework not in shim_dirs and framework not in (
                _per_framework_classes or {}):
            rows.append((entry, "undecidable",
                "no GuestFrameworks/%s directory" % framework))
            continue

        if kind == "class":
            if lookup in all_defined:
                rows.append((entry, "implemented", "@implementation in shims"))
            elif lookup in template_classes:
                if generated_available:
                    rows.append((entry, "implemented", "generated shim"))
                else:
                    rows.append((entry, "implemented",
                        "listed in generated.plist (shims not generated "
                        "locally)"))
            else:
                rows.append((entry, "missing", "no class of this name"))
            continue

        if kind == "ivar":
            rows.append((entry, "undecidable",
                "ivar symbol; depends on the generated class layout"))
            continue

        if framework == "OpenGLES" and lookup in gl_symbols:
            rows.append((entry, "implemented",
                "opengles-supported-symbols.txt"))
            continue

        if lookup in all_defined:
            where = [name for name in shim_dirs if lookup in defined_by[name]]
            rows.append((entry, "implemented",
                "defined in %s" % (", ".join(where) or "generated shims")))
            continue

        macro = macro_suffix_match(lookup, all_defined)
        if macro:
            rows.append((entry, "implemented",
                "defined through the %s(...) macro" % macro[len("macro:"):]))
            continue

        if lookup in all_tokens:
            where = [name for name in shim_dirs if lookup in tokens_by[name]]
            rows.append((entry, "undecidable",
                "name appears in %s but no plain definition matched "
                "(macro?)" % (", ".join(where) or "generated shims")))
            continue

        if not generated_available and framework in (
                _per_framework_classes or {}):
            rows.append((entry, "missing",
                "absent from the shims (generated sources not built "
                "locally; C functions are not generated)"))
            continue

        rows.append((entry, "missing", "absent from the shims"))

    return image, rows


def classify_selectors(binary, arch):
    with open(binary, "rb") as handle:
        data = handle.read()
    slices = macho_imports.list_slices(data)
    chosen = macho_imports.select_slice(slices, arch)
    if chosen is None:
        raise SystemExit("no matching slice; available: %s" % ", ".join(
            entry[2] for entry in slices))
    metadata = macho_imports.objc_metadata(data, chosen[0], chosen[1])

    owners = generated_selectors()
    declared = {selector for _kind, selector in owners}

    implemented = set()
    for name in sorted(os.listdir(GUEST_ROOT)):
        directory = os.path.join(GUEST_ROOT, name)
        if os.path.isdir(directory) and not name.startswith("."):
            implemented |= shim_selectors(directory)
    if os.path.isdir(GENERATED_ROOT):
        implemented |= shim_selectors(GENERATED_ROOT)
    implemented_names = {selector for _kind, selector in implemented}

    own = set(metadata["own_selectors"])
    rows = []
    for selector in metadata["selrefs"]:
        if selector in own:
            rows.append((selector, "own", "implemented by the app itself"))
        elif selector in declared:
            classes = sorted({owner for (_kind, name), values in owners.items()
                if name == selector for owner in values})
            rows.append((selector, "declared", ", ".join(classes[:4]) + (
                " (+%d more)" % (len(classes) - 4) if len(classes) > 4 else "")))
        elif selector in implemented_names:
            rows.append((selector, "declared", "hand-written shim"))
        else:
            rows.append((selector, "missing", "not in generated.plist"))
    return metadata, rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("--arch")
    parser.add_argument("--selectors", action="store_true",
        help="check __objc_selrefs against generated.plist instead of the "
             "imported C symbols")
    parser.add_argument("--show", choices=("missing", "undecidable", "all"),
        default="missing")
    args = parser.parse_args()

    if args.selectors:
        metadata, rows = classify_selectors(args.binary, args.arch)
        counts = {}
        for _selector, verdict, _why in rows:
            counts[verdict] = counts.get(verdict, 0) + 1
        print("# arch: %s" % metadata["arch"])
        print("# selrefs: %d (%s)" % (len(rows), ", ".join(
            "%s=%d" % item for item in sorted(counts.items()))))
        print("# the image defines %d classes and %d categories of its own"
            % (len(metadata["own_classes"]), len(metadata["own_categories"])))
        print()
        missing = [row for row in rows if row[1] == "missing"]
        print("== selectors with no shim (%d) ==" % len(missing))
        for selector, _verdict, _why in missing:
            print("  %s" % selector)
        return 0

    image, rows = classify(args.binary, args.arch)

    counts = {}
    for _entry, verdict, _why in rows:
        counts[verdict] = counts.get(verdict, 0) + 1
    print("# arch: %s" % image["arch"])
    print("# imports: %d (%s)" % (len(rows), ", ".join(
        "%s=%d" % item for item in sorted(counts.items()))))
    if not os.path.isdir(GENERATED_ROOT):
        print("# note: GuestFrameworks/.generated is absent; Objective-C "
              "classes were matched against Generator/templates/"
              "generated.plist instead")
    print()

    wanted = ("missing", "undecidable") if args.show == "all" else (args.show,)
    by_framework = {}
    for entry, verdict, why in rows:
        if verdict not in wanted:
            continue
        match = FRAMEWORK_PATH.match(entry["library"])
        framework = match.group(1) if match else "(other)"
        by_framework.setdefault(framework, []).append((entry, verdict, why))

    for framework in sorted(by_framework):
        items = sorted(by_framework[framework],
            key=lambda row: (row[1], row[0]["name"]))
        print("== %s (%d) ==" % (framework, len(items)))
        for entry, verdict, why in items:
            print("  [%s] %s%s\n      %s" % (verdict, entry["name"],
                " (weak)" if entry["weak"] else "", why))
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
