# Fork notes

This fork of [LiveContainer/LiveExec32](https://github.com/LiveContainer/LiveExec32)
exists to get one 32-bit iOS app running: **Kids Paint**
(`com.phyzios.PhyziosKidsPaint`, armv7, built against the iOS 3.2 era SDK).

Everything here started as a crash on that app and ended as a gap in the
guest shims that other 32-bit apps are likely to hit too. Upstream's README
is unchanged; this file only covers what the fork adds.

I'm a native Japanese speaker and these notes were written with Claude Code,
so please forgive any awkward English.

## Verified on

| | |
|---|---|
| Device | iPad (9th generation) |
| OS | iPadOS 26.6 |
| Host | LiveContainer, JIT enabled |
| Guest app | Kids Paint, armv7 slice |

The app launches, draws, and saves. Ad and analytics traffic does not work;
see the CFNetwork entry below.

## What this fork changes

### CoreGraphics: five missing `Retain` functions

`dd2c54b`

`CGImageRetain` was missing from the guest CoreGraphics shim, so the app
aborted at first call with `Symbol not found: _CGImageRetain`. Four more
`Retain` functions had the same hole — each had its `Release` counterpart
implemented but no `Retain`:

`CGColorRetain`, `CGColorSpaceRetain`, `CGContextRetain`, `CGGradientRetain`,
`CGImageRetain`

Each forwards through `CFRetain`, matching the existing `CGFontRetain` and
`CGPathRetain`. See [`GuestFrameworks/CoreGraphics/CoreGraphics.m`](GuestFrameworks/CoreGraphics/CoreGraphics.m).

### CoreGraphics: `CGBitmapContextGetWidth` / `CGBitmapContextGetHeight`

`524a3f1`

The shim had `CGBitmapContextGetBytesPerRow` and `CGBitmapContextGetData`
but not the two dimension getters. Both are real implementations forwarded
over the CoreGraphics opcode bridge (opcodes 115 and 116), not stubs: a paint
app asking its bitmap context for its own size needs a true answer.

The host side calls the native getters directly rather than consulting the
guest bitmap backing, because `CGBitmapContextCreate` pads only
`bytesPerRow`; width and height reach the host context unchanged.

### CFNetwork: `CFStreamCreatePairWithSocketToCFHost` (stub)

`524a3f1`

Called from an `NSTimer` every few seconds, from Reachability-style code that
pairs `SCNetworkReachability*` with `CFHostCreateWithName`. It is a **stub**:
both out parameters are set to `NULL`, which is how CoreFoundation reports
that the pair could not be opened, so callers take their connection-failed
path. The guest CFStream shims tolerate `NULL`, so callers that skip the
check do not crash either.

This means ad and analytics requests that go through this path never connect.
That was acceptable here — the app is playable without them, and the calls
happen even in airplane mode. A real implementation is maybe 50 lines
(the `CFStreamCreatePairWithSocketToHost` opcode already does the same job
for a hostname), but it would not make those requests succeed offline.

### Generator: out-qualified object pointers were silently dropped

`9cebdb0` — the one worth reading about.

The app crashed with:

```
+[NSPropertyListSerialization propertyListFromData:mutabilityOption:format:errorDescription:]:
unrecognized selector sent to instance 0x10127c6c
```

The selector was already declared in `Generator/templates/generated.plist`,
so nothing was missing from the signature table. The shim generator was
dropping it while emitting the code.

**The bug.** An `id *` out parameter — every `NSError **`, and every
`errorDescription:` — is spelled by the runtime either bare (`^@`) or
qualified with the `out` modifier (`o^@`). `MethodParameter -declaration`,
`-parameterToBePassed` and `-postCall` dispatched on the *raw* first byte of
the encoding. For `o^@` that byte is `o`, so none of the pointer cases
matched and all three fell through to their `/* unhandled type */` fallback.

**Why it reached run time.** `MethodBuilder` wraps any method whose generated
text contains `unhandled type` in `#if 0`:

```objc
if([self.description containsString:@"unhandled type"]) {
    [self.lines insertObject:@"#if 0 // FIXME: has unhandled types" atIndex:0];
    [self.lines addObject:@"#endif"];
}
```

The `@implementation` survives, so the file still compiles and the build
still succeeds. The only trace is a `-Wincomplete-implementation` warning
among thousands of lines of build output. The method is simply absent at run
time, and the guest aborts the first time that selector is sent — which for
a deprecated API can be minutes into a session, or never, depending on what
the user does.

**The fix.** Add an `objectOutPointerSignature` check ahead of the three raw
switches. It emits exactly the code the bare spelling already produced, so
`^@` is untouched; only `o^@` and `o^#` change status. This mirrors the
design already used next to it: the scalar-pointer path unqualifies its
encoding and reads `o`/`r`/`n` to pick the copy direction, and the opaque-CF
and known-struct helpers unqualify before matching.

`r^@` and `n^@` stay excluded on purpose — an encoding cannot distinguish a
single-object parameter from a caller-provided object array. `N^@` (inout) is
excluded because the host cell is zeroed rather than seeded with the guest's
incoming object.

**Result.** 25 methods came back, across `NSPropertyListSerialization` (7),
the `-getObjectValue:forString:errorDescription:` formatters (13),
`NSURL -getResourceValue:forKey:error:`, `NSCalendar`, `NSNetService` and
`CNContactFormatter`. The build's unique `-Wincomplete-implementation`
warnings went from 446 to 435; no method regressed.

**Guard rail.** The generator now prints how many methods it disabled:

```
Disabled 1839 methods with unhandled types (wrapped in #if 0).
```

and [`test/generated_disabled_methods.sh`](test/generated_disabled_methods.sh)
ratchets that number against a recorded baseline. It fails when the count
grows, and prints the new value when it shrinks. The point is that the next
encoding to lose its bridge shows up at generation time rather than in a
crash log.

The remaining 1839 are a different problem: `void *` buffers whose length is
not in the type, structures passed by value that are not in the known-struct
table, and out pointers to structures. Those need per-API knowledge, not a
dispatch fix.

## tools/

Two scripts for finding what a guest binary needs before running it. They are
plain Python 3 with no dependencies, and they parse Mach-O directly, so they
work on Windows where `nm` and `otool` are unavailable.

### `tools/macho_imports.py`

Lists a Mach-O image's undefined symbols. Two-level namespace binaries record
a library ordinal per symbol, so each import is reported with the dylib dyld
will resolve it in. It also classifies each import as lazily or non-lazily
bound, which tells you whether a missing symbol aborts at launch or on first
call.

```bash
python tools/macho_imports.py --list-arches "Payload/App.app/App"
python tools/macho_imports.py --list-dylibs "Payload/App.app/App"
python tools/macho_imports.py "Payload/App.app/App"          # undefined symbols
python tools/macho_imports.py --objc "Payload/App.app/App"   # selectors
```

Fat binaries pick the first armv7s or armv7 slice unless `--arch` says
otherwise. `--objc` walks `__objc_selrefs` and `__objc_classrefs`, and reads
`__objc_classlist` / `__objc_catlist` to find what the image implements
itself — which is what separates a selector sent to a framework class from
one the app defines.

### `tools/guest_symbol_gaps.py`

Cross-checks that against the shims in this repository.

```bash
python tools/guest_symbol_gaps.py "Payload/App.app/App"
python tools/guest_symbol_gaps.py "Payload/App.app/App" --show all
python tools/guest_symbol_gaps.py "Payload/App.app/App" --selectors
```

Imports resolved in `/usr/lib/*` are reported as out of scope: `pack-ramdisk.sh`
copies those from the genuine iOS image and only replaces
`/System/Library/Frameworks/*`. Everything else is matched against the
hand-written shims, including macro-generated definitions
(`LC32_OPENAL_VOID2(alGenBuffers, ...)`), `__asm__` aliases and `.global`
symbols in inline assembly. Anything it cannot decide textually is reported
separately rather than being called missing.

For Kids Paint this reduced 550 undefined symbols to three real gaps, which
is how the two CoreGraphics getters were found before they had a chance to
crash.

**Known limit.** `--selectors` checks `generated.plist` and the hand-written
shims. A selector declared in `generated.plist` is not proof that the built
shim responds to it — the generator bug above is exactly that case, and this
tool cannot see it. Use the disabled-method ratchet for that.

## Working on this fork

The generated shims are not tracked, so a symbol audit needs them built
first:

```bash
gmake -C GuestMakefile generate-shims
gmake -C GuestMakefile
gmake -C test check-generated-disabled-methods
```

Builds run in GitHub Actions on every push to `main` and `dev`
(`.github/workflows/nightly.yml`) and publish `packages/*.ipa` and
`packages/*.deb` as a nightly release. The workflow does not run the test
suite; the checks under `test/` are run by hand on macOS.
