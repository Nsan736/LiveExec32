#!/bin/sh
set -eu

# A generated method whose parameter types have no bridge is wrapped in
# `#if 0` by the shim generator. The class still compiles, so nothing fails
# the build: the selector simply goes missing and the guest aborts with an
# unrecognized selector the first time it is sent. Ratchet the count down.

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd)
GENERATED_DIR=${LC32_GENERATED_DIR:-"$REPO_ROOT/GuestFrameworks/.generated"}
BASELINE_FILE="$SCRIPT_DIR/generated_disabled_methods.txt"

if [ ! -d "$GENERATED_DIR" ]; then
    echo "Generated shims not found: $GENERATED_DIR" >&2
    echo "Run: gmake -C GuestMakefile generate-shims" >&2
    exit 1
fi

if [ ! -f "$BASELINE_FILE" ]; then
    echo "Baseline file not found: $BASELINE_FILE" >&2
    exit 1
fi

baseline=$(sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "$BASELINE_FILE" \
    | head -n 1 | tr -d '[:space:]')
case "$baseline" in
    ''|*[!0-9]*)
        echo "Baseline is not a number: '$baseline'" >&2
        exit 1
        ;;
esac

count=$(find "$GENERATED_DIR" -type f -name '*.m' -exec \
    grep -c '^#if 0 // FIXME: has unhandled types$' {} + \
    | awk -F: '{ total += $NF } END { print total + 0 }')

echo "Disabled generated methods: $count (baseline $baseline)"

if [ "$count" -gt "$baseline" ]; then
    echo "Disabled method count grew by $((count - baseline)); a new type" \
        "encoding lost its bridge." >&2
    echo "Find them with: grep -rl '#if 0 // FIXME' $GENERATED_DIR" >&2
    exit 1
fi

if [ "$count" -lt "$baseline" ]; then
    echo "Baseline can be lowered to $count in $BASELINE_FILE"
fi

echo "Generated disabled-method audit: PASS"
