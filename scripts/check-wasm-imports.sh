#!/usr/bin/env bash
#
# The wasm32 gate: build identikey-log for the browser target and assert that
# the resulting module declares EXACTLY ONE host import, `env.getRandomBytes`.
#
# Why the import section and not just "it compiled": every regression this gate
# exists to catch shows up there first.
#
#   * `bc-components/pqcrypto` → pqcrypto-mldsa (PQClean C) → does not compile
#     at all. Caught by the build.
#   * `bc-shamir` force-enabling `bc-crypto/secp256k1` → secp256k1-sys (C) →
#     does not compile at all. Caught by the build.
#   * `dcbor`'s chrono default features → `wasmbind` → js-sys + wasm-bindgen →
#     compiles FINE and silently adds seven imports the host never agreed to
#     provide. Caught only here.
#
# The third is the reason this script checks a count rather than an exit code.
#
# Tracks Dreamball-y4t.20. See vendor/DUPLICATION.md and
# docs/pq-and-wasm.md.

set -euo pipefail

cd "$(dirname "$0")/.."

TARGET=wasm32-unknown-unknown
PROFILE="${1:-release}"

case "$PROFILE" in
release) CARGO_FLAGS=(--release) ;;
debug) CARGO_FLAGS=() ;;
*)
    echo "usage: $0 [release|debug]" >&2
    exit 2
    ;;
esac

echo "==> cargo build -p identikey-log --target $TARGET ($PROFILE)"
cargo build -p identikey-log --target "$TARGET" "${CARGO_FLAGS[@]}"

WASM="target/$TARGET/$PROFILE/identikey_log.wasm"
if [[ ! -f "$WASM" ]]; then
    echo "FAIL: expected a cdylib at $WASM." >&2
    echo "      Check that [lib] crate-type still includes \"cdylib\"." >&2
    exit 1
fi

echo "==> import section of $WASM"
if command -v wasm-dis >/dev/null 2>&1; then
    IMPORTS="$(wasm-dis "$WASM" | grep '(import' || true)"
elif command -v wasm-objdump >/dev/null 2>&1; then
    IMPORTS="$(wasm-objdump -j Import -x "$WASM" | grep -E '^ - ' || true)"
else
    echo "FAIL: need wasm-dis (binaryen) or wasm-objdump (wabt) on PATH." >&2
    exit 1
fi

if [[ -z "$IMPORTS" ]]; then
    # Zero imports means the linker dead-code-eliminated everything, which
    # would make this gate pass vacuously. That is a failure, not a success.
    echo "FAIL: the module declares NO imports." >&2
    echo "      Expected exactly one (env.getRandomBytes). Zero means nothing" >&2
    echo "      was linked — check src/wasm.rs still exports ik_log_verify." >&2
    exit 1
fi

printf '%s\n' "$IMPORTS"

COUNT="$(printf '%s\n' "$IMPORTS" | wc -l | tr -d ' ')"
if [[ "$COUNT" != "1" ]]; then
    echo "FAIL: expected exactly 1 import, found $COUNT." >&2
    echo "      A new host import means some dependency reintroduced" >&2
    echo "      wasm-bindgen/js-sys. See vendor/dcbor/VENDOR.md." >&2
    exit 1
fi

if ! printf '%s\n' "$IMPORTS" | grep -q 'getRandomBytes'; then
    echo "FAIL: the single import is not env.getRandomBytes." >&2
    exit 1
fi

echo "OK: exactly one import, env.getRandomBytes."
