# Post-quantum signatures and the browser target

Why `identikey-log` has a `pqcrypto` cargo feature that is **off by default**,
why there is a `fips204` seam that looks redundant next to it, and what a
browser build can and cannot do with an ML-DSA signature.

Tracks `Dreamball-y4t.20`. Prior decisions: `Dreamball-y4t.2` (which PQ crate),
`Dreamball-y4t.13` (the vendored forks), `Dreamball-idq`, `Dreamball-n8r`,
`Dreamball-69h`.

## The constraint

`identikey-log` is not a server-only crate. World-Tree is local-first
multiplayer **in the browser**, and the op log is precisely the component that
has to run there: a peer that cannot verify an op it received is not a peer.
So `wasm32-unknown-unknown` is a first-class target for this crate, not a
nice-to-have.

Three separate things in the Gordian Envelope dependency graph break that
target. None of them is transient; all three are properties of adopting
Gordian Envelope today, and any other crate that adopts it will meet all three.

### 1. `pqcrypto-mldsa` is C and cannot be built for the browser

`bc-components`' `pqcrypto` feature — **on by default**, and pulled in
transitively by `bc-envelope`'s defaults — depends on `pqcrypto-mldsa`, a
binding to PQClean's C implementation. rustpq's own `WASM.md` states these
routines need a hosted stdlib. Reproduced here directly:

```
warning: pqcrypto-internals@0.2.11: cfiles/fips202.c:10:10: fatal error: 'stdlib.h' file not found
warning: pqcrypto-internals@0.2.11: cfiles/aes.c:30:10: fatal error: 'string.h' file not found
warning: pqcrypto-internals@0.2.11: error: unable to create target: 'No available targets are compatible with triple "wasm32-unknown-unknown"'
```

This is not a build-flag problem. WASI would work; the browser target will not.

### 2. `secp256k1-sys` is reachable through `bc-shamir`

`bc-shamir` declares `bc-crypto` without `default-features = false`, which
force-enables `bc-crypto/secp256k1` for the entire graph. `sskr` depends on
`bc-shamir` unconditionally and `bc-components` depends on `sskr`
unconditionally, so no amount of `default-features = false` downstream avoids
it. Fixed by a vendored one-line fork — `vendor/bc-shamir/`,
[BlockchainCommons/bc-shamir-rust#4](https://github.com/BlockchainCommons/bc-shamir-rust/issues/4).

### 3. Two `getrandom` majors, and the obvious fix is wrong

`getrandom 0.3` arrives via `bc-rand`; `getrandom 0.2` arrives via
`chacha20poly1305`'s default features. `getrandom 0.2` hard-`compile_error!`s
on this target unless `js` or `custom` is enabled — and `js` would re-import
`wasm-bindgen`, undoing the `vendor/dcbor` patch and its seven-import
regression. Both majors are therefore routed to one host function in
`crates/identikey-log/src/wasm.rs`.

`dcbor`'s own defect is the quiet one: `chrono` with default features enables
`wasmbind`, which **compiles fine** and silently adds js-sys/wasm-bindgen
imports. Fixed by `vendor/dcbor/`,
[BlockchainCommons/bc-dcbor-rust#6](https://github.com/BlockchainCommons/bc-dcbor-rust/issues/6).

## The shape of the fix

| | default (and wasm) | `--features pqcrypto` (native only) |
|---|---|---|
| Ed25519 sign / verify | yes | yes |
| ML-DSA-87 **verify** | yes — `fips204`, pure Rust | yes — the same `fips204` seam |
| ML-DSA key generation / signing | no | yes |
| **Parse** a `#6.40105` ML-DSA signature | **no** | yes |
| Builds for `wasm32-unknown-unknown` | yes | no, and cannot be made to |

Note the third row: PQ verification is **not** what the feature gates. The
maths is always compiled, because `fips204` is pure Rust and costs roughly
14 KB raw / 6.7 KB gzipped on wasm (measured, `Dreamball-y4t.2`). What the
feature gates is Blockchain Commons' *representation* of a PQ signature.

Both configurations run the same ML-DSA implementation, deliberately:
`verify_signatures` routes `Signature::MLDSA` through `verify_ml_dsa_87` even
when `pqcrypto` is on, rather than calling `SigningPublicKey::verify`. A
divergence between the native and browser verifiers is then impossible by
construction instead of by discipline — and the
`a_pq_signature_with_no_pq_key_is_rejected_not_ignored` test becomes a live
cross-implementation KAT: signed by PQClean C, verified by pure Rust, on every
native test run.

`verify_ml_dsa_87` uses FIPS 204 **pure** mode with the empty context string,
`verify(msg, sig, &[])`, i.e. `M' = 0x00 || 0x00 || M`. Never the `*_internal`
entry points: they skip the domain separator and fail this project's golden
vectors.

## The cost, stated plainly: this is an interop split, not a missing feature

**A default/wasm build cannot decode a PQ-signed op at all.** Not "decodes it
and declines to verify" — fails at `from_envelope` with
`LogError::PqUnavailable`.

The reason is that `bc-components` gates the *enum variant*:

```rust
#[cfg(feature = "pqcrypto")]
MLDSA(MLDSASignature),
```

and its CBOR decoder gates the arm that recognises tag `40105`. Without the
feature there is no value of type `Signature` that can hold an ML-DSA
signature, so `Signature::try_from(cbor)` returns `Err("Invalid signature
format")` — the same error it gives for garbage. `identikey-log` distinguishes
the two by checking the tag structurally before reporting, which is why
`PqUnavailable` exists as its own named error rather than being folded into
`InvalidValue`.

The practical consequence: **if any actor in a deployment signs ops with
ML-DSA, browser peers cannot read those ops.** Not "cannot trust them" —
cannot parse them. That is a network-partitioning property, and it means the
choice of whether to emit PQ signatures is a deployment-wide decision, not a
per-signer one.

Today this is theoretical for this crate: `Author` is Ed25519-only and nothing
in the stack emits an ML-DSA signature. The gate is worth keeping in view
before that changes.

### If the split needs closing

It can be, and the seam is already the right shape. `identikey-log` would stop
storing `Vec<bc_components::Signature>` and store its own enum — the
bc-components `Signature` for classical schemes, plus a raw
`{ level, bytes }` variant parsed directly from the `#6.40105` tagged CBOR
(which is just `[level, bstr]`, and needs no PQ code to read). Verification
would then go through `verify_ml_dsa_87`, which already works everywhere.
That closes the split completely and removes the need for
`bc-components/pqcrypto` in this crate at all.

It was not done here because it changes a public type and the codec's decode
path, which is a design decision rather than a regression fix. Filed as debt
rather than performed silently.

## Generalisation — this is permanent, not an annoyance

Any Gordian-based crate targeting `wasm32-unknown-unknown` needs all three of:

1. both vendored patches (`vendor/bc-shamir`, `vendor/dcbor`) via
   `[patch.crates-io]` at the **workspace root**;
2. both `getrandom` majors routed to one custom backend, `custom` and never
   `js`;
3. `pqcrypto` off.

Rediscovering that per crate is the failure mode this document exists to
prevent — and the `wasm32` CI job in `.github/workflows/ci.yml` is what stops
it being rediscovered by a user instead. That job asserts the module's import
section is exactly `env.getRandomBytes`, because the `dcbor`/`wasmbind` defect
is invisible to a build that merely succeeds.
