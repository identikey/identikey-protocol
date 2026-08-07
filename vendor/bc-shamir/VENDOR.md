# Vendored fork — `bc-shamir` 0.13.0 (wasm32 buildability patch)

Tracks `Dreamball-idq`. Prerequisite for `Dreamball-y4t.4` (the Rust port).

## Pin

- Upstream: <https://github.com/BlockchainCommons/bc-shamir-rust>
- Version / tag: `0.13.0` — commit `fcf8deb2b0f51566635a7de89ae6d8d6628921c7`
- Source of truth for this copy: the published `bc-shamir 0.13.0` crate
  tarball, as unpacked by cargo into the local registry.
- Copied on: 2026-08-07
- Upstream `master` was checked on the same date and is **identical** to the
  0.13.0 release for the file we patch. `0.13.0` is the newest published
  version (crates.io, 2026-08-07), so **there is no upgrade that avoids this
  fork.**

## The defect

`bc-shamir` declares its `bc-crypto` dependency without `default-features =
false`:

```toml
bc-crypto = "^0.14.0"
```

`bc-crypto`'s default feature set is `["secp256k1", "ed25519"]`, so this
force-enables `bc-crypto/secp256k1` → `secp256k1` → `secp256k1-sys`, a C
library that does not build for `wasm32-unknown-unknown`.

This is not something a downstream consumer can feature-flag around:
`bc-components` depends on `sskr` **unconditionally**, and `sskr` depends on
`bc-shamir` unconditionally. Cargo feature unification then turns on
`bc-crypto/secp256k1` for the whole graph no matter how many
`default-features = false` declarations the consumer writes.

Verified with `cargo tree -e features -i secp256k1-sys --target
wasm32-unknown-unknown` from a clean scratch crate depending only on
`bc-envelope` + `bc-components` with `default-features = false`:

```
secp256k1-sys → secp256k1 → bc-crypto feature "default"
                            └── bc-shamir → sskr → bc-components → bc-envelope
```

## The patch

One line in `Cargo.toml`:

```diff
 [dependencies]
 bc-rand = "^0.5.0"
-bc-crypto = "^0.14.0"
+bc-crypto = { version = "^0.14.0", default-features = false }
```

`bc-shamir` uses exactly three items from `bc-crypto` — `hash::hmac_sha256`,
`memzero`, `memzero_vec_vec_u8` (`src/shamir.rs`, `src/hazmat.rs`,
`src/interpolate.rs`) — and **none of them are behind a feature gate**. So no
replacement feature list is needed; the dependency is correct with no features
at all. That is why the fix is safe and strictly a bug fix, not a behaviour
change.

Nothing else in this directory differs from upstream, with two mechanical
exceptions applied to every vendored crate here:

- `Cargo.toml` is upstream's hand-authored `Cargo.toml.orig` (cargo's
  normalised `Cargo.toml` from the tarball was discarded) so that the diff
  above is a real, PR-ready diff against the upstream repository.
- `.cargo_vcs_info.json` was removed.

## Ready-to-paste `[patch.crates-io]`

The Rust workspace does not exist yet — `Dreamball-y4t.4` creates it. When it
does, paste this into the **workspace root** `Cargo.toml`:

```toml
[patch.crates-io]
bc-shamir = { path = "vendor/bc-shamir" }
dcbor     = { path = "vendor/dcbor" }
```

(Both patches are needed together; see `vendor/dcbor/VENDOR.md` for the other.)

`[patch.crates-io]` is only honoured from the workspace root, and the path is
relative to that root — adjust if the workspace is not rooted at the repo root.

## Proof

A scratch `cdylib` depending on

```toml
bc-envelope   = { version = "0.43.0", default-features = false, features = ["signature", "ed25519"] }
bc-components = { version = "0.31.1", default-features = false, features = ["ed25519"] }
```

fails to build for `wasm32-unknown-unknown` against stock crates and builds
cleanly with both patches applied. See `vendor/dcbor/VENDOR.md` § Proof for the
full recipe, the getrandom wiring, and the measured import section.

## Supply-chain note

Running on a patched dependency is a real cost: we no longer get upstream's
published-artifact guarantee for this crate, and a `cargo update` will not move
us off it. Mitigations:

- The delta is **one line of `Cargo.toml`**. No Rust source is modified, so the
  compiled behaviour of `bc-shamir` is unchanged except that a feature we never
  call is no longer enabled.
- The pin above records the exact upstream commit; `diff -ru` against a fresh
  `cargo vendor` of 0.13.0 should show only `Cargo.toml`.
- `UPSTREAM-ISSUE.md` in this directory is a drafted, unfiled bug report. Once
  upstream ships the fix in a release, delete this directory and the
  corresponding `[patch.crates-io]` line.

## Refresh procedure

1. Check whether a newer `bc-shamir` fixes it:
   `cargo add bc-shamir@<new> --dry-run` then
   `cargo tree -e features -i secp256k1-sys --target wasm32-unknown-unknown`.
   If `secp256k1-sys` is absent, **delete this fork** and drop the patch line.
2. Otherwise: re-unpack the new version, re-apply the one-line diff above,
   update the Pin section, and re-run the proof build.

## License

BSD-2-Clause-Patent, unchanged. `LICENSE.md` is upstream's verbatim.
