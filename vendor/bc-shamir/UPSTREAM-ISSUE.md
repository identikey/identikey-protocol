# FILED 2026-08-07

**Issue:** <https://github.com/BlockchainCommons/bc-shamir-rust/issues/4>

**Target:** <https://github.com/BlockchainCommons/bc-shamir-rust/issues/new>
**Status:** filed 2026-08-07 with the project owner's authorization.

Everything below the line is the issue body, ready to paste.

---

**Title:** `bc-crypto` dependency lacks `default-features = false`, forcing
`secp256k1` on every consumer and breaking `wasm32-unknown-unknown`

### Summary

`bc-shamir` 0.13.0 declares:

```toml
bc-crypto = "^0.14.0"
```

`bc-crypto`'s default feature set is `["secp256k1", "ed25519"]`, so this
unconditionally enables `bc-crypto/secp256k1` → `secp256k1` →
`secp256k1-sys`. `secp256k1-sys` is a C library and does not build for
`wasm32-unknown-unknown`.

Because `bc-components` depends on `sskr` unconditionally and `sskr` depends on
`bc-shamir` unconditionally, cargo's feature unification propagates this to
**every consumer of `bc-components` or `bc-envelope`**. There is no
downstream workaround: no amount of `default-features = false` on the
consumer's side can turn it off. The published crates simply cannot be built
for the browser.

### Reproduction

```console
$ cargo new --lib repro && cd repro
```

`Cargo.toml`:

```toml
[lib]
crate-type = ["cdylib"]

[dependencies]
bc-envelope   = { version = "0.43.0", default-features = false, features = ["signature", "ed25519"] }
bc-components = { version = "0.31.1", default-features = false, features = ["ed25519"] }
```

```console
$ cargo tree -e features -i secp256k1-sys --target wasm32-unknown-unknown
secp256k1-sys v0.11.0
└── secp256k1 v0.31.1
    ├── secp256k1 feature "alloc"
    │   └── secp256k1 feature "std"
    │       └── secp256k1 feature "default"
    │           └── bc-crypto v0.14.0
    │               ...
    │               ├── bc-crypto feature "default"
    │               │   └── bc-shamir v0.13.0
    │               │       └── bc-shamir feature "default"
    │               │           └── sskr v0.12.0
    │               │               └── sskr feature "default"
    │               │                   └── bc-components v0.31.1
```

Note the consumer never asks for `secp256k1`; the only edge that enables it is
`bc-shamir → bc-crypto feature "default"`.

Building then fails in the `secp256k1-sys` C build (and, en route, in
`getrandom` 0.2, which `secp256k1`'s `rand` support drags in).

### Fix

One line:

```diff
 [dependencies]
 bc-rand = "^0.5.0"
-bc-crypto = "^0.14.0"
+bc-crypto = { version = "^0.14.0", default-features = false }
```

`bc-shamir` uses exactly three items from `bc-crypto`:

- `bc_crypto::hash::hmac_sha256` (`src/shamir.rs`)
- `bc_crypto::memzero` (`src/shamir.rs`, `src/hazmat.rs`, `src/interpolate.rs`)
- `bc_crypto::memzero_vec_vec_u8` (`src/shamir.rs`, `src/interpolate.rs`)

None of them are behind a feature gate in `bc-crypto` 0.14.0 — `pub mod hash`
and `pub use memzero::{memzero, memzero_vec_vec_u8}` are unconditional. So no
replacement feature list is required, and the change is a pure bug fix with no
behavioural or API effect on existing consumers.

### Verified

With that one-line change applied via `[patch.crates-io]`, a
`wasm32-unknown-unknown` `cdylib` depending on `bc-envelope` + `bc-components`
(features above) compiles and links, including `Envelope::sign` / `verify`
round-trips over Ed25519.

Environment: rustc 1.96.0, target `wasm32-unknown-unknown`, macOS aarch64,
crates as published on 2026-08-07 (`bc-shamir` 0.13.0, `bc-crypto` 0.14.0,
`sskr` 0.12.0, `bc-components` 0.31.1, `bc-envelope` 0.43.0).

### Related

`chacha20poly1305` is declared with default features in `bc-crypto` itself,
which pulls `getrandom` 0.2 into wasm builds via `aead`/`crypto-common`. That
one *is* workable downstream (enable `getrandom`'s `custom` backend), so it is
lower priority — but the same `default-features = false` hygiene would help
there too.

Happy to open a PR with the one-line change if that is the preferred route.
