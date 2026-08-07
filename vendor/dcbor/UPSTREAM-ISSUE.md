# FILED 2026-08-07

**Issue:** <https://github.com/BlockchainCommons/bc-dcbor-rust/issues/6>

**Target:** <https://github.com/BlockchainCommons/bc-dcbor-rust/issues/new>
**Status:** filed 2026-08-07 with the project owner's authorization.

Everything below the line is the issue body, ready to paste.

---

**Title:** `chrono` default features pull `wasm-bindgen` into every
`wasm32-unknown-unknown` build (+110 KB gzip, 7 extra host imports)

### Summary

`dcbor` 0.25.2 declares:

```toml
chrono = { version = "^0.4.28", default-features = true }
```

`chrono`'s default feature set includes `wasmbind`, which on
`wasm32-unknown-unknown` pulls in `js-sys` and `wasm-bindgen`.

`dcbor` is a mandatory dependency throughout the Blockchain Commons stack
(`bc-components`, `bc-envelope`, `bc-ur`, `known-values`), so **every wasm
consumer of that stack silently inherits a browser-JS dependency** — including
consumers that never touch dates and consumers that are not running in a
browser at all (standalone runtimes, wasm plugin hosts, `wasi`-less embeddings).

The cost is not theoretical: it more than doubles the binary and, more
seriously, changes the module's host contract. A module that used to declare a
single import now declares imports from `__wbindgen_placeholder__` and
`__wbindgen_externref_xform__`, so it can no longer be instantiated by a plain
host — it requires the wasm-bindgen JS shim, which is a build-time artefact the
consumer never asked for.

### Reproduction

A `cdylib` for `wasm32-unknown-unknown` depending on

```toml
bc-envelope   = { version = "0.43.0", default-features = false, features = ["signature", "ed25519"] }
bc-components = { version = "0.31.1", default-features = false, features = ["ed25519"] }
```

(with `getrandom` wired to a custom backend, and with
<https://github.com/BlockchainCommons/bc-shamir-rust> patched so the graph
builds at all — see the companion issue on `bc-shamir`).

```console
$ cargo tree -e features -i chrono --target wasm32-unknown-unknown
chrono v0.4.45
├── chrono feature "alloc"
│   └── chrono feature "std"
│       ├── dcbor feature "std"
...
```

Release profile `opt-level = "z"`, `lto = true`, `panic = "abort"`,
`codegen-units = 1`; then `wasm-opt -Oz --enable-bulk-memory
--enable-nontrapping-float-to-int --strip-debug`.

| | raw | gzip -9 | imports |
|---|---|---|---|
| stock `dcbor` 0.25.2 | 571,190 B | 222,717 B | **8** |
| with the one-line fix | 201,096 B | 112,070 B | **1** |
| delta | −370,094 B (−65 %) | −110,647 B (−50 %) | −7 |

Stock import section (`wasm-dis`):

```wat
(import "env" "getRandomBytes" (func $fimport$0 (param i32 i32)))
(import "__wbindgen_placeholder__" "__wbg_new_0_3da9e97f24fc69be" (func $fimport$1 (result i32)))
(import "__wbindgen_placeholder__" "__wbg_getTime_d6f070c088c9b5ed" (func $fimport$2 (param i32) (result f64)))
(import "__wbindgen_placeholder__" "__wbindgen_object_drop_ref" (func $fimport$3 (param i32)))
(import "__wbindgen_placeholder__" "__wbindgen_describe" (func $fimport$4 (param i32)))
(import "__wbindgen_placeholder__" "__wbg___wbindgen_throw_344f42d3211c4765" (func $fimport$5 (param i32 i32)))
(import "__wbindgen_externref_xform__" "__wbindgen_externref_table_set_null" (func $fimport$6 (param i32)))
(import "__wbindgen_externref_xform__" "__wbindgen_externref_table_grow" (func $fimport$7 (param i32) (result i32)))
```

Patched import section, complete:

```wat
(import "env" "getRandomBytes" (func $fimport$0 (param i32 i32)))
```

The only functional difference the extra imports buy is that `Utc::now()` reads
`Date.now()` through JS instead of returning an error/zero — which is exactly
the trade-off a consumer should get to make.

### Fix

One line:

```diff
 [dependencies]
-chrono = { version = "^0.4.28", default-features = true }
+chrono = { version = "^0.4.28", default-features = false, features = ["alloc", "now"] }
```

`alloc` covers formatting/parsing of `DateTime<Utc>`; `now` covers
`Date::now()` / `Utc::now()`. `dcbor`'s existing `std` feature already adds
`chrono/std`, so non-wasm `std` builds are unaffected — they simply stop
force-enabling `wasmbind` and the rest of chrono's defaults.

Consumers who *do* want JS-backed wall-clock time in the browser can then opt
back in with `chrono = { version = "0.4", features = ["wasmbind"] }` in their
own manifest, which is the normal way this is expressed.

### Optional, larger follow-up

Making `chrono` optional in `dcbor` altogether (feature-gating `Date`) would
serve `no_std` and embedded consumers better still, and would fit the crate's
existing `no_std` feature. The one-line fix above is the safe immediate change;
this is a separate design question.

### Environment

rustc 1.96.0, target `wasm32-unknown-unknown`, macOS aarch64, binaryen
`wasm-opt`/`wasm-dis`, crates as published 2026-08-07 (`dcbor` 0.25.2,
`chrono` 0.4.45, `bc-components` 0.31.1, `bc-envelope` 0.43.0).

Happy to open a PR with the one-line change if that is the preferred route.
