# Vendored fork — `dcbor` 0.25.2 (wasm32 size / host-import patch)

Tracks `Dreamball-n8r`. Prerequisite for `Dreamball-y4t.4` (the Rust port).

## Pin

- Upstream: <https://github.com/BlockchainCommons/bc-dcbor-rust>
- Version / tag: `0.25.2` — commit `c76a15a3729b5753824d0b08b95a08d7c7d8998d`
- Source of truth for this copy: the published `dcbor 0.25.2` crate tarball, as
  unpacked by cargo into the local registry.
- Copied on: 2026-08-07
- Upstream `master` was checked on the same date and still carries the
  unpatched line. `0.25.2` is the newest published version (crates.io,
  2026-08-07), so **there is no upgrade that avoids this fork.**

## The defect

`dcbor` declares `chrono` with default features:

```toml
chrono = { version = "^0.4.28", default-features = true }
```

`chrono`'s defaults include `wasmbind`, which on `wasm32-unknown-unknown` pulls
in `js-sys` and `wasm-bindgen`. `dcbor` is not optional anywhere in the
Blockchain Commons stack, so every wasm consumer of `bc-components` /
`bc-envelope` silently inherits a browser-JS dependency.

This breaks Dreamball's ADR-1 invariant (see `docs/ARCHITECTURE.md`): the WASM
binary must declare **exactly one host import**, `env.getRandomBytes`. With
`wasmbind` linked, the module declares imports from `__wbindgen_placeholder__`
and `__wbindgen_externref_xform__` as well, which means the binary can no
longer be instantiated by a plain host that supplies only randomness.

## The patch

One line in `Cargo.toml`:

```diff
 [dependencies]
-chrono = { version = "^0.4.28", default-features = true }
+chrono = { version = "^0.4.28", default-features = false, features = ["alloc", "now"] }
 half = { version = "^2.4.1", default-features = false }
```

`alloc` covers `dcbor`'s formatting/parsing of `DateTime<Utc>`; `now` covers
`Date::now()` / `Utc::now()`. `dcbor`'s existing `std` feature already adds
`chrono/std` on top, so the `std` build is unaffected — it simply no longer
force-enables `wasmbind`, `clock`'s platform glue, `oldtime`, and friends.

No Rust source is modified. Nothing else in this directory differs from
upstream, with two mechanical exceptions applied to every vendored crate here:

- `Cargo.toml` is upstream's hand-authored `Cargo.toml.orig` (cargo's
  normalised `Cargo.toml` from the tarball was discarded) so that the diff
  above is a real, PR-ready diff against the upstream repository.
- `.cargo_vcs_info.json` was removed.

## Measured impact

Same scratch `cdylib`, `bc-shamir` patched in both arms, only `dcbor` differing.
Release profile `opt-level = "z"`, `lto = true`, `panic = "abort"`,
`codegen-units = 1`, then `wasm-opt -Oz --enable-bulk-memory
--enable-nontrapping-float-to-int --strip-debug`. Measured 2026-08-07.

| | raw | gzip -9 | imports |
|---|---|---|---|
| `dcbor` **stock** | 571,190 B | 222,717 B | **8** (3 modules) |
| `dcbor` **patched** | 201,096 B | 112,070 B | **1** |
| delta | −370,094 B (−65 %) | −110,647 B (−50 %) | −7 |

Stock import section, verbatim from `wasm-dis`:

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

Patched import section — the whole thing:

```wat
(import "env" "getRandomBytes" (func $fimport$0 (param i32 i32)))
```

The `Dreamball-h7s.2` spike reported "four extra host imports / five total"; the
count depends on which rung of the ladder is linked and on how the tool groups
externref-table helpers. The invariant that matters is unchanged and now
verified end-to-end: **one import with the patch, many without.**

## Ready-to-paste `[patch.crates-io]`

The Rust workspace does not exist yet — `Dreamball-y4t.4` creates it. When it
does, paste this into the **workspace root** `Cargo.toml`:

```toml
[patch.crates-io]
bc-shamir = { path = "vendor/bc-shamir" }
dcbor     = { path = "vendor/dcbor" }
```

Both patches are needed together. `[patch.crates-io]` is only honoured from the
workspace root and the path is relative to that root.

## Proof recipe

Reproduce from a clean scratch crate (this is what produced the table above):

`Cargo.toml`

```toml
[lib]
crate-type = ["cdylib"]

[dependencies]
bc-envelope   = { version = "0.43.0", default-features = false, features = ["signature", "ed25519"] }
bc-components = { version = "0.31.1", default-features = false, features = ["ed25519"] }
getrandom_02  = { package = "getrandom", version = "0.2", features = ["custom"] }
getrandom_03  = { package = "getrandom", version = "0.3" }

[profile.release]
opt-level = "z"; lto = true; panic = "abort"; codegen-units = 1; strip = true

[patch.crates-io]
bc-shamir = { path = "../../vendor/bc-shamir" }
dcbor     = { path = "../../vendor/dcbor" }
```

`.cargo/config.toml`

```toml
[target.wasm32-unknown-unknown]
rustflags = ['--cfg', 'getrandom_backend="custom"']
```

Then `cargo build --release --target wasm32-unknown-unknown` and
`wasm-dis <out>.wasm | grep '(import'`.

### The third thing the port has to do: two `getrandom` majors

Not an upstream bug, but it *looks* like one and will bite `Dreamball-y4t.4`,
so it is recorded here. The graph pulls in **both** getrandom majors:

- `getrandom 0.3` via `bc-rand` / `rand_core 0.9`
- `getrandom 0.2` via `chacha20poly1305`'s default `getrandom` feature →
  `aead` → `crypto-common` → `rand_core 0.6`
  (`bc-crypto` declares `chacha20poly1305 = "^0.10.1"` with default features —
  the same class of defect as the two above, but this one *is* fixable
  downstream, so it does not need a fork.)

`getrandom 0.2` emits a hard `compile_error!` on `wasm32-unknown-unknown` unless
`js` or `custom` is enabled. Enabling `js` would re-import wasm-bindgen and undo
the `dcbor` fix. The correct wiring routes **both** majors to the one host seam:

```rust
#[link(wasm_import_module = "env")]
unsafe extern "C" { fn getRandomBytes(ptr: *mut u8, len: usize); }

fn host_fill(dest: &mut [u8]) { unsafe { getRandomBytes(dest.as_mut_ptr(), dest.len()) } }

getrandom_02::register_custom_getrandom!(gr02);
fn gr02(dest: &mut [u8]) -> Result<(), getrandom_02::Error> { host_fill(dest); Ok(()) }

#[unsafe(no_mangle)]
unsafe extern "Rust" fn __getrandom_v03_custom(
    dest: *mut u8, len: usize,
) -> Result<(), getrandom_03::Error> {
    host_fill(unsafe { core::slice::from_raw_parts_mut(dest, len) });
    Ok(())
}
```

That is what yields the single-import result above.

## Supply-chain note

Same reasoning as `vendor/bc-shamir/VENDOR.md`: the delta is one line of
`Cargo.toml`, no Rust source is touched, and `diff -ru` against a fresh
`cargo vendor` of 0.25.2 should show only `Cargo.toml`. `UPSTREAM-ISSUE.md` in
this directory is a drafted, unfiled bug report; when upstream ships the fix,
delete this directory and the corresponding `[patch.crates-io]` line.

## Refresh procedure

1. Check whether a newer `dcbor` fixes it: unpack it and grep for
   `chrono = `. If it carries `default-features = false`, **delete this fork**
   and drop the patch line.
2. Otherwise: re-unpack, re-apply the one-line diff, update the Pin section,
   re-run the proof build, and re-measure the table above.

## License

BSD-2-Clause-Patent, unchanged. `LICENSE.md` is upstream's verbatim.
