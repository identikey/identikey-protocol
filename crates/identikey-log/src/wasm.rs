//! The `wasm32-unknown-unknown` host seam — one import, and nothing else.
//!
//! This module is compiled only for `wasm32`. It exists to keep a promise that
//! predates this crate (Dreamball ADR-1): **the browser module declares
//! exactly one host import, `env.getRandomBytes`.** Anything else — a JS shim,
//! a clock, a console — is a capability the host did not agree to grant and a
//! surface an auditor has to reason about.
//!
//! # Why there are two backends and not one
//!
//! The dependency graph pulls **two `getrandom` majors**, and neither is
//! optional:
//!
//! * `getrandom 0.3` — via `bc-rand` / `rand_core 0.9`
//! * `getrandom 0.2` — via `chacha20poly1305`'s default `getrandom` feature →
//!   `aead` → `crypto-common` → `rand_core 0.6`
//!
//! On `wasm32-unknown-unknown`, `getrandom 0.2` emits a hard `compile_error!`
//! unless `js` or `custom` is enabled, and `getrandom 0.3` refuses to link
//! unless a backend is selected by cfg. The obvious fix — turn on `js` — would
//! re-import `wasm-bindgen` and `js-sys` and undo the whole reason
//! `vendor/dcbor` exists. So both majors are routed to the *same* host
//! function, and the module ends up with one import rather than five or eight.
//!
//! `--cfg getrandom_backend="custom"` for this target lives in
//! `.cargo/config.toml` at the repository root.
//!
//! # Placement
//!
//! Only one crate in a linked artefact may define these symbols. That makes
//! defining them in a library a real constraint on downstream consumers, and
//! it is deliberate: `identikey-log` is the leaf of the Gordian stack for the
//! browser, and a consumer that wants to supply its own entropy backend should
//! depend on this crate for `wasm32` with `default-features = false` once such
//! a knob is needed. If a second wasm consumer ever appears, split this module
//! into its own `identikey-wasm-rt` crate rather than duplicating it.

#[link(wasm_import_module = "env")]
unsafe extern "C" {
    /// The single host capability this module asks for: fill `len` bytes at
    /// `ptr` with cryptographically secure randomness.
    ///
    /// The host must treat a failure as fatal; there is no error channel,
    /// because there is no safe behaviour on entropy failure other than not
    /// continuing.
    fn getRandomBytes(ptr: *mut u8, len: usize);
}

fn host_fill(dest: &mut [u8]) {
    // A zero-length fill is a no-op; do not hand the host a dangling pointer.
    if dest.is_empty() {
        return;
    }
    unsafe { getRandomBytes(dest.as_mut_ptr(), dest.len()) }
}

// --- getrandom 0.2 ---------------------------------------------------------
getrandom_02::register_custom_getrandom!(gr02);

fn gr02(dest: &mut [u8]) -> core::result::Result<(), getrandom_02::Error> {
    host_fill(dest);
    Ok(())
}

// --- getrandom 0.3 ---------------------------------------------------------
// Matched by name, not by macro: getrandom 0.3's `custom` backend looks for a
// symbol called exactly `__getrandom_v03_custom` with this signature.
#[unsafe(no_mangle)]
unsafe extern "Rust" fn __getrandom_v03_custom(
    dest: *mut u8,
    len: usize,
) -> core::result::Result<(), getrandom_03::Error> {
    host_fill(unsafe { core::slice::from_raw_parts_mut(dest, len) });
    Ok(())
}

// ---------------------------------------------------------------------------
// Minimal exported surface
// ---------------------------------------------------------------------------
//
// The crate is built as a `cdylib` for this target so that CI has a real
// module to inspect. A `cdylib` with no exports links nothing, dead-code-
// eliminates everything, and would "prove" a one-import invariant vacuously.
// These two exports pull the decode and verify paths — the parts a browser
// peer actually runs — into the binary.

/// Scratch buffer the host writes an encoded op into before calling
/// [`ik_log_verify`]. Returns a pointer to `len` writable bytes.
///
/// Deliberately crude: this is a build-and-audit gate, not a finished ABI. A
/// real browser binding belongs in its own crate with a real memory protocol.
#[unsafe(no_mangle)]
pub extern "C" fn ik_log_alloc(len: usize) -> *mut u8 {
    let mut buf = Vec::<u8>::with_capacity(len);
    let ptr = buf.as_mut_ptr();
    core::mem::forget(buf);
    ptr
}

/// Decode and verify an encoded signed op.
///
/// Returns `1` on success, `0` on any failure. Coarse on purpose — the point
/// here is that the code path *links*, not that it reports well.
///
/// # Safety
/// `ptr`/`len` must describe a buffer obtained from [`ik_log_alloc`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ik_log_verify(ptr: *const u8, len: usize) -> i32 {
    let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
    match crate::sign::decode_and_verify(bytes) {
        Ok(_) => 1,
        Err(_) => 0,
    }
}
