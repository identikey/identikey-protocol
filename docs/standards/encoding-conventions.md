# Encoding Conventions

**Status:** Stable
**Date:** 2026-04-27; rescoped 2026-08-07
**Scope:** Every place a byte sequence crosses a text boundary in any consumer
of the IdentiKey envelope formats — `identikey-auth`, `identikey-wallet`,
`identikey-log`, [Recrypt](https://github.com/identikey/recrypt), and
Dreamball.

> **Rescoped 2026-08-07.** This document was written for Recrypt and said so
> ("anywhere in recrypt"). It is now normative for three repositories, because
> all three encode the same Gordian Envelopes and were independently inventing
> the same rules — and, in one place, inventing them *differently*. See §5.

---

## 1. The boundary rule

There are **three** regimes:

- **Inside CBOR / Gordian Envelope payloads** (wire, wallet body, exported identity, signed messages, op-log entries): everything is **raw bytes** (CBOR major type 2). No base58, no base64, no hex, no JSON arrays. The dCBOR rules in [dcbor-determinism.md](dcbor-determinism.md) require byte-identical re-serialization, and any text wrapping breaks that contract.

- **A whole envelope crossing a text boundary** (export, QR, airgap, paste-into-chat, `--format` output): **UR** — `ur:envelope/<bytewords>`. See §7. This is the Gordian ecosystem's own text form, it round-trips through the `envelope` CLI and every Blockchain Commons tool, and it is already available in every one of our binaries at no cost.

- **A single value crossing a text boundary** (HTTP headers, HTTP JSON bodies, console output, URL path segments, error messages, log lines): use the table in §2.

JSON-with-byte-arrays is not a wire format, and a hand-rolled armor block is
not a text form when `ur:` exists.

## 2. Text encodings

| Use case                                                                                 | Encoding                  | Why                                                                       |
|------------------------------------------------------------------------------------------|---------------------------|---------------------------------------------------------------------------|
| Short stable identifiers (≤ 256 bytes): public keys, fingerprints, file hashes, share IDs | **base58**                | Compact, no padding, URL-safe, easy to read and visually compare          |
| Variable-length opaque blobs (> 256 bytes or runtime-variable): signatures, ML-DSA keys, lattice PRE keys, recryption keys, ciphertexts | **base64 standard** (RFC 4648, with padding) | Linear-time encoding; base58 is O(n²) and gets painful past a few KB     |
| Diagnostic dumps (CBOR diagnostic notation, debug logs, error details)                   | **hex (lowercase)**       | Direct byte-to-nibble mapping; matches CBOR-diag conventions              |
| Naturally textual values (identity name, backend ID, format-version, type tag)           | **utf-8 string** (or native CBOR / JSON type) | These aren't bytes                                              |

**Rule of thumb for choosing between base58 and base64:** if a human will copy/paste it, base58. If a machine produces and consumes it, base64. The 256-byte cutoff exists because base58's bignum arithmetic is quadratic — a 5 KB ML-DSA key takes orders of magnitude longer to encode than the 5 KB itself warrants.

## 3. Forbidden encodings

- **JSON byte arrays** (`[1, 2, 3, …]`). Anywhere. If you find yourself reaching for one, the right answer is CBOR (envelope) or one of the text encodings above. Serde's default for `[u8; N]` produces these — guard against it with `#[serde(with = "…")]` or a wrapper type at any boundary that touches JSON.
- **base58 of multi-KB values.** O(n²). Use base64.
- **hex outside diagnostics.** 2× expansion vs ~1.33× for base64; no upside.
- **base32, ASCII85, hex variants (uppercase/0x-prefixed), custom encodings.** Not part of this stack's vocabulary.
- **Hand-rolled armor / PEM blocks for whole envelopes.** Use UR (§7).

## 4. Specific values

This table is normative — when implementing a new boundary, check here first.

Rows naming PRE keys, recryption keys and KeyMaterial are Recrypt-specific;
they stay here rather than in Recrypt's own docs because the *rule* they
instantiate (size decides base58 vs base64) is what other consumers need to
copy. Everything above the PRE rows applies to every consumer.

| Value                                | Size       | Inside CBOR | At text boundary |
|--------------------------------------|------------|-------------|------------------|
| ED25519 public key                   | 32 B       | raw bytes   | base58           |
| ED25519 secret key                   | 32 B       | raw bytes   | base58 (rare)    |
| ED25519 signature                    | 64 B       | raw bytes   | base64           |
| ML-DSA-87 public key                 | ~2.5 KB    | raw bytes   | **base64**       |
| ML-DSA-87 secret key                 | ~4.9 KB    | raw bytes   | **base64**       |
| ML-DSA-87 signature                  | ~4.6 KB    | raw bytes   | base64           |
| Fingerprint (Blake3 of ed25519 pk)   | 32 B       | raw bytes   | base58           |
| File hash (Blake3 of plaintext/file) | 32 B       | raw bytes   | base58           |
| PRE public key (mock)                | 32 B       | raw bytes   | base58           |
| PRE public key (lattice-bfv)         | multi-KB   | raw bytes   | **base64**       |
| PRE secret key (lattice-bfv)         | multi-KB   | raw bytes   | **base64**       |
| Recryption key (mock)                | small      | raw bytes   | base58           |
| Recryption key (lattice-bfv)         | multi-KB   | raw bytes   | **base64**       |
| KeyMaterial (96-byte fixed PRE blob) | 96 B fixed | raw bytes (not CBOR-wrapped — see [wire-protocol.md §"KeyMaterial"](https://github.com/identikey/recrypt/blob/main/docs/wire-protocol.md)) | base64 |
| Argon2id salt (wallet shell)         | 32 B       | raw bytes (in shell header, not CBOR) | n/a (never exposed) |
| XChaCha20-Poly1305 nonce             | 24 B       | raw bytes   | base64 (rare)    |
| Server auth nonce                    | server-defined string | n/a         | utf-8 (server returns a string)          |
| Identity name, type tag, backend ID  | utf-8      | utf-8 string | utf-8           |

## 5. Known violations

**Recrypt:** none as of 2026-04-27 (post recrypt-6aj sweep). All multi-KB blobs in code paths use base64; short stable IDs use base58.

**Dreamball, as of 2026-08-07 — open.** `docs/PROTOCOL.md` §7 specifies the
JSON export as: *"Byte strings become base58-encoded strings prefixed with
`b58:`"* — universally, with no size tier. Two problems, and they are separate:

1. **Opposite default from §5.1.** Recrypt emits `b64:` and accepts `b58:` for
   back-compat; Dreamball emits `b58:` as the standard. Same prefix vocabulary,
   inverted meaning, in two codebases whose stated goal is envelope-level
   interop.
2. **It reproduces a bug already fixed here.** Base58 is O(n²) — see the rule
   of thumb in §2 and `recrypt-n1e` in §5.2, where `identity show` hung
   encoding a multi-MB key. An unconditional rule means the first ML-DSA-87
   signature (~4.6 KB) or large blob in an op hits it.

Reconciling these is the point of rescoping this document. Dreamball has no
size tier because nothing forced the question yet; it will.

**Nobody emits UR (§7).** Not a violation of the old two-regime rule, which is
why it went unnoticed — the capability has been linked into every binary in
the stack and unused. Dreamball's Gordian adoption ADR (2026-08-07) lists "UR
for QR/sneakernet" among the benefits *obtained* from the migration; that
benefit is available, not yet taken.

### 5.1 Tagged-input convention

Endpoints that accept multi-KB blobs over JSON accept input strings tagged with their encoding:

- `b64:<base64>` — preferred
- `b58:<base58>` — accepted for backward compatibility
- bare string with no prefix — treated as base58 (legacy pre-2026 clients)

Outputs always emit `b64:<base64>`. Clients that previously stripped a `b58:` prefix must be updated to also handle `b64:`. This applies today to `/sign/ml-dsa`, `/verify/ml-dsa`, and the `root_pk` / `signatures` fields of `KeyspaceDocJson`.

### 5.2 Historical fixes

- `recrypt-jtw` (closed 2026-04-27) — migrated `CreateShareRequest.recrypt_key` and `wrapped_key` from base58 to base64.
- `recrypt-fil` (closed 2026-04-27) — migrated `ml_dsa_pk` (REST body + `CREATE` canonical signature message) from base58 to base64.
- `recrypt-n1e` (closed 2026-04-27) — fixed `identity show` hanging on bs58::encode of multi-MB lattice PRE pubkey; display path now picks base58 vs base64 by size.
- `recrypt-6aj` (closed 2026-04-27) — migrated `/sign/ml-dsa`, `/verify/ml-dsa`, and `KeyspaceDocJson.{root_pk, signatures}` from base58 to tagged base64; introduced the `b64:` / `b58:` input-tag convention.

## 6. ASCII armor block headers — LEGACY, read-only

> **Superseded 2026-08-07 by §7 (UR).** New code MUST NOT emit armor blocks.
> Decoders keep reading them for existing exports. `recrypt identity export`
> emits `ur:envelope/…`; `--format=armor` is retained as a legacy alias whose
> output is frozen at what is specified below.
>
> This format was written before anyone checked what the envelope library
> already provided. It is a PEM variant with its own header grammar, its own
> BEGIN/END matching rule, and its own implementation — solving, less well, the
> problem `ur:` solves for free.

ASCII-armored exports wrap envelope bytes in a PEM-style block:

```
----- BEGIN RECRYPT IDENTITY -----
Version: 1
Format: envelope+cbor

<base64 of envelope bytes>
----- END RECRYPT IDENTITY -----
```

**Canonical headers:**

| Key         | Required? | Value                                                          |
|-------------|-----------|----------------------------------------------------------------|
| `Version`   | yes       | Integer string. Currently `1` for `recrypt.identity` exports. Bumped on breaking changes to the encapsulated envelope. |
| `Format`    | yes       | Always `envelope+cbor` for envelope payloads.                   |
| `Algorithm` | optional  | Free-form algorithm summary (e.g. `ED25519+ML-DSA-87+PRE`). Advisory only — the payload bytes are the source of truth. |
| `Created`   | optional  | Epoch seconds the armor was produced.                          |
| `Fingerprint` | optional | base58 fingerprint of the embedded identity for visual ID.    |

**Header parsing rules:**

- Each header line is `Key: Value\n` (key, ASCII colon, ASCII space, value).
- Decoders MUST tolerate unknown header keys (forward compat).
- Decoders MUST NOT use header values for security decisions — the payload is signed and authoritative.
- Encoders MUST NOT include any whitespace inside the key. Values may contain spaces.

**BEGIN/END marker rule:** the `END` line MUST match the `BEGIN` armor type byte-for-byte. A `BEGIN RECRYPT IDENTITY` block ending with `END RECRYPT PUBLIC KEY` is rejected.

> **Corrected 2026-08-07.** This section previously showed the markers as
> `-----BEGIN RECRYPT IDENTITY-----`, with no spaces. The implementation
> (`recrypt-wire/src/armor.rs`) has always emitted and required
> `----- BEGIN RECRYPT IDENTITY -----`, **with** a space inside each dash run.
> Every armor block in the wild uses the spaced form, so the implementation
> wins and the spec is corrected to match. Noted rather than silently changed
> because this is exactly the class of drift that test vectors would have
> caught at the time (`ikp-6yz.2`) — and freezing a legacy format against the
> wrong text would have been worse than leaving it unfrozen.

**Implementation:** [`recrypt-wire/src/armor.rs`](https://github.com/identikey/recrypt/blob/main/crates/recrypt-wire/src/armor.rs) (recrypt repo).

## 7. UR — the canonical text form for a whole envelope

When an entire envelope crosses a text boundary, emit a **UR** (Uniform
Resource):

```
ur:envelope/lftpsplftpsotanshdhdcxjnwlkslgtplgbwfmcndsfhmhmyghbwoxrn…
```

**This costs nothing to adopt.** `bc-ur` declares
`impl<T> UREncodable for T where T: CBORTaggedEncodable`, and `Envelope`
implements `CBORTaggedEncodable`. Every binary in this stack already links
`bc-ur` transitively through `bc-components`, so `envelope.ur_string()` and
`Envelope::from_ur_string()` work today with no new dependency and no feature
flag.

**Rules:**

- The UR type is `envelope` for a Gordian Envelope. Do not invent per-app UR
  types (`ur:recrypt-identity/…`) — the payload's own envelope subject and
  assertions carry the type, and a non-standard UR type is unreadable to every
  tool in the ecosystem.
- UR strings are **case-insensitive** and are conventionally lowercase in text,
  UPPERCASE in QR codes (alphanumeric QR mode is denser for uppercase).
- Multi-part URs (`ur:envelope/1-3/…`) exist for payloads too large for one QR.
  Emit single-part unless generating QR for something over ~2 KB.
- Bytewords are the UR body encoding. Do not hand-roll them; do not
  base64-then-UR.

**Why this and not the armor block in §6:**

| | armor (§6) | UR (§7) |
|---|---|---|
| Read by BC `envelope` CLI, seedtool, Gordian apps | no | yes |
| QR / airgap transport | no | yes, incl. multi-part |
| Implementation we maintain | ~a file of header grammar | none |
| Self-describing type | header line, advisory only | UR type + envelope subject |
| Checksum | none | bytewords CRC |

**What is lost:** the armor headers (`Algorithm`, `Created`, `Fingerprint`)
were advisory metadata visible without decoding. If any of that is worth
keeping, it belongs *inside* the envelope as assertions — where it is signed —
rather than in a header the spec already says decoders "MUST NOT use for
security decisions."

## 8. References

- [wire-protocol.md](https://github.com/identikey/recrypt/blob/main/docs/wire-protocol.md) — wire format (envelope + dCBOR)
- [wallet-envelope-format.md](wallet-envelope-format.md) — wallet body encoding
- [http-api-reference.md](https://github.com/identikey/recrypt/blob/main/docs/http-api-reference.md) — header & JSON-body encodings
- [hashing-standard.md](https://github.com/identikey/recrypt/blob/main/docs/standards/hashing-standard.md) — fingerprint / file-hash construction
- [dcbor-determinism.md](dcbor-determinism.md) — dCBOR rules for byte-identical serialization
- [RFC 4648](https://datatracker.ietf.org/doc/html/rfc4648) — base64 / base32 / base16 specs
- [Base58 (Bitcoin)](https://en.bitcoin.it/wiki/Base58Check_encoding) — alphabet origin and rationale
