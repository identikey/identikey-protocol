# Protocol-tier specifications

These specify the formats and protocols this workspace implements. They live
here, rather than in a consumer's repo, for the reason the whole tier exists:
a spec that can only be read inside an AGPL product repo is not a spec anyone
can safely reimplement.

| Spec | Specifies | Implemented by |
|---|---|---|
| [`identikey-auth-challenge-v1.md`](identikey-auth-challenge-v1.md) | Audience-bound nonce challenge/response, cipher-agile, CBOR wire form. Same bytes for wallet signer and managed-custody operator. | [`identikey-auth`](../../crates/identikey-auth) |
| [`identikey-oidc-urn-grant-v1.md`](identikey-oidc-urn-grant-v1.md) | How that `Response` is carried on OAuth `POST /token` (`urn:identikey:params:oauth:grant-type:challenge-response`) | `identikey-oidc` in identikey-core (product) |
| [`identikey-auth-platform-backends.md`](identikey-auth-platform-backends.md) | Engineering notes for `Signer` backends against hardware key stores (Secure Enclave, TPM 2.0) | [`identikey-auth`](../../crates/identikey-auth) |
| [`wallet-envelope-format.md`](wallet-envelope-format.md) | The `IKEYW` wallet container: Gordian Envelope layout, encryption shell, unknown-assertion preservation | [`identikey-wallet`](../../crates/identikey-wallet) |
| [`dcbor-determinism.md`](dcbor-determinism.md) | The byte-identical serialization contract every envelope above depends on | all of the above |
| [`encoding-conventions.md`](encoding-conventions.md) | Where bytes cross text boundaries: raw-in-CBOR, `ur:` for whole envelopes, base58/base64 by size for single values | all consumers, incl. Recrypt and Dreamball |

Moved here from the recrypt repo on 2026-08-07, where they had been left
behind by the code extraction of 2026-08-01 (recrypt D-4).

## Known gap: these are not yet independently implementable

**None of these carry test vectors.** That is the single largest thing standing
between "we wrote a spec" and "someone else can implement it" — a spec without
vectors gets read, a spec with vectors gets implemented — and it is the reason
`ikp-6yz.2` exists.

Two of them also still lean on documents that stayed in recrypt, which is a
real dependency and not just a broken link:

- ~~`wallet-envelope-format.md` references recrypt's `encoding-conventions.md`~~
  — resolved 2026-08-07: that document moved here and was rescoped to bind
  every consumer of these envelope formats. It also gained §7, making `ur:` the
  canonical text form for a whole envelope and demoting the hand-rolled armor
  block to legacy-read.
- `wallet-envelope-format.md` still references recrypt's
  `identity-self-signature.md`, and that one is correctly recrypt's:
  app-specific key material (`pre-public`, `pre-backend`) riding on a generic
  container is exactly the boundary D-4 drew.
- `dcbor-determinism.md` references recrypt's `wire-protocol.md` for context.

Those links are absolute URLs into the recrypt repo, so they resolve. But an
implementer who cannot read an AGPL repo — the exact person this tier is for —
still needs the normative content restated here. Tracked in `ikp-6yz.2`.

## What deliberately stayed in recrypt

Not everything under `docs/standards/` there was protocol-tier, and the ones
that stayed are not oversights. (`encoding-conventions.md` was on this list
until 2026-08-07, kept back because its scope line said "anywhere in recrypt"
and six recrypt source files cite it. Dreamball adopting the same envelope
format the same day settled it: the scope line described the document's
history, not its role.)

- `recrypt-key-material-v1.md`, `xchacha20-bao-aead.md` — proxy recryption and
  bulk-data encryption. Nothing to do with identity.
- `identity-self-signature.md` — the *recrypt* identity envelope, carrying PRE
  key material.
- `hashing-standard.md` — a recrypt decision (Blake3 everywhere).
