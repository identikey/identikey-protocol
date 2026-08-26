# IdentiKey Capability Tokens v1

**Status:** Adopted format. Draft spec. No test vectors yet (`ikp-6yz.2`).
**Date:** 2026-08-26
**Does not implement:** a crate in this workspace. Format choice plus
the identity/capability split. First consumer profile: Mjolnir
([`docs/plans/rbac-design.md`](https://github.com/identikey/mjolnir/blob/main/docs/plans/rbac-design.md)).
**Biscuit:** [biscuitsec.org](https://www.biscuitsec.org) /
[`biscuit-auth`](https://docs.rs/biscuit-auth).

This is the protocol-tier answer to “how does an agent (or any
delegate) prove what it may *do*.” It does not replace identity, and
it does not replace Recrypt’s recryption-key-as-bearer for *data*.

---

## 1. Three layers. Do not collapse them.

| Layer | Question | Spec |
|---|---|---|
| **Identity** | Who is this? | [`identikey-auth-challenge-v1.md`](identikey-auth-challenge-v1.md) (possession proof). OIDC JWT is an on-ramp, not the grant. |
| **Agency** | What may this holder *do*? | **This spec.** Biscuit capability tokens. Attenuation is the delegation primitive. |
| **Data access** | Who can read this ciphertext? | Recrypt. The recryption key *is* the bearer ([D-5](https://github.com/identikey/recrypt/blob/main/docs/decisions/2026-08-04-capability-tokens-and-field-scoped-recryption.md)). `identikey-storage-auth` / Gordian-envelope capabilities stay Recrypt’s. |

Auth-challenge v1 correctly cut SIWE `resources` / `request-id`.
That hole is this document, not a field on the challenge.

A possession proof (`Response`) is not a grant. A Biscuit is not a
proof of who you are. A recryption key is not a right to `exec` a
VM. Mixing any two is a protocol error.

---

## 2. Format: Biscuit

Evaluated Macaroons, UCAN (JWT subset), custom Ed25519 tokens, and
Biscuit.

| System | Attenuation | Offline verify | Expressiveness | Notes |
|---|---|---|---|---|
| Macaroons | HMAC caveats | Partial | Opaque strings | Elixir/Rust ecosystems stale |
| UCAN | JWT abilities | Full | Flat | Recrypt’s envelope capabilities rhyme; not the agency token |
| Custom Ed25519 | Roll your own | Full | Whatever we invent | We would be specifying a worse Biscuit |
| **Biscuit** | **Datalog checks** | **Full** | **Datalog rules** | Rust-native (`biscuit-auth`); compact (~400–600 B with a few attenuations) |

**Biscuit is the IdentiKey agency-capability format.**

Reasons that survive outside Mjolnir:

- Rights attenuation is first-class and monotonic: a holder may
  append checks, never remove them, never escalate.
- Offline verification: a guest, an agent VM, or a peer can check
  the token without calling an authorization server.
- Datalog maps onto pattern-matched policies without a second
  policy language.
- The authority block is signed. Attenuation blocks chain. The
  token is self-contained.

Recrypt’s Gordian-envelope / UCAN-style tokens remain the *data*
capability for storage-auth. Do not mix wire formats. Do not
“align with UCAN later” for agency — that sentence is retired.

---

## 3. Cryptographic choices

These are the choices, including ones Mjolnir already runs on
identity and hashing, restated so an implementer does not have to
read a product repo.

### 3.1 Identity keys (already specified)

From auth-challenge v1 §3:

| Tag | Role | Scheme |
|---|---|---|
| `"ed25519"` | classical | Ed25519 (RFC 8032). Software. Not enclave-native. |
| `"p256"` | classical | ECDSA P-256. Enclave-native (Apple SE, TPM, Android). |
| `"ml-dsa-44/65/87"` | optional PQ | ML-DSA (FIPS 204). PQ implies classical. |

Fingerprint of an identity is Blake3 over the self-describing
public key (auth-challenge §5). Content-addressed blobs elsewhere
in the stack are also Blake3. That hash choice is not revisited
here.

### 3.2 Biscuit authority key

The Biscuit **authority block** is signed with **Ed25519**. That
is `biscuit-auth`’s native sealing key, and it is a *service*
key (the minter), not the human Identikey.

A P-256 enclave identity **does not sign Biscuit blocks**. It
proves who the minter is talking to (auth-challenge or OIDC).
The minter then issues a root Biscuit whose authority signature
is the minter’s Ed25519 key.

Optional: an attenuation or a Datalog fact names the Identikey
fingerprint the token was minted *for*, so a verifier can bind
agency to identity without confusing the two keys.

### 3.3 Always signed. Verification is not a protocol mode.

Every Biscuit has an authority signature. There is no “unsigned
capability” in this spec.

A product that *presents* tokens before it *verifies* them is
incomplete, not a second mode. When a component claims to
authorize from a capability, it MUST:

1. Verify the Ed25519 authority chain.
2. Evaluate the Datalog checks against the request facts.
3. Reject on any failed check.

Early Mjolnir still authorizes with JWT scopes (Phase 0). That
is identity-bootstrap leftover, not an unsigned-capability
profile.

### 3.4 What this spec does not change

- Wallet at rest: Argon2id + XChaCha20-Poly1305 (`IKEYW` v2).
- Wire of identity proofs: canonical dCBOR.
- Recrypt bulk data: XChaCha20-Bao-AEAD, PRE key material.
  Those stay Recrypt.

---

## 4. Lifecycle

```
Identikey (or OIDC JWT)
        │  possession / login
        ▼
   minter (Ed25519 authority)
        │  root Biscuit
        ▼
   holder ──attenuate──► delegate ──attenuate──► …
        │
        ▼
   verifier (offline or online): signature chain + Datalog
```

- **Mint.** After identity is established, a minter issues a
  root Biscuit encoding the maximum rights for a resource (a VM,
  a snapshot, a tool, a mailbox). The root is the ceiling.
- **Attenuate.** Anyone holding a token may append checks
  (TTL, operation subset, resource subset, count facts the
  verifier will inject). No server call. Cannot widen.
- **Present.** `Authorization: Bearer biscuit:<base64>` or the
  equivalent vsock / Iroh frame. Application profiles name the
  header; the bytes are a Biscuit.
- **Verify.** §3.3.

OIDC remains an on-ramp: prove who you are, receive root
capabilities, then stop sending the JWT for authorization.
Auth-challenge is the same on-ramp without an OpenID Provider.
VMs and agents typically never have an OIDC identity; they
hold only Biscuits.

---

## 5. Wallet cache

[`wallet-envelope-format.md`](wallet-envelope-format.md) §8
defines `"delegated-capability"` as a nested envelope for cached
tokens. That assertion carries **Biscuit token bytes** (and
optional metadata: resource id, expiry, attenuation notes).

Older wallet clients that do not know the predicate MUST
preserve the assertion on load/save (unknown-assertion rule).
They MUST NOT interpret it.

---

## 6. Application profile (non-normative): Mjolnir

Normative agency rules are Biscuit + §3. What a token *may
talk about* is an application profile.

Mjolnir’s first profile (not this spec’s job to freeze):

- Authority facts such as `vm(<id>)`, `owner(<identikey>)`,
  `right(<id>, <op>)` with ops `exec | read | stop | snapshot |
  terminal:read | terminal:write | pty | message | spawn`.
- Attenuation examples: time bound, op subset, spawn-count
  (stateful fact the host injects), VM-to-VM chain.
- Guest agent verifies offline on Iroh using the minter’s
  Ed25519 public key injected at boot.

See Mjolnir `docs/plans/rbac-design.md`. Papyrus is the first
human UI that mints and attenuates (identity-manager / PRM has
not started). OS/TCC permissions in Papyrus are a different
object.

---

## 7. Out of scope

- Revocation sets / bloom filters (product; TTL + authority
  epoch cover the common case).
- Session types, process calculus, mailbox spool — those are
  Mjolnir communication, not this token.
- Recrypt PRE, field-scoped recryption, storage-auth envelope
  capabilities.
- Test vectors — `ikp-6yz.2`. Until they exist this spec is
  not independently implementable, same as the rest of this
  folder.

---

## 8. What changed on 2026-08-26

Auth-challenge v1 §9 and §11, and the OIDC grant “not a
capability” line, pointed at Recrypt UCAN-style capabilities
“when needed.” That pointer is wrong for *agency*. Recrypt
keeps data-access capabilities. Agency is Biscuit.
