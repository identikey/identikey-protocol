# IdentiKey Capability Tokens v1

**Status:** Adopted format. Draft spec. Fixtures in
`crates/identikey-capability/tests/fixtures/` (`ikp-6yz.4`).
**Date:** 2026-08-26
**Implements:** [`identikey-capability`](../../crates/identikey-capability)
(wire + validators; no lifecycle). First consumer profile: Mjolnir
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

## 7. Secret-redemption profile (foreign secrets)

A working secret (GitHub PAT, API key) must not travel down an
agent tree. This profile is an **online-verifier application of
agency**. It does not weaken §2 for other profiles (VM exec,
mailbox, snapshot). It is not a fourth crypto layer. Recrypt PRE
stays data access for *our* ciphertext. The first verifier is
Mjolnir's tokenator (`add-secret-tokenator`, living spec
`secret-tokenator`).

### 7.1 Holder-bound

A Biscuit that authorizes `redeem` of a foreign secret SHALL name
the holder that may perform it. v1 holder class is a single
Identikey public key. The token SHALL carry a holder **check**
(`check if holder($fp), $fp == "<fingerprint>"`) and SHALL NOT
assert a `holder` fact in any block. Fingerprint is the Blake3
identity fingerprint from auth-challenge v1 §5. A verifier SHALL
NOT treat possession of the token bytes as sufficient. It SHALL
verify a signature by that key over a single signed tuple (token
identity, verifier-chosen nonce, audience; plus a response key if
the profile seals the release), compute the fingerprint from the
presented `{alg, key}`, inject the `holder(<fingerprint>)`
**fact** (verifier-injected only), then evaluate the Biscuit. A
failed holder proof SHALL fail closed. Encoding of the tuple and
the definition of token identity stay with Mjolnir
`add-biscuit-runtime` / `ikp-6yz.2`.

This requirement SHALL NOT apply to other agency profiles unless
those profiles add it. A root VM-exec Biscuit without a holder
check is not a violation of this spec.

A minted token whose authority or attenuation block contains a
`holder` fact SHALL be rejected.

### 7.2 Secret bytes stay out of the token

A Biscuit SHALL NOT contain the bytes of a foreign secret, nor a
ciphertext of those bytes that the presenter can decrypt without
the verifier. It MAY name a secret identifier and SHALL, if it
carries a digest of the secret, use a **salted** Blake3
commitment (`Blake3(domain || salt || secret)`). Salt MAY travel
with the token. An unsalted hash of the secret SHALL NOT appear
on the wire (Recrypt D-5: salting is mandatory for low-entropy
secrets). Copy-out (release of `{value, salt}` to the holder;
Mjolnir tokenator) SHALL be verifiable against that commitment.
Holder fingerprints SHALL be Blake3 per auth-challenge v1 §5, not
a SHA-256 stub and not a raw-Ed25519 preimage.

### 7.3 Hop provenance is the Biscuit block chain

v1 redeem SHALL succeed with zero hop blocks when the issuer
bound the holder at mint. When a hop is recorded, it SHALL be a
Biscuit block on that token, not an `identikey-log` (or other)
op. A hop SHALL NOT remove holder checks or widen rights.

v1 hop blocks are **nextKey attenuation**: signed by the token's
current nextKey, which the holder of the bytes has. That proves
monotonicity, not Identikey attribution. Identikey-signed hops
SHALL use Biscuit third-party blocks and are not v1.

### 7.4 Redemption is agency, not PRE

Redeeming a foreign secret SHALL be specified as an agency
operation on a Biscuit (`redeem` of a named secret), verified by
a tokenator that already holds the secret. Recrypt PRE SHALL
remain the layer for *our* ciphertext. A design that puts
Recrypt-protected data behind this tokenator, or that
PRE-transforms a GitHub PAT, SHALL be rejected.

The owner *could* Recrypt-encrypt a PAT to Z (plaintext in hand;
no GitHub participation). That is the wrong tier: PRE is durable
read with no per-use policy. Agency plus an online verifier gives
redeemable use with TTL/scope/log.

The verifier SHALL release the secret only to the party that
completed the holder proof, over a channel that delegation-path
intermediaries cannot read. Application profiles choose the
binding: host-local overlay where the holder is the socket peer
(Mjolnir v1), a transport authenticated to the holder key, or
sealing the response to a response key carried in the signed
holder proof.

### 7.5 Guild holder class is not v1

v1 SHALL bind a holder to one public key. Membership in a guild
or keyspace MAY be named as a future holder class. v1 SHALL NOT
require a membership lookup to accept a holder-bound token.

---

## 8. Out of scope

- Revocation sets / bloom filters (product; TTL + authority
  epoch cover the common case).
- Session types, process calculus, mailbox spool — those are
  Mjolnir communication, not this token.
- Recrypt PRE, field-scoped recryption, storage-auth envelope
  capabilities.
- Application profiles (Mjolnir login Datalog, tokenator, HTTP).
- Test vectors for **other** identity-tier specs — `ikp-6yz.2`.
  Capability fixtures live in
  `crates/identikey-capability/tests/fixtures/` (`ikp-6yz.4`).

---

## 9. What changed on 2026-08-26

Auth-challenge v1 §9 and §11, and the OIDC grant “not a
capability” line, pointed at Recrypt UCAN-style capabilities
“when needed.” That pointer is wrong for *agency*. Recrypt
keeps data-access capabilities. Agency is Biscuit.

## 10. What changed on 2026-09-10

§7 secret-redemption profile: holder is a **check** in the
token, never a `holder` fact; signed tuple is identity + nonce
+ audience; release is holder-bound; PRE is the wrong tier for
a PAT (Mjolnir `update-identikey-capability`, Fable accept).
