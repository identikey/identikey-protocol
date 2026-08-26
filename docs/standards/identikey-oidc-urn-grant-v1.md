# IdentiKey — OIDC URN grant for identikey-auth v1

**Status:** Draft spec
**Date:** 2026-08-19
**Proof:** [`identikey-auth-challenge-v1.md`](identikey-auth-challenge-v1.md)
**Consumers:** `identikey-oidc` (AGPL product), any OP that projects
IdentiKey custody onto OAuth
**Does not implement:** the `Signer`. Wallet or managed-custody
operator, not this document.

---

## 1. Why this exists

`identikey-auth` is a self-verifying challenge/response. Ordinary
relying parties speak OAuth. This grant is the seam:

```
urn:identikey:params:oauth:grant-type:challenge-response
```

The same `Response` bytes work whether the **wallet** signed
(self-custody) or the **custody operator** signed with a managed key
(after an access credential). The OP verifies the proof and mints
standard tokens. It never holds a *user* private key to do that
verification.

A WebAuthn assertion MUST NOT satisfy this grant. WebAuthn proves
"I hold a passkey registered against an account." This grant proves
"I hold the IdentiKey key" (or: the operator who currently holds it
signed, under consent). Different column on the custody ladder.
Mixing them at `/token` is a release blocker (I2).

## 2. Roles

| Role | Does |
|---|---|
| **Verifier / OP** | Issues the `Challenge` (`aud` = this issuer). Verifies the `Response`. Mints OIDC tokens. |
| **Self-custody claimant** | Wallet `Signer`. User holds Sign. |
| **Managed claimant** | Custody operator `Signer` using `managed_key_blob`. Allowed only after A3 or user A4 authorised this use. |
| **RP** | Ordinary OAuth client. Receives `access_token` / `id_token` as today. |

The OP is the verifier of the `Response`. The RP is not. The RP
never has to parse dCBOR.

## 3. Flow

```
Claimant                         OP                              RP
  | -- GET /challenge ----------> |                               |
  | <---- Challenge (dCBOR) ----- |                               |
  |  sign (wallet or managed)     |                               |
  | -- POST /token (URN grant) -> |                               |
  | <---- TokenResponse --------- |                               |
  |                               |   (RP uses tokens as usual)   |
```

PKCE does not apply (there is no `/authorize` redirect on this
grant). Confidential-client authentication at `/token` still applies
when the RP is confidential.

Managed browser login to the OP (user in front of a website) is
**not** this grant. That is authorization-code + PKCE, with A3
passkeys (or a flag-gated dev login) completing `/authorize`. The
operator may still sign an identikey-auth `Response` *for other
audiences* after that session; this grant is how a claimant who can
sign presents the proof *as* the token request.

## 4. Challenge issuance

`GET` or `POST` `{issuer}/challenge`

The OP is the identikey-auth verifier. It MUST pick the nonce
(never the claimant). `aud` MUST be this OP's issuer identifier
(the discovery `issuer`). `exp` is short-lived (minutes, not hours).

Response body: the canonical dCBOR `Challenge` bytes,
`Content-Type: application/cbor`.

## 5. Token request

```
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:identikey:params:oauth:grant-type:challenge-response
&response={base64url(Response bytes)}
&client_id=…
```

`response` is unpadded base64url of the canonical dCBOR `Response`.
Client authentication is whatever this client registered
(`none` / `client_secret_basic` / `client_secret_post`). A WebAuthn
assertion in `response` (or any body that is not a v1 `Response`)
MUST fail as `invalid_grant` with no tokens.

The OP MUST:

1. Decode and `verify_response` per the challenge spec, with
   `aud` = this issuer.
2. Bind `fingerprint(pub)` to a stored XID via the published XID
   document (the public key must currently be on that document).
3. Compute `sub` through the single pairwise seam. Never a second
   `sub` formula.
4. Mark the nonce used. Replay is `invalid_grant`.

`identikey-oidc` MUST NOT load a user private key to perform these
steps. Managed signing, when it happens, happens in `identikey-keys`
behind the access-credential gate, then the resulting `Response` is
verified here like any other.

## 6. Discovery

`grant_types_supported` includes this URN in addition to
`authorization_code` and `refresh_token`. It still MUST NOT include
`password` or implicit.

## 7. What this spec is not

- Not WebAuthn, not passkeys, not `/authorize`.
- Not a capability envelope. Agency tokens are Biscuit
  ([`identikey-capability-v1.md`](identikey-capability-v1.md)). Recrypt
  storage-auth envelopes stay data-access, not this grant.
- Not a requirement that every RP speak dCBOR.
- Not a required OIDF profile. Basic OP remains authorization-code.
