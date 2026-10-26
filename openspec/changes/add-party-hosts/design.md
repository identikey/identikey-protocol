# add-party-hosts — design

## Context

WebAuthn's relying party id is a hostname. From a page, the id is the
page's host or a registrable suffix of it. A path, a port, and an
OAuth `client_id` are invisible to the authenticator and to 1Password.

`https://iro.id.vm.worldtree.network` is one relying party. Every
`localhost` port is the relying party `localhost`. Separate passkeys
require separate hosts. One binary can still serve them: wildcard DNS,
one certificate name pattern, Host-header routing.

IdentiKey already has two proofs, and they stay two proofs.

- A passkey proves "this authenticator is registered at this host."
- An identikey-auth response proves "this IdentiKey key signed this
  challenge." The OIDC URN grant accepts only the second. A party
  certificate does not replace that grant's XID-current-key check,
  pairwise `sub`, or signature verification.

This change adds the object that sits between them: a local group that
admits a host by a group-issued HTTPS certificate and a holder by a
dual certificate. A party certificate does not assert keyspace
membership or capability authority.

## Parties

A **party id** is one DNS label: LDH, lowercase, 1–63 characters, no
dots. The labels `www` and the empty label are not party ids.

A **deployment parent** is configuration.

- Production example: `id.vm.worldtree.network`
- Dev parent: `localhost`

The **party host** (and the WebAuthn `rp.id`) is `<party-id>.<parent>`.
A wildcard TLS certificate covers one label, so a party id is exactly
one label.

The **ceremony origin** is an exact origin string on the registration.
Production default is `https://<party-host>` with no port in the
string. Dev records the scheme and, when used, the port
(`http://alice.localhost:3000`). The port is part of the origin and
of an OIDC issuer URL. It is not part of `rp.id`. Two ports on
`alice.localhost` share one passkey. `alice.localhost` and
`bob.localhost` do not.

The endpoint accepts a ceremony only when the request's `Origin`
header equals the registered origin. Checking `rp.id` does not
replace that check.

`rp.name` is the registry display name. Password managers show it.
They file the item under `rp.id`.

## Operator registry

The deployment operator registers a party before that host serves a
ceremony or receives certificates. A registration is the party id,
a display name, the origin, and a status of `active` or `suspended`.

An unknown or suspended host is not a party. The endpoint does not
create a passkey there and the group CA does not issue for it.
Issuance reads the status again. A party suspended after the ceremony
and before issuance gets no certificate.

OAuth clients stay a separate list. A client id is not a party and
does not receive a relying party id.

Suspension blocks new ceremonies and new issuance. A certificate
already issued stays acceptable until its `exp`, plus the skew below.
v1 has no CRL and no OCSP. Reaching the deployment and seeing
`suspended` is not a revocation of an issued certificate.

## Local group and v1 paths

A **local group** has one P-256 issuer key. The public key is an
identikey-auth `PublicKey` (`alg` `p256`, 33-byte compressed SEC1).
The group id is `fingerprint(PublicKey)` from identikey-auth-challenge
v1 §5. That key is the only signer in v1.

The group's X.509 CA certificate is self-signed, `basicConstraints`
CA true, `keyCertSign` set, subject key the same P-256 point. The
verifier configures this certificate as its trust anchor. A
parent-signed certificate for the same key may exist later. v1 does
not configure that certificate as the anchor and does not walk to the
parent. The parent gains no authority.

v1 accepts exactly one path shape: **leaf → G**, where G is the
configured anchor and the leaf signature verifies under G's key.
`PartyCert.group` is the fingerprint of G, and the dCBOR signature
verifies under G. There is no second signer.

Rejected shapes:

- leaf → I → G (an intermediate below G)
- a chain whose trust anchor is not the configured G (an unrelated root)
- a chain that ends at a parent of G and does not use the configured
  anchor (parent-only trust)

X.509 path checks for the accepted shape follow RFC 5280 for a single
certificate under a trust anchor: signature, validity, CA constraints
and `keyCertSign` on G, leaf not a CA, extended key usage, name
constraints if any. Party checks are additional and are not supplied
by generic path validation. The verifier inspects the trust-anchor
certificate itself for the boundary OID. RFC 5280 §6.1 does not put
the trust anchor in the prospective path, so the profile checks it
explicitly.

Clock skew for party certificates is 60 seconds, chosen here:
`nbf - 60 <= now <= exp + 60`. Auth-challenge takes `skew_secs` as an
argument and does not fix this number.

## OID arc

Extension OIDs are children of the UUID OID (ITU-T X.667) for
`e2eddd01-be4d-5102-ae58-a42da06f2c7f`, the UUIDv5 of
`https://identikey.dev/standards/identikey-party-v1`.

```text
id-identikey-party              2.25.301640583953509932672957614958725508223
id-identikey-party-twin-sha256  {id-identikey-party}.1
id-identikey-party-boundary     {id-identikey-party}.2
id-identikey-party-credential   {id-identikey-party}.3
```

This standard is the assignment authority for these three arcs.
A later revision may add a sibling. It does not reuse these numbers
for a different meaning.

`id-identikey-party-twin-sha256`: critical. Value is an ASN.1
`OCTET STRING` of exactly 32 bytes, the raw SHA-256 digest. A second
copy, a wrong tag, or any other length fails verification.

`id-identikey-party-credential`: critical. Value is an ASN.1
`OCTET STRING` of 1 to 1023 bytes, the raw WebAuthn credential id.
A second copy, a wrong tag, or a length outside that range fails.

`id-identikey-party-boundary`: reserved. Any appearance of this OID,
on a host certificate, a holder certificate, an intermediate, or the
configured anchor, fails verification. Criticality does not matter.
The value does not matter, including empty. A second copy fails.
v1 issuers omit the OID. Generic "ignore unknown non-critical
extensions" does not apply to this OID.

## HTTPS entry and the public handshake

The live TLS handshake on the production party origin presents a
chain that ends at a public WebPKI anchor. That handshake makes the
origin a secure context for the ceremony. It does not prove
local-group membership. A verifier that trusts the public Web must
not treat that server certificate as a group entry.

The group entry is a separate server certificate issued by G:

- `dNSName` is the party host and no other
- extended key usage includes `serverAuth` and not `clientAuth`
- leaf is not a CA
- path is leaf → G
- the boundary OID is absent on the leaf and on G
- the twin-hash OID and the credential OID are absent

The deployment publishes that chain (leaf, then G) at:

```text
https://<party-host>/.well-known/identikey-party-entry
```

The body is the DER certificates concatenated in that order
(`application/pkcs7-mime` is not used). A group verifier fetches it
over the public handshake, then validates the published chain to the
configured anchor. The handshake certificate is transport only.

Dev origins on `*.localhost` may serve the ceremony without the
public chain. The same well-known path on the registered origin
publishes the group entry chain.

## Holder enrollment

Passkey registration does not choose the IdentiKey subject key. After
the ceremony, the authenticated holder submits the subject `PublicKey`
they want certified. The endpoint stores that key on the pending
enrollment as K1 and refuses to replace it. Only then does it issue a
nonce.

The nonce is at least 16 bytes, single-use, and bound to that pending
enrollment: party id, `rp.id`, origin, credential id, and K1. The
endpoint stores the nonce deadline. That deadline is the only expiry.
The holder returns `EnrollAuth`, signed by K1. `exp` in the map MUST
equal the stored deadline. A larger or smaller `exp` fails. Canonical
dCBOR, keys as in auth-challenge. The signature is 64-byte `r‖s` for
`p256`, or 64-byte Ed25519, over the canonical bytes of this map and
no other:

```text
EnrollAuth = {
  "v": 1,
  "domain": "identikey-party-enroll-v1",
  "party_id": tstr,
  "rp_id": tstr,
  "origin": tstr,
  "credential_id": bstr,
  "subject": PublicKey,
  "nonce": bstr,
  "exp": uint
}
```

`subject.alg` is `ed25519` or `p256`. The signed bytes are the
canonical dCBOR of `EnrollAuth`. The signature is carried beside the
map and is not a field inside it.

Issuance accepts the enrollment only when all of these hold:

- the party status is `active` at this moment
- the nonce is unused
- `exp` equals the deadline the endpoint stored when it issued the
  nonce, and `now` is inside that deadline under the 60-second skew
- `credential_id`, `party_id`, `rp_id`, `origin`, and `subject` equal
  the pending enrollment, including K1
- the signature verifies under K1

A first submission that signs a different subject, including a valid
signature under some K2, fails. A submission that extends `exp` fails.
A second submission of the same nonce, or a credential id from another
session, fails. The WebAuthn assertion is not this signature and is
not presented to the OIDC URN grant.

Managed custody may produce that signature only when the operator
already holds an authorization the URN grant would accept for a
managed claimant (A3 access or user A4). This standard names that
gate. It does not define the custody implementation.

## Holder certificate

One issuance produces two encodings of one holder credential. v1
holder verifiers require both. An X.509-only check is not a way to
read the credential id or the subject key binding.

Claims:

- group id = fingerprint of G
- party id and `rp.id`
- subject IdentiKey classical `PublicKey`
- WebAuthn credential id
- `nbf` and `exp` as Unix seconds

dCBOR map, canonical, exactly these keys:

```text
PartyCert = {
  "v": 1,
  "group": bstr,          ; 32-byte fingerprint of G
  "party_id": tstr,
  "rp_id": tstr,
  "subject": PublicKey,
  "credential_id": bstr,
  "x509_sha256": bstr,    ; 32 bytes
  "nbf": uint,
  "exp": uint
}
```

Unknown keys fail, including `boundary`. Non-canonical encoding fails.

The signed bytes are canonical dCBOR of:

```text
{
  "domain": "identikey-party-cert-v1",
  "cert": PartyCert
}
```

`PartyCertSig` is the wrapper `{ "cert": PartyCert, "sig": Signature }`
with `sig.alg` `p256` and `sig.sig` the 64-byte `r‖s`. The wrapper and
the signature bytes are not an input to either hash.

X.509 holder certificate, signed by G:

- version 3, leaf, not a CA
- subject public key matches `subject`:
  - `p256`: `id-ecPublicKey` and `prime256v1`. `subject.key` is the
    33-byte compressed SEC1 point. The SPKI bit string is the same
    point uncompressed (`0x04‖X‖Y`, 65 bytes), which is the RFC 5480
    form. The verifier decompresses and compares.
  - `ed25519`: RFC 8410. Both sides are the same 32 raw bytes.
- validity: `notBefore` and `notAfter` are whole seconds, Zulu, and
  mean the same Unix seconds as `nbf` and `exp`. Encoding follows
  RFC 5280 §4.1.2.5. A time before `2050-01-01T00:00:00Z` is UTCTime
  (`YYMMDDHHMMSSZ`). A time at or after that instant is GeneralizedTime
  (`YYYYMMDDHHMMSSZ`). The twin hash commits to whichever tag the DER
  actually uses. The C0 → X → C order does not change.
- extended key usage is `clientAuth` only
- subjectAltName URI, and no DNS name:

```text
urn:identikey:party:<rp-id>:<base58(fingerprint(subject))>
```

- critical `id-identikey-party-twin-sha256` = SHA-256(C0)
- critical `id-identikey-party-credential` = the credential id
- boundary OID absent

`party_id` is the first label of `rp_id`. The registry parent is the
remainder.

### Binding order

One order. C0 is the canonical dCBOR of `PartyCert` with
`x509_sha256` set to 32 zero bytes. X is the final signed DER. C is
the final `PartyCert`.

1. Build C0.
2. Set the twin extension to SHA-256(C0). Put the credential id in
   its extension. Sign the certificate under G. X is that DER.
3. Set `x509_sha256` to SHA-256(X). That map is C.
4. Sign canonical dCBOR of `{ "domain": "identikey-party-cert-v1", "cert": C }`
   under G.

X commits to the normalized claims. The signature over C commits to
the exact DER. No fixed point is required. The hash in X is not the
hash of `PartyCertSig` and not the hash of the signature.

Paired verification:

1. Decode C under the strict rules above. Verify the signature over
   the domain map under G. `group` equals fingerprint(G).
2. `x509_sha256` equals SHA-256 of the presented DER.
3. Rebuild C0 by writing 32 zero bytes into `x509_sha256` and
   re-encoding canonically. The twin extension equals SHA-256(C0).
4. Credential id, party id, `rp.id`, subject, `nbf`, and `exp` agree
   across the URI, the SPKI, the credential extension, and C.
5. Path and boundary rules above. Skew of 60 seconds.

A substituted DER, a substituted subject, or a non-canonical body
fails one of these steps.

## Ceremony

On an active party, and only when `Origin` equals the registered
origin, the endpoint calls WebAuthn with:

- `rp.id` = party host
- `rp.name` = registry display name
- `residentKey` / `requireResidentKey` required
- `authenticatorAttachment` unset
- `user.id` a stable opaque id for that holder inside that party
- `user.name` a human label the password manager can show

A second party is a second host and a second passkey. The ceremony
authorizes the session that enrollment must match. It is not the
certificate and it is not an identikey-auth `Response`.

## What stays put

- identikey-auth challenge/response, fingerprints, and `PublicKey`.
  The party signing domain is not an auth-challenge payload.
- The OIDC URN grant.
- Keyspaces. A local group is not a keyspace.

## Resolved in the 2026-10-25 amend

Astra send-back R1–R4 and the competing hash prose. OID numbers are
pinned here, not left for act. Intermediates below G are out of v1.
The public handshake and the group entry certificate are different
objects on the same name.
