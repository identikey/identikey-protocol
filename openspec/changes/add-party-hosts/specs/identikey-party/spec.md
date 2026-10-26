## ADDED Requirements

### Requirement: Party host
A party id SHALL be a single lowercase LDH DNS label of 1 to 63
characters. The labels `www` and empty SHALL NOT be party ids. The
party host SHALL be `<party-id>.<deployment-parent>`. The WebAuthn
relying party id SHALL be that party host. A port, a path, and an
OAuth client id SHALL NOT change the relying party id. The endpoint
SHALL accept a ceremony only when the request `Origin` equals the
origin recorded for that party.

#### Scenario: Two parties on one endpoint
- GIVEN a deployment whose parent is `id.vm.worldtree.network`
- AND the operator has registered parties `alice` and `bob` at origins `https://alice.id.vm.worldtree.network` and `https://bob.id.vm.worldtree.network`
- WHEN a user registers a passkey on each origin
- THEN the relying party ids are `alice.id.vm.worldtree.network` and `bob.id.vm.worldtree.network`
- AND a password manager files them as two items

#### Scenario: Dev hosts share a port and not a label
- GIVEN a deployment whose parent is `localhost`
- AND `alice` is registered at `http://alice.localhost:3000` and at no other origin
- WHEN ceremonies are attempted at `http://alice.localhost:3000`, `http://alice.localhost:4000`, and `http://bob.localhost:3000` with `bob` registered at that origin
- THEN the first origin is accepted with relying party id `alice.localhost`
- AND the second origin is rejected
- AND the third uses relying party id `bob.localhost`

#### Scenario: Reject a dotted party id
- GIVEN a requested party id `a.b`
- WHEN the operator registry considers it
- THEN registration fails
- AND no ceremony is served for it

### Requirement: Operator registry
The deployment SHALL serve a ceremony and SHALL issue certificates
only for a party the operator has registered with status `active`.
Status SHALL be read again at issuance. An unknown host and a
`suspended` party SHALL receive neither a ceremony nor a new
certificate. An already issued certificate SHALL remain acceptable
until `exp` under the 60-second skew rule. Suspension SHALL NOT
revoke it. v1 SHALL NOT require CRL or OCSP.

#### Scenario: Unknown host
- GIVEN no registration for party id `carol`
- WHEN a client opens `https://carol.id.vm.worldtree.network`
- THEN the endpoint does not start a WebAuthn registration
- AND the group CA issues no certificate for that host

#### Scenario: Suspended between ceremony and issuance
- GIVEN an active party whose passkey ceremony has completed
- AND the operator sets the party to `suspended` before issuance
- WHEN issuance runs
- THEN no holder certificate is issued

#### Scenario: OAuth client is not a party
- GIVEN a registered OAuth client id
- WHEN that client is used as an OIDC relying party
- THEN the WebAuthn relying party id remains the party host of the ceremony
- AND the client id is not written into `rp.id`

### Requirement: Ceremony parameters
On an active party whose `Origin` matches, the ceremony SHALL set
`rp.id` to the party host and `rp.name` to the registered display
name. It SHALL require a resident key and SHALL leave authenticator
attachment unset. `user.id` SHALL be stable for that holder inside
that party.

#### Scenario: Synced authenticator
- GIVEN an active party and a matching Origin
- WHEN the endpoint builds the registration request
- THEN resident key is required
- AND authenticator attachment is absent
- AND a password manager can complete registration

### Requirement: Local group anchor
A local group SHALL have one P-256 issuer key. The group id SHALL be
the identikey-auth fingerprint of that public key. The v1 trust anchor
SHALL be the self-signed CA certificate of that key. A verifier SHALL
accept only the path leaf → G for that configured anchor. It SHALL
reject leaf → intermediate → G, a chain anchored at an unrelated root,
and a chain that trusts only a parent of G. `PartyCert.group` SHALL be
the fingerprint of G, and the dCBOR signature SHALL verify under G.
Party validity SHALL accept `now` when `nbf - 60 <= now <= exp + 60`.

#### Scenario: Direct path
- GIVEN verifier anchor G
- AND a holder certificate signed by G with `group` equal to fingerprint(G)
- WHEN the path is built
- THEN the path leaf → G is accepted
- AND the dCBOR signature verifies under G

#### Scenario: Intermediate below the anchor
- GIVEN a chain leaf → I → G
- WHEN a v1 verifier builds the path
- THEN verification fails

#### Scenario: Wrong anchor
- GIVEN a certificate signed by an unrelated root R
- WHEN a verifier configured with G checks it
- THEN verification fails

#### Scenario: Parent-only trust
- GIVEN a certificate signed by parent P of G
- AND the verifier is configured with G, not with P
- WHEN the path is built
- THEN verification fails
- AND P is not an additional trust anchor

### Requirement: HTTPS entry
The live TLS handshake on a production party origin SHALL present a
chain that ends at a public WebPKI anchor. That handshake SHALL
establish a secure context and SHALL NOT establish local-group
membership. The group CA SHALL issue a server certificate whose only
DNS name is the party host, whose extended key usage includes
serverAuth, and whose path is leaf → G. The deployment SHALL publish
that chain, leaf then G, as concatenated DER at
`/.well-known/identikey-party-entry` on the party origin. A group
verifier SHALL validate the published chain to G. The boundary OID
SHALL be absent on that leaf and on G. The twin-hash and credential
OIDs SHALL be absent on that leaf.

#### Scenario: Browser ceremony
- GIVEN `https://alice.id.vm.worldtree.network`
- WHEN a browser completes the TLS handshake
- THEN the presented chain ends at a public WebPKI anchor
- AND the connection is a secure context
- AND the handshake certificate is not a local-group entry

#### Scenario: Group verifier entry
- GIVEN the same origin
- AND `/.well-known/identikey-party-entry` returns a server certificate for that DNS name signed by G, then G
- WHEN a verifier configured with G validates the published chain
- THEN the published certificate is the HTTPS entry of the local group
- AND the handshake certificate is transport only

### Requirement: Enrollment binding
After the ceremony the authenticated holder SHALL submit one subject
`PublicKey`. The endpoint SHALL store it as K1 on the pending
enrollment and SHALL NOT replace it. The endpoint SHALL then issue a
nonce of at least 16 bytes and SHALL store that nonce's deadline.
Issuance SHALL require `EnrollAuth` signed by K1 over the domain
`identikey-party-enroll-v1`, covering party id, relying party id,
origin, credential id, subject public key, the nonce, and `exp`.
`subject` SHALL equal K1. `exp` SHALL equal the stored deadline.
The endpoint SHALL reject a different subject, an `exp` the holder
changed, nonce reuse, and a credential id from another session.
Party status SHALL be `active` at issuance. A managed operator MAY sign `EnrollAuth` only
under the managed-claimant gate the OIDC URN grant already names.
The WebAuthn assertion SHALL NOT be this proof and SHALL NOT satisfy
the URN grant. A party certificate SHALL NOT replace the grant's
XID-current-key check, pairwise `sub`, or signature verification, and
SHALL NOT assert keyspace membership or capability authority.

#### Scenario: First submission matches the pinned key
- GIVEN a pending enrollment whose pinned subject is K1 and whose stored nonce deadline is T
- WHEN the first `EnrollAuth` is signed by K1, names K1, and sets `exp` to T
- THEN the subject check passes

#### Scenario: Subject substitution
- GIVEN a pending enrollment whose pinned subject is K1
- WHEN the first `EnrollAuth` is a valid signature under K2 and names K2
- THEN issuance fails

#### Scenario: Extended expiry
- GIVEN a pending enrollment whose stored nonce deadline is T
- WHEN `EnrollAuth` is otherwise valid and sets `exp` to a time after T
- THEN issuance fails

#### Scenario: Replay
- GIVEN a nonce already consumed by an issuance
- WHEN a second `EnrollAuth` presents that nonce
- THEN issuance fails

#### Scenario: Passkey is not an auth-challenge response
- GIVEN only a WebAuthn assertion from the party ceremony
- WHEN a client presents that assertion to the OIDC URN grant
- THEN the grant rejects it
- AND no tokens are issued

### Requirement: Dual holder certificate
After a successful enrollment on an active party, the group CA SHALL
issue one holder credential as a dCBOR `PartyCert` and an X.509 client
certificate. Holder verification SHALL require both. The signature
SHALL cover canonical dCBOR of
`{ "domain": "identikey-party-cert-v1", "cert": PartyCert }`
and SHALL verify under G.

The X.509 certificate SHALL use the subject public key that matches
`subject` (compressed SEC1 P-256 in the IdentiKey key, uncompressed
SPKI point; Ed25519 raw 32 bytes on both sides), validity times that
mean the same Unix seconds as `nbf` and `exp`, encoded as UTCTime
before `2050-01-01T00:00:00Z` and as GeneralizedTime at or after that
instant (RFC 5280 §4.1.2.5), extended key usage `clientAuth`
only, and the SAN URI
`urn:identikey:party:<rp-id>:<base58(fingerprint(subject))>`.

OID `2.25.301640583953509932672957614958725508223.1` SHALL be critical
and SHALL carry an OCTET STRING of the 32-byte SHA-256 of C0, where
C0 is canonical dCBOR of `PartyCert` with `x509_sha256` set to 32 zero
bytes. OID `2.25.301640583953509932672957614958725508223.3` SHALL be
critical and SHALL carry an OCTET STRING of the 1-to-1023-byte
credential id. A duplicate, a wrong tag, or a wrong length SHALL fail
verification. `x509_sha256` in the signed `PartyCert` SHALL be the
SHA-256 of the final DER. The wrapper `PartyCertSig` SHALL NOT be an
input to either hash.

#### Scenario: Twin hashes match
- GIVEN a completed issuance
- WHEN a verifier holds the `PartyCert` and the X.509 DER
- THEN the domain-map signature verifies under G
- AND `x509_sha256` equals SHA-256 of the DER
- AND the twin extension equals SHA-256 of the `PartyCert` map with `x509_sha256` set to 32 zero bytes
- AND the subject, party host, validity, and credential id agree across both encodings

#### Scenario: Substituted certificate
- GIVEN a `PartyCert` signed for DER X1
- WHEN a verifier is shown a different DER X2
- THEN verification fails

#### Scenario: Present-day validity uses UTCTime
- GIVEN `nbf` and `exp` both before `2050-01-01T00:00:00Z`
- WHEN the holder certificate is issued
- THEN `notBefore` and `notAfter` are UTCTime
- AND they mean the same Unix seconds as `nbf` and `exp`

#### Scenario: Validity crosses into 2050
- GIVEN `nbf` is `2049-12-31T23:59:59Z` and `exp` is `2050-01-01T00:00:00Z`
- WHEN the holder certificate is issued
- THEN `notBefore` is UTCTime and `notAfter` is GeneralizedTime
- AND the C0 → X → C binding order is unchanged

#### Scenario: Non-canonical body
- GIVEN `PartyCert` bytes that are not canonical dCBOR
- WHEN a verifier decodes them
- THEN verification fails

### Requirement: Reserved boundary
OID `2.25.301640583953509932672957614958725508223.2` is the boundary
slot. v1 issuers SHALL omit it. v1 verifiers SHALL reject a host
certificate, a holder certificate, an intermediate, or the configured
anchor certificate that contains this OID, at either criticality,
including an empty value. Unknown other non-critical extensions follow
RFC 5280. This OID does not. Reputation sets and contract-limited
issuance are a later profile on this slot.

#### Scenario: Boundary present on the leaf
- GIVEN a holder certificate that contains the boundary OID as a non-critical extension
- WHEN a v1 verifier checks it
- THEN verification fails

#### Scenario: Boundary present on the anchor
- GIVEN a configured anchor certificate that contains the boundary OID as a critical extension
- WHEN a v1 verifier checks the anchor itself
- THEN verification fails

### Requirement: Living document
Act SHALL publish this capability as
`docs/standards/identikey-party-v1.md` and SHALL list it in
`docs/standards/README.md`. Fold SHALL NOT create
`openspec/specs/identikey-party/`.

#### Scenario: Standard is readable without this change folder
- GIVEN act has landed
- WHEN an implementer opens `docs/standards/`
- THEN `identikey-party-v1.md` states the host rule, the registry rule, the enrollment binding, the dual certificate, the OID arc, the direct path to the local anchor, the well-known HTTPS entry, and the reserved boundary
