## ADDED Requirements

### Requirement: Stored passkey
The endpoint SHALL store, for each passkey it accepts, the party host, the credential id, the holder's stable user id, the COSE public key, and the user.name shown to the password manager. It SHALL store a row only after WebAuthn registration verification succeeds.

#### Scenario: Row recorded at creation
- GIVEN a successful verified add for a holder on a party host
- WHEN the endpoint accepts the new credential
- THEN it stores that credential id under that holder and party host

#### Scenario: Unverified client row
- GIVEN a client submits a credential id and public key without a verified registration ceremony
- WHEN the endpoint considers storing it
- THEN no row is stored

### Requirement: Sign-in uses a stored passkey
On an active party whose request Origin equals the registered origin, sign-in SHALL call `credentials.get` with `rpId` equal to the party host. The server SHALL issue a challenge of at least 16 bytes, single-use and expiring, bound to this ceremony and this party. When the holder is known, `allowCredentials` SHALL be the credential ids stored for that holder at that host. When the holder is unknown, the allow list SHALL be empty. The server SHALL accept the assertion only after WebAuthn assertion verification: the challenge and signed origin match this ceremony and the registered origin, the relying party matches the party host, the signature matches the stored public key, and the user handle is the stable user id stored for that credential. When a holder was named, the credential id SHALL be one of that holder's. The session SHALL bind that verified holder. `NotAllowedError` SHALL leave the person on the page and SHALL NOT call `credentials.create`.

#### Scenario: Known holder
- GIVEN holder H has credential ids C1 and C2 stored for party host `alice.localhost`
- WHEN H signs in on the registered origin for that host
- THEN `credentials.get` uses relying party id `alice.localhost` and allow list C1, C2
- AND a verified assertion for one of those ids starts a session bound to H

#### Scenario: Unknown holder
- GIVEN no holder has been named
- WHEN sign-in runs on the party origin
- THEN `credentials.get` uses an empty allow list
- AND the server rejects a credential id that is not stored for this party host

#### Scenario: Replay
- GIVEN a challenge already consumed by a successful sign-in
- WHEN a client presents the same signed assertion again
- THEN sign-in fails

#### Scenario: Wrong origin
- GIVEN the registered origin is `https://alice.id.vm.worldtree.network`
- WHEN the assertion's client data origin is a different origin
- THEN sign-in fails

#### Scenario: Another holder
- GIVEN credential C belongs to holder H2 at this party host
- WHEN a ceremony named holder H1 presents a valid assertion for C
- THEN sign-in fails
- AND the session does not bind H1

#### Scenario: Mismatched user handle
- GIVEN credential C is stored with stable user id U
- WHEN the assertion verifies but the user handle is not U
- THEN sign-in fails

#### Scenario: Cancel does not create
- GIVEN `credentials.get` fails with `NotAllowedError`
- WHEN the page handles that error
- THEN no `credentials.create` call is made

### Requirement: Add is explicit
`credentials.create` SHALL run only from an add control. First registration SHALL create the holder and that holder's stable user id. Adding to an existing holder SHALL require a server session already authorized for that holder and this party, and the pending registration and its completion SHALL be bound to that session. An unnamed or unauthenticated request SHALL NOT attach a credential to an existing holder. Completion for a different holder or a different session SHALL fail. Both the ordinary add and the same-vault control SHALL use this gate. Every add SHALL use the holder's stable user id and a user.name that differs from the names already stored for that holder on that party. The ordinary add SHALL pass `excludeCredentials` containing the stored credential ids. The control for another passkey in the same vault SHALL omit `excludeCredentials`. A successful registration under an existing user id SHALL store the new credential id and SHALL NOT remove other accepted ids. The standard SHALL NOT require one vault to retain two passkeys for one user handle. An authenticator MAY replace its previous discoverable credential for that handle.

#### Scenario: Ordinary add refuses a duplicate on the same authenticator
- GIVEN holder H already has credential id C stored for this party host
- AND H has an authorized session for this party
- WHEN H uses the ordinary add control
- THEN `credentials.create` includes C in `excludeCredentials`
- AND the user.id is H's stable id
- AND the user.name differs from the stored name for C

#### Scenario: Same-vault control may replace
- GIVEN holder H has credential C1 under stable user id U on an authenticator
- AND H has an authorized session for this party
- WHEN H uses the same-vault control and that authenticator returns a new credential C2 for user handle U and no longer presents C1
- THEN the server stores C2 under H
- AND the server does not delete other accepted ids solely because C2 was created
- AND the user.name on C2 differs from the name stored for C1

#### Scenario: Unauthenticated add
- GIVEN holder H already exists on this party
- WHEN a client calls the add control with no session authorized for H
- THEN no credential is attached to H

#### Scenario: Cross-session completion
- GIVEN a pending registration bound to holder H's session S1
- WHEN a completion arrives on session S2 or for holder H2
- THEN the completion fails
- AND no row is stored

### Requirement: Accepted credentials are signaled
After a successful sign-in the server SHALL supply the complete set of credential ids it still accepts for that holder at that party host. The page SHALL call `PublicKeyCredential.signalAllAcceptedCredentials` when that function exists, with the party host, the base64url stable user id, and the base64url form of every id in that set. A missing function, a rejected call, or a vault that does not update SHALL leave the sign-in in place and SHALL NOT call `credentials.create`. A failed read of the accepted set SHALL NOT call the function with an empty list. A successful call SHALL NOT be treated as proof that every vault updated.

#### Scenario: Signal lists every accepted id
- GIVEN the database accepts C1 and C2 for holder H at this party host
- WHEN sign-in with C1 succeeds and the browser provides the signal function
- THEN the call includes both C1 and C2

#### Scenario: Signal unsupported
- GIVEN sign-in succeeded
- AND the browser has no `signalAllAcceptedCredentials`
- WHEN the page finishes sign-in
- THEN the session remains
- AND no `credentials.create` call is made

#### Scenario: Database read failure
- GIVEN sign-in succeeded
- AND the read of the accepted set fails
- WHEN the page would signal
- THEN it does not call the function with an empty list

### Requirement: Passkey still is not the grant
A successful sign-in SHALL authorize only the party session. It SHALL NOT satisfy the OIDC URN grant, SHALL NOT choose the IdentiKey subject key, and SHALL NOT revoke a party certificate.

#### Scenario: Assertion is not an auth-challenge response
- GIVEN only a WebAuthn assertion from party sign-in
- WHEN a client presents that assertion to the OIDC URN grant
- THEN the grant rejects it
