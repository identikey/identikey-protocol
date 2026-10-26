# add-party-sign-in — design

## Context

`identikey-party-v1` §4 sets `rp.id` to the party host and requires a
resident key and a stable `user.id` per holder per party. The test page
behind `e81dfd7` called `credentials.create` with a new random `user.id`
each time. That observation shows 1Password files by hostname. It does
not show that one stable `user.id` keeps two passkeys in one vault.
WebAuthn maps a discoverable credential by relying party id and user
handle, and an authenticator keeps at most one for that pair.
Re-registration can replace the previous credential on that
authenticator. `user.name` is only the label.

The browser will not list the vault. Each accepted passkey is a row:
party host, credential id, stable `user.id`, COSE public key, and the
`user.name` that was shown.

## Sign-in

On an active party, and only when the request `Origin` equals the
registered origin, sign-in is `credentials.get` with `rpId` equal to
the party host.

The server issues a challenge of at least 16 bytes, single-use,
expiring, and bound to this ceremony and this party. The same 60-second
skew used for party certificates applies to that expiry. The enrollment
nonce in §5 is a later proof. It does not protect this assertion.

- The holder is known. `allowCredentials` is the credential ids stored
  for that holder at this party host.
- The holder is unknown. The allow list is empty. The password manager
  shows discoverable passkeys for this hostname. Both ports of one host
  show that list.

The server accepts the assertion only after WebAuthn assertion
verification (WebAuthn Level 3, verifying an authentication assertion):
client-data type `webauthn.get`, challenge, and origin; `rpIdHash`;
user presence and the verification flag the ceremony required;
signature over the stored public key; and, when a holder was named,
the credential id is one of that holder's. The returned user handle
must be the stable `user.id` stored for that credential. The signed
origin must equal the registered origin. The party must still be
`active`. The session binds that verified holder.

A replayed assertion, a signature over a different challenge, a wrong
origin or relying party, another holder's credential at the same host,
or a user handle that does not match the stored id fails. The client
allow list is not this check.

`NotAllowedError` leaves the person on the page. It does not mean the
vault is empty. It does not call `credentials.create`.

## Add

`credentials.create` runs only from an add control. The server verifies
the registration (WebAuthn Level 3, registering a new credential)
before storing a row. A client-submitted credential id and public key,
without that verification, are not a row.

First registration creates the holder and that holder's stable
`user.id`. There is no prior session.

Adding to an existing holder requires a server session already
authorized for that holder and this party. The pending registration,
its challenge, and its completion are bound to that session. A caller
who only names the holder does not get to attach a passkey. Completion
under a different holder or a different session fails. This gate covers
both the ordinary add and the same-vault control.

Every add uses the holder's stable `user.id`. `user.name` differs from
the names already stored for that holder on that party, so the new row
has a readable label. The label does not create a second user handle.

The ordinary add passes `excludeCredentials` with the stored ids. An
authenticator that already holds one of those ids does not create
another. A different authenticator can still create one for the same
user handle. Both can stay in the accepted set.

The control that means "save another in this vault" omits
`excludeCredentials` and still sends a distinct `user.name`. The
supported outcome is a new credential id under the same user handle, or
a replacement of the credential that authenticator already held for
that handle. The standard does not promise two retained passkeys in one
vault for one user handle. The server stores the new credential id
under the holder. It does not drop other accepted ids, because another
authenticator may still hold them. It does not assume the previous id
is still on the authenticator that just registered.

## After sign-in

Sign-in succeeds before any signal. The server gives the page the
complete accepted set for that authenticated holder and party host.
The page calls `PublicKeyCredential.signalAllAcceptedCredentials` only
when the function exists. `rpId` is the party host. `userId` is the
base64url of the stable user-id bytes. Each credential id is base64url
of the raw id. The list is every accepted id, not only the one just used.

A missing function, a rejected call, or a vault that does not update
leaves the sign-in in place and does not call `credentials.create`. A
failed read of the accepted set does not call the function with an
empty list. A successful call is not proof that every vault updated.

## What stays put

The passkey still only authorizes the party session. Enrollment still
pins K1 and uses its own nonce. The passkey does not satisfy the OIDC
URN grant, does not choose the IdentiKey subject key, and does not
revoke a certificate. Host grammar, the registry, the dual certificate,
and the local-group anchor are unchanged.
