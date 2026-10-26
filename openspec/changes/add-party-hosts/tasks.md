# Tasks

- [x] Astra advise on this change (protocol blast). Accept before act.
- [ ] Confirm 1Password stores distinct items for `alice.localhost` and `bob.localhost` (and for two production party hosts when a wildcard name is available). Record the result in the change. Revisit the dev parent if a manager collapses those relying party ids.
  - 2026-10-25 dev result, Duke, Chrome + 1Password: `http://alice.localhost:3000`, `http://bob.localhost:3000`, and `http://alice.localhost:4000` each saved a passkey. 1Password showed two websites, `alice.localhost` (`holder@alice.localhost`) and `bob.localhost` (`holder@bob.localhost`). The dev parent stays `.localhost`. The port-4000 ceremony did not join the first alice item. It created a second passkey with the same website and the same username, so the two alice passkeys cannot be told apart. The page calls `credentials.create` with `user.name` set to `holder@<host>`, so the port is not in the label. Production hosts are still unchecked.
- [x] Write `docs/standards/identikey-party-v1.md` from this change's design and delta. Copy the pinned OID arc, the binding order, and the 60-second skew.
- [x] Add the standard to the table in `docs/standards/README.md`.
- [x] Add a pointer in `docs/standards/identikey-oidc-urn-grant-v1.md` §7. Leave the WebAuthn rejection in §1 and §5 as it stands.
- [x] Name fixture hooks in the standard: party-host accept/reject labels, a dual-cert binding example, a boundary-present rejection, a chain that stops at the local anchor.

Out of scope, not owed here:

- identikey-core registry, ceremony routes, and CA implementation.
- Reputation-boundary evaluation and any parent above the local group.
- Filled signature test vectors beyond the hooks.

## Owed by advise — 2026-10-25

- [x] R1: Complete the X.509 claim/twin profile, custom extension OIDs and syntax, twin-required semantics, and boundary rejection on every applicable certificate including the configured anchor; add negative fixture hooks.
- [x] R2: Specify authenticated holder-to-subject-key enrollment binding, proof of possession or managed-custody authorization, replay/substitution rejection, and active-status recheck at issuance.
- [x] R3: Define allowed v1 CA path shapes, group versus signer identity, validation rules, and parent/self-signed anchor representations; add direct/intermediate/wrong-anchor scenario outcomes.
- [x] R4: Specify the supported TLS trust/chain presentation contract for public-browser ceremony and local-group HTTPS entry on the party origin.
- [x] Reconcile dual-hash prose with the sole five-step normalized-map construction and specify complete paired verification; add substitution and canonical-input fixture hooks.
- [x] Fresh advise after preparation. Contract revised again 2026-10-25 after reviews/2026-10-25-advise-2.md. The amend is `design.md` and `specs/identikey-party/spec.md` in this change.

## Owed by fresh advise — 2026-10-25

- [x] R2 follow-up: Pin the authenticated holder's authorized subject key and server-controlled nonce expiry in the pending enrollment; require equality at issuance and add first-submission K1/K2 substitution and expiry-extension rejection hooks. See reviews/2026-10-25-advise-2.md.
- [x] R1 follow-up: Reconcile holder validity encoding with RFC 5280 (UTCTime through 2049, GeneralizedTime from 2050), or explicitly specify an intentional non-PKIX profile; preserve Unix-second equality and add present-day and 2049/2050 transition hooks. See reviews/2026-10-25-advise-2.md.
