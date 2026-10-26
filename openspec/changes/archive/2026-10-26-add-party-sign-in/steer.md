# steer add-party-sign-in

**When.** 2026-10-26
**Depth.** standard

## Decided
- Where the flow lives: user, amend `identikey-party-v1` in this repo.
  A core page that performs the calls is a later bead.

## Auto-logged
- Sign-in is `credentials.get` for the party host.
- A new passkey is a separate control.
- Ordinary add passes `excludeCredentials`.
- A second passkey in the same vault omits `excludeCredentials` and uses a distinct `user.name`.
- The database of credential ids is the list that counts.
- The passkey still does not satisfy the OIDC URN grant.

## Skipped
None.

## Feeds change
Write `add-party-sign-in` as an amendment to the party standard.
Source of the flow is bead ikp-hdj. Banner stays PENDING until a grant.
