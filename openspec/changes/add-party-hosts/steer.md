# steer add-party-hosts

**When.** 2026-10-25
**Depth.** standard

## Decided
- Subdivision: auto — one WebAuthn relying party id per party hostname.
  The endpoint is one deployment. `rp.id` is the full party host.
- Issued object: user, Other — both a dCBOR party certificate and an
  X.509 certificate, one issuance, each committing to the other.
- Who may open a party: user, operator registry. An unregistered host
  does not run a ceremony and does not receive certificates.
- Authorities: user, Other — certificate authorities form a hierarchy
  and may later include shared reputation boundaries (smart-contract
  style). This version scopes trust to the local group. HTTPS on the
  party host is the entry into that group.

## Auto-logged
- Dev parent is `.localhost`. A port is not part of `rp.id`.
- Living file after activation: `docs/standards/identikey-party-v1.md`.
- The OIDC URN grant continues to reject a WebAuthn assertion.
- A `boundary` slot is reserved. v1 issuers omit it. v1 verifiers
  reject a certificate that carries it.
- Keyspaces are a different object. This change does not add a log kind.

## Skipped
None.

## Feeds change
Write `add-party-hosts` as the architecture change. A party is one
operator-registered DNS label. The ceremony origin is that host. The
local group CA issues the host's HTTPS certificate (the entry) and,
after passkey registration, a dual holder certificate (dCBOR + X.509)
binding an IdentiKey public key to that host. Verifiers trust the
configured local group anchor and do not walk above it. Reputation
and contract boundaries are a later profile on the reserved slot.
