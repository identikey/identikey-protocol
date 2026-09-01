# steer add-keyspace-spec

**When.** 2026-09-01
**Depth.** standard

## Decided
- Wrap: Other (user) — self-describing wrap; data is CBOR; standardize
  that map. v1 tags pair to identity keys: `x25519-xchacha20poly1305`
  and `p256-xchacha20poly1305`. No HPKE. No PQ wrap this landing.
- Keyspace id: genesis content hash (user, recommended). Nested
  keyspace id = inner genesis hash. No second identifier.
- Op catalog: seven kinds, leave distinct (user, recommended).
  Kick/blacklist/admin-grant/wrap-list are fields, not kinds.
- Device layer: cascade rule only (user, recommended).

## Auto-logged
- Spec path `docs/standards/identikey-keyspace-v1.md`. No
  `openspec/specs/` living tree. Capability `identikey-keyspace`.
- One spec, two named profiles.
- Test-vector hooks this landing; filled fixtures not owed.
- Wallet `"keyspace-membership"` stays out.

## Skipped
None.

## Feeds change
Write `add-keyspace-spec` as the architecture change for this protocol
landing. The living file is the standards doc. Wire: genesis
`content_hash` as id; seven `keyspace.*` kinds; CBOR self-describing
wraps; device cascade named, not specified as objects.

## Amend 2026-09-01 (advise send-back)
- Outer genesis = first `keyspace.join` with admin+PTK. Inner genesis =
  `keyspace.nest`. No eighth kind.
- Log actor Ed25519 only. P-256 wrap-target only.
- Roster entries carry `admin` boolean.
