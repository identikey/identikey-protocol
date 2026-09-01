# add-keyspace-spec

> **ACTIVE BUILD**

**Rigor:** architecture

Steer residue is on `ikp-cvu` (2026-08-31 / 2026-09-01). This is the
protocol-tier architecture node. identikey-core `add-guild-keyspaces`
out-of-scopes this file. Runtime wrap/rotate stays in identikey-keys.

## Why

Several identikeys need to hold keys in one space. Recrypt is data
access. Biscuit is agency. XID is who-I-am. None of those is a shared
keyspace. FOKS-the-product (servers, `user@host`) is not the identity
plane. Without this spec, mesh "guild" talk and identikey-core
architecture have no implementable wire.

## What

- ADD capability `identikey-keyspace`. Protocol word is **keyspace**.
  Lightning Mesh product word is **guild**. One object, two words (D5).
- Living file after act: `docs/standards/identikey-keyspace-v1.md`.
  This repo's spec surface is `docs/standards/`, not `openspec/specs/`.
  This change packet lives under `openspec/changes/` so advise/run can
  see a banner. Fold does not create `openspec/specs/identikey-keyspace/`.
- Wire from steer plus advise 2026-09-01 amend: genesis `content_hash`
  as id (outer = first admin `join`, inner = `nest`); seven `keyspace.*`
  kinds; Ed25519 log actor, P-256 wrap-target only; `admin` boolean on
  roster entries; self-describing CBOR wraps; device cascade named, not
  specified as objects; two named profiles (house/buyer, access-node).
- Test-vector hooks this landing. Filled byte fixtures are not owed.
- Act 2026-09-01: `docs/standards/identikey-keyspace-v1.md` landed.

Capabilities: `identikey-keyspace` (ADDED). `identikey-log` is not
modified (kind strings stay open). Auth-challenge and capability-v1
are not modified (three layers stay uncollapsed).

## Impact

- Capabilities: ADDED `identikey-keyspace` (standards doc, not a crate)
- ADRs: none in this repo (core ADR-012 is the product architecture)

## User journey & surfaces

No new UI because this node specifies a protocol-tier document.
Implementers read `docs/standards/`. Ops ride existing `identikey-log`.

Intended path, for later act: a holder appends `keyspace.*` ops; peers
verify signatures and apply wrap-lists; a nested access-node keyspace
is a genesis op of its own, referenced by hash. Lightning Admin and
hello.mesh are other repos.

## Out of scope

- FOKS servers, `user@host`, encrypted git, FOKS KV
- Recrypt as keyspace identity (`mjolnir-mesh-6t7` stays deferred)
- Biscuit as membership (`identikey-capability-v1` stays agency)
- OIDC claim named `guilds`
- Wallet `"keyspace-membership"` (later non-authoritative pointer)
- `rename` verb
- HPKE; PQ wrap
- Device-key objects on the keyspace log
- Filled byte test vectors (`ikp-6yz.2` pattern; hooks only here)
- Runtime wrap/rotate crate (`add-keyspace-runtime` in identikey-core)
- Access-node wrap runtime (`identikey-core-trr.2`)
- Lightning Admin v2 (`add-lightning-admin-guild`)
- `openspec/specs/` living tree in this repo
