# Tasks

Owed by this architecture activation (`nod-keyspace-architecture`) only:

- [x] `openspec/changes/add-keyspace-spec` proposal, design, deltas
- [x] Independent architecture read (advise; reader Grok 4.6)
- [x] Name which kind is genesis: first `keyspace.join` that installs admin+PTK, or `keyspace.nest` for inner, or an eighth kind (advise 2026-09-01)
- [x] State identikey-log actors are Ed25519; P-256 is wrap-target only this landing (advise 2026-09-01)
- [x] Name how admin-ness is carried on `join` / `change` roster bodies (advise 2026-09-01)
- [x] `docs/standards/identikey-keyspace-v1.md` + README row (act after advise accept)

Not owed here (bullets, not boxes):

- Filled byte test vectors — `ikp-6yz.2` pattern
- Runtime wrap/join/leave/rotate — `add-keyspace-runtime` (identikey-core)
- Access-node inner wrap — `identikey-core-trr.2`
- Lightning Admin v2 verbs — `add-lightning-admin-guild`
- Wallet `"keyspace-membership"` assertion
- `openspec/specs/` living tree in this repo
