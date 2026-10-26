# Tasks

- [x] Fresh advise after preparation. Contract revised 2026-10-26 after reviews/2026-10-26-advise.md. The amend is design.md and specs/identikey-party/spec.md.
- [x] Amend `docs/standards/identikey-party-v1.md` with the sign-in ceremony, the explicit add, `excludeCredentials`, and `signalAllAcceptedCredentials`.
- [x] Adjust the one-line description in `docs/standards/README.md` so it mentions sign-in before a new passkey.

Owed from `reviews/2026-10-26-advise.md` (send-back):

- [x] R1: Require full WebAuthn assertion verification and a fresh, expiring, single-use ceremony/session challenge; bind the verified holder/userHandle, party, exact signed origin, and RP. Add rejection scenarios for replay, wrong origin/RP, another holder at the same host, and mismatched userHandle.
- [x] R2: Require server authorization and session binding when adding to an existing holder, distinguish first registration, and incorporate WebAuthn registration validation. Add rejection scenarios for unauthenticated existing-holder add and cross-holder/session completion on both add paths.
- [x] R3: Reconcile stable user.id with the same-vault second-passkey claim; document replacement behavior and a replacement scenario. Keep the explicit control, omitted exclusions, and distinct label; do not claim the random-user.id experiment proves two retained credentials with a stable id. Resolve any required handle-model change before act, including lookup and signal grouping.
- [x] R4: Define feature-detected browser signaling with encoded ids and a complete server-authorized accepted set; unsupported/rejected signaling preserves sign-in and never creates. Add unsupported/error and multi-credential completeness scenarios; a database read failure must not become an empty accepted set.

Out of scope, not owed here:

- The core page and database.
- The production 1Password check on `add-party-hosts`.
- URN grant, keyspaces, dual-certificate binding.
