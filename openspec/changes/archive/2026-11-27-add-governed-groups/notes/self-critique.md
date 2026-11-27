# Self-critique (author disclosure)

Written by the author session. Not a review and not a verdict.

Where I think this design is weakest:

1. **Witness time.** The expiry rule rests on the witness's clock. A
   witness can backdate a receipt to settle an expired entry. It still
   needs the owners' signatures, so this widens nothing a dishonest
   witness plus a stale approval could not already do before expiry
   existed. It does mean expiry protects only against an honest witness.
2. **Freeze has no stated way out.** Two settlement records at one
   sequence freeze the group at the predecessor. The design does not
   say whether an exit-receipted witness replacement can settle at that
   same sequence afterward. If it cannot, a witness that equivocates on
   two owner-approved entries ends the group.
3. **Acceptance stops at roster entries.** A `group.policy` entry can
   name a role in a rule for the first time. Its holders become
   governing with no acceptance signature and no proof their keys work.
4. **Founding needs every governing key.** With the 64-signature limit,
   a group cannot be founded with more than 64 governing keys. Later
   roster entries can add them. This is stated nowhere as a limit.
5. **ADR-013 decision 4.** I read "freshness and consume" as satisfied
   by the settled entry plus a head. That reading is mine. If consume
   must be a separate record per use of a grant, the grant section
   changes.
6. **H1 is unrun.** The whole approval model assumes `identikey-log`
   verifies several co-signatures by non-actor keys over one op.
7. **Member key assertion.** The log asserts that a key speaks for a
   member XID and never proves it. A relying party that maps a member
   to a person by XID trusts the admitting quorum for that link.
8. **Receipt time and replay.** Two bundles can carry different valid
   receipts for one entry with different times. State is the same.
   The monotonic time check can then pass in one bundle and fail in
   the other.
