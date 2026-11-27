# Spike H1: a group verifier on `identikey-log`, with no crate change

Change: `openspec/changes/add-governed-groups`. Run 2026-11-27.

## Verdict

**go.** A group entry can be an `identikey-log` op with several Ed25519
signatures by different keys, and a group verifier can attribute and
check each one without a change to the crate's library code.

- spike-artifact: `crates/identikey-log/tests/cosign.rs` (11 tests, all pass)
- confidence: high
- verification: empirically-tested
- command: `cargo test -p identikey-log --test cosign`

The one change to the crate is a test-only dependency on
`ed25519-dalek`, already in the workspace. The library and its public
API are untouched.

## The claim, part by part

| Claim | Result | Test |
|---|---|---|
| `counter_sign` attaches signatures by keys other than `Op.actor`, over the same digest | Holds. Each verifies under its own key and under no other. | `each_co_signature_verifies_under_its_own_key_and_no_other` |
| The actor need not sign at all, as far as the crate is concerned | Holds. Two non-actor keys alone produce a decodable signed op. A group verifier adds the rule that the proposer signs. | `two_non_actor_keys_alone_can_sign_an_op` |
| The generic `verify` rejects a co-signed op | Holds, with `BadSignature`, from both `verify` and `decode_and_verify`. | `the_generic_verifier_rejects_a_co_signed_op` |
| The entry hash and the sign digest are different values | Holds. Co-signing moves neither. A signature over the entry hash does not verify over the sign digest. | `the_sign_digest_is_not_the_entry_hash` |
| `signatures_of` returns signatures in wire order | Holds. Wire order is ascending assertion digest, not signing order. The same three signers in two orders give identical bytes. | `wire_order_is_assertion_digest_order_not_signing_order` |
| Decode then re-encode reproduces the bytes | Holds for an entry with no elision. | same test |
| An unattributable signature is detectable | Holds. The codec carries a stranger's signature. Attribution against the candidate keys finds none for it. | `a_signature_by_a_key_outside_the_candidates_is_unattributable` |
| An elided entry is detectable | Holds twice over: `elided` is non-zero, and re-encoding does not reproduce the bytes. | `an_elided_signature_is_visible_to_the_decoder`, `an_elided_inner_assertion_is_visible_and_moves_the_entry_hash` |
| Verification is strict | Holds. The verifier's own path is `ed25519-dalek` `verify_strict` with a weak-key check. `bc-crypto` 0.14.0 also uses `verify_strict`. | `a_key_that_is_not_a_point_is_weak_or_is_non_canonical_never_verifies` |

## The bytes

The standard has to describe the signed bytes without naming a Rust
function. This test computes them by hand and compares with
`bc-envelope` 0.43.0: `the_digests_can_be_computed_without_this_crate`.

A group entry has no assertion, so its unsigned envelope is a bare
leaf, not a node.

```
core         = dCBOR map of 7 pairs (hlc, body, kind, type, actor,
               parent-hashes, format-version)
entry bytes  = D8 C8  D8 C9  core            ; 200(201(core))
entry_hash   = BLAKE3(entry bytes)
leaf digest  = SHA-256(core)                 ; the map alone, no tag
sign_digest  = SHA-256(leaf digest)          ; the wrapper's digest

signature assertion      = A1 03 D8 C9 D9 9C54 82 02 58 40 <sig:64>
                           ; {3: 201(40020([2, h'sig']))}
assertion digest         = SHA-256( SHA-256(D9 9C40 03)
                                 || SHA-256(D9 9C54 82 02 58 40 <sig:64>) )
signed envelope, n sigs  = D8 C8  (array of 1+n)  entry bytes
                           assertion ... in ascending assertion digest
```

## What the spike found beyond the claim

1. **A repeated signature does not survive encoding.** Ed25519 is
   deterministic, so one key signing twice gives one signature, and an
   envelope keeps one copy of an identical assertion.
   `a_repeated_signature_does_not_survive_encoding`. This agrees with
   the design rule that no key appears twice.

2. **`bc-components` panics on a key that is not a curve point.**
   `bc-crypto` 0.14.0 `ed25519_verify` calls
   `VerifyingKey::from_bytes(..).unwrap()`. A key of thirty-two `0x02`
   bytes does not decompress, and the call panics. The identity point
   decodes and returns `false`. Checked with a throwaway test, not kept.

   For the group verifier this changes nothing in the contract. The
   design already requires every key to be a valid, non-weak Ed25519
   key. It does fix how the verifier is built: it screens every key
   itself and verifies with `ed25519-dalek`, and it never hands an
   unchecked key to `bc-components`. `tests/cosign.rs` shows that path.

   For `identikey-log` it is an existing defect, outside this change.
   `sign::decode_and_verify` takes `actor` from the bytes it was given,
   so an op that names a non-point actor panics the caller. Filed as
   bead `ikp-o70` in this repo.

## Not covered

- ML-DSA signatures. v1 rejects them. Not exercised here.
- The size limits (80 signatures, 65,536 bytes). They are verifier
  rules, not crate behavior.
- H2 (a `bc-xid` document with no inception key). It belongs to the
  identikey-core change that projects a group XID document.
