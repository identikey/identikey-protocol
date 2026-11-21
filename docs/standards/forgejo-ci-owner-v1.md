# Forgejo CI owner proof v1 (experimental)

This interoperability profile describes one guild decision. The guild authorizes
a particular Forgejo organization to own CI VMs under its XID. The action
target is the canonical Forgejo HTTPS instance hostname and immutable numeric
organization ID. Renaming the organization does not change the target. The
result of the action is exactly that scoped binding. The decision carries no
repository membership, shell access, or identity-document control power.

## Scope and inputs

The input to approval verification is a *trusted prior checkpoint*. The caller
has already authenticated the collective XID binding to the keyspace, the prior
state and effective policy digests, the expected next sequence, the eligible
Ed25519 owner keys and their corresponding principals, and the settlement
witness key. It also knows which Forgejo target it is authorizing, has obtained
the Forgejo operator's consent, and has issued an outstanding one-use challenge.
None of those authority inputs can be learned from the submitted proof.

The checkpoint and its policy commit to a **distinct-principal threshold**.
The table contains 1–64 owner public keys, each appearing once. Multiple
devices may map to one principal. The threshold is at least one and no
greater than the distinct principal count. A single-owner policy is the
one-key, one-approval case. Every key must be a valid, non-weak Ed25519
verification key. Signatures use strict Ed25519 verification.

The fixture profile trusts one independent, non-equivocating settlement
witness, named by the effective checkpoint. This is a one-member witness set.
It assumes a durable, serialized record of consumption. The fixture supplies
its signatures so an offline implementation can verify the transcript.
Bootstrapping checkpoint trust, producing live settlement records, rotating
authority, and verifying witness storage are separate integration requirements.
The v1 keyspace log and its existing operations remain as specified in
[Keyspace v1](identikey-keyspace-v1.md).

## Signed bytes

Concatenate fields in order, with no padding or implicit separators. Each
domain label is literal ASCII followed by one zero byte. A u64 or u16 is an
unsigned big-endian integer. XIDs are raw 32 bytes. The keyspace ID, state and
policy digests are also 32 bytes. Each owner signs the full approval message:

```text
"identikey/forgejo-ci-owner/approval/v1" 0x00
keyspace_id guild_xid predecessor policy_digest
next_sequence:u64 hostname_length:u16 hostname:ASCII organization_id:u64
```

Sequence and organization ID are positive. Hostname length counts bytes in
the range 1–253. Each dot-separated label is 1–63 ASCII lowercase letters,
digits or hyphens, with an alphanumeric first and last byte. The hostname has
no trailing dot. The instance runs at the root of the default HTTPS origin
(port 443). Reject noncanonical or unsupported inputs without normalization.

Every submitted approval contains the 32-byte public key and a 64-byte
signature. Require 1–64 approvals. Verify **all** of them over the identical
bytes and resolve each key to its trusted principal. Reject unknown signers,
invalid signatures, repeated principals (including distinct devices), and
an insufficient count. Compare the signed context and target against the
caller's expected values in full.

After validating that decision, the witness signs the following bytes:

```text
"identikey/forgejo-ci-owner/consume/v1" 0x00
full_approval_message outstanding_consumer_challenge:32
```

The consume signature binds the exact action and its prior authority. The
witness must record this consume durably in the same order as changes to the
governing head. It must refuse stale policies, competing successors, and
reused challenges. On detected equivocation, freeze the affected predecessor.
The relying service must bind its challenge to the intended operation and
consumer, verify the witness signature and its challenge, and atomically spend
the outstanding challenge when installing the binding. It must reject stale
or already-spent requests across restarts. Proof validation alone does not
perform these writes. Failure or absence of settlement leaves the binding
pending. A positive fixture verdict means that the cryptographic checks pass
given its synthetic trusted inputs.

## Conformance

[vectors/forgejo-ci-owner-v1.json](vectors/forgejo-ci-owner-v1.json) is the
shared corpus. JSON is a test carrier. Hex fields encode raw bytes in lowercase,
and integers use JSON numbers interpreted with exact integer precision.
`context` contains trusted caller inputs. `proof` is untrusted. Reconstruct
`approval_bytes` and (when settlement is present) `consume_bytes` from
`proof`; those two hex fields are test oracles. `valid` gives the expected
offline verdict. Cases are independent and contain disposable identities.
The production hostname and numeric organization in the examples are test
targets; these vectors cannot establish a production binding.

Regenerate or check deterministic fixtures from the repository root:

```sh
uv run --script scripts/forgejo_ci_owner_vectors.py --check
```
