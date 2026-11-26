# /// script
# requires-python = ">=3.10"
# dependencies = ["cryptography==46.0.3"]
# ///
"""Generate deterministic draft Forgejo ownership fixtures. All keys are public test data."""
import argparse
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import struct

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

OUT = Path(__file__).resolve().parents[1] / "docs/standards/vectors/forgejo-ci-owner-v1.json"


def sample(label):
    return sha256(("identikey public fixture " + label).encode()).digest()


def key(label):
    return Ed25519PrivateKey.from_private_bytes(sample(label))


def pub(signer):
    return signer.public_key().public_bytes_raw().hex()


def approval_bytes(action):
    host = action["instance"].encode("ascii")
    parts = [bytes.fromhex(action[k]) for k in ("keyspace_id", "guild_xid", "predecessor", "policy_digest")]
    return (b"identikey/forgejo-ci-owner/approval/v1\0" + b"".join(parts)
            + struct.pack(">QH", action["seq"], len(host)) + host + struct.pack(">Q", action["org_id"]))


def consume_bytes(action, challenge):
    return b"identikey/forgejo-ci-owner/consume/v1\0" + approval_bytes(action) + bytes.fromhex(challenge)


def signed(signer, transcript):
    signature = signer.sign(transcript)
    signer.public_key().verify(signature, transcript)
    return signature.hex()


def vectors():
    alice, bob, charlie, alice_device, witness = map(key, ("alice", "bob", "charlie", "alice-device", "witness"))
    owners = [(alice, "alice"), (bob, "bob"), (charlie, "charlie"), (alice_device, "alice")]
    action = {k: sample(k).hex() for k in ("keyspace_id", "guild_xid", "predecessor", "policy_digest")}
    action.update(seq=6, instance="mimir.worldtree.network", org_id=5)
    challenge = sample("consumer-challenge").hex()
    context = dict(action, challenge=challenge, threshold=2, witness_key=pub(witness),
                   owners=[dict(principal=sample("principal-" + principal).hex(), public_key=pub(signer))
                           for signer, principal in owners])

    def approval(signer):
        return dict(public_key=pub(signer), signature=signed(signer, approval_bytes(action)))

    good = dict(action, approvals=[approval(alice), approval(bob)],
                settlement=dict(challenge=challenge, signature=signed(witness, consume_bytes(action, challenge))))
    cases = []

    def add(name, valid=False, proof=None, expected=None):
        proof = deepcopy(good) if proof is None else proof
        settlement = proof["settlement"]
        cases.append(dict(name=name, valid=valid, context=expected or deepcopy(context), proof=proof,
                          approval_bytes=approval_bytes(proof).hex(),
                          consume_bytes=consume_bytes(proof, settlement["challenge"]).hex() if settlement else None))

    add("settled-quorum", True)
    single_action = dict(action, policy_digest=sample("single-key-policy").hex())
    single_proof = dict(single_action, approvals=[dict(public_key=pub(alice),
                        signature=signed(alice, approval_bytes(single_action)))],
                        settlement=dict(challenge=challenge,
                        signature=signed(witness, consume_bytes(single_action, challenge))))
    add("settled-single-owner", True, single_proof,
        dict(context, policy_digest=single_action["policy_digest"], threshold=1, owners=context["owners"][:1]))
    add("other-expected-organization", expected=dict(context, org_id=6))
    add("duplicate-key", proof=dict(good, approvals=[approval(alice), approval(alice)]))
    add("two-devices-one-principal", proof=dict(good, approvals=[approval(alice), approval(alice_device)]))
    for field, replacement in (("org_id", 6), ("instance", "other.worldtree.network")):
        add("substituted-" + field, proof=dict(good, **{field: replacement}),
            expected=dict(context, **{field: replacement}))
    add("superseded-policy", expected=dict(context, policy_digest=sample("later-policy").hex()))
    add("unsettled-quorum", proof=dict(good, settlement=None))
    add("stale-challenge", expected=dict(context, challenge=sample("next-challenge").hex()))
    add("wrong-witness", expected=dict(context, witness_key=pub(key("other-witness"))))
    return json.dumps(dict(profile="forgejo-ci-owner-v1", cases=cases), indent=2) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    generated = vectors()
    if args.check:
        if generated != OUT.read_text():
            raise SystemExit("fixture differs from deterministic generation")
    else:
        OUT.write_text(generated)
