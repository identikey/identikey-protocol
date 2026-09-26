# identikey-capability

Protocol-tier mint/verify for [IdentiKey Capability Tokens v1](../../docs/standards/identikey-capability-v1.md).

Biscuit, Ed25519 authority, monotonic attenuation, holder **checks** (never `holder` facts). Wire + validators only — no HTTP, no login profiles, no tokenator, no Mjolnir Datalog schema.

```rust
use identikey_capability::{append_holder_check, authorize, mint_right, new_keypair, parse};

let root = new_keypair();
let minted = mint_right(&root, "example", "read").unwrap();
let tok = parse(&minted, root.public()).unwrap();
let held = append_holder_check(&tok, "FP").unwrap();
authorize(&held, root.public(), Some("FP"), "example", "read").unwrap();
```

Secret commitments take a caller domain: `secret_commit(b"app/secret-commit/v1", salt, secret)`. Do not hardcode a product domain in this crate.
