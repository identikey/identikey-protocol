# identikey-auth-challenge-v1 fixtures

Fixed challenge: audience `identikey-vector`, nonce 16×`0x42`, iat `1700000000`, ttl 120s.

- `challenge.bin` — canonical dCBOR Challenge
- `response-ed25519.bin` — signed by Ed25519 seed `11`×32
- `response-p256.bin` — signed by P-256 seed `22`×32

Tests in `../vectors.rs` verify against these bytes (not merely roundtrip).
Regenerate: `cargo test -p identikey-auth --test vectors write_fixtures -- --ignored`
