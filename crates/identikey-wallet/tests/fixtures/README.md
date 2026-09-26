# IKEYW v2 fixtures

Password `vector-password`, salt `11`×32, nonce `22`×24. Argon2id m=65536 t=3 p=4.

- `ikeyw-v2.bin` — one identity `alice` plus an unknown `delegated-capability` assertion

Tests in `../vectors.rs` decrypt this file and re-encode with the same nonce.
Regenerate: `cargo test -p identikey-wallet --test vectors write_fixtures -- --ignored`
