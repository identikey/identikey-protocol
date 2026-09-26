# identikey-capability-v1 fixtures

Generated from authority private key `11`×32 (Ed25519). Tokens are not
re-minted in tests — Biscuit nextKeys are random — they are verified as
committed bytes.

- `root_public.hex` — 32-byte Ed25519 authority public key
- `authority.bin` — root token `right("example", "read");`
- `attenuated.bin` — same plus `check if holder($fp), $fp == "FP";`
