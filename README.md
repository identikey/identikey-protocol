# IdentiKey Protocol

Reference implementations of the IdentiKey identity protocols — the
*protocol tier* of the IdentiKey stack. Everything here is permissively
licensed (**Apache-2.0 OR BSD-2-Clause-Patent**, both with mandatory patent
grants) and designed to be embedded anywhere: these formats and protocols
are meant to outlive any single steward.

## Crates

| Crate | What it is |
|---|---|
| [`identikey-auth`](crates/identikey-auth) | Hardware-enclave-backed challenge/response authentication: audience-bound nonce challenges signed by Secure Enclave (macOS), TPM 2.0 (Linux/Windows), or software keys; cipher-agile (Ed25519/P-256 + optional ML-DSA), no relying-party server required. |
| [`identikey-wallet`](crates/identikey-wallet) | Password-encrypted identity wallet: `IKEYW` v2 file format (Argon2id + XChaCha20-Poly1305), OS keychain key caching (macOS Keychain / Secret Service / Windows Credential Manager), Gordian Envelope container with forward-compatible unknown-assertion preservation. Generic over the identity type via the `WalletIdentity` trait. |
| [`ikey`](ikey) | CLI for managing identity wallets: `ikey identity new/list/show/use/delete`, `ikey wallet lock/unlock/status/path`. Identities are Ed25519 + optional ML-DSA-87 (post-quantum). |

## ikey quick start

```bash
cargo install --path ikey

ikey identity new --name alice     # Ed25519 + ML-DSA-87
ikey identity list
ikey identity use alice
ikey wallet status
```

The wallet is a single password-encrypted file (`ikey wallet path` shows
where). Non-interactive use: set `IDENTIKEY_WALLET_PASSWORD`, or
`IDENTIKEY_WALLET_KEY` (base64 32-byte key) in CI;
`IDENTIKEY_NO_KEYCHAIN=1` disables OS keychain caching.

## Embedding the wallet

Applications define their own identity type (extra key material, their own
envelope predicates) by implementing `WalletIdentity`, which also names the
app's `WalletParams` — wallet envelope type string, keychain service, env
vars, and default path. [Recrypt](https://github.com/identikey/recrypt)
does exactly this: its identities carry proxy-recryption key material as
additional assertions on the same wallet format.

Unknown assertions — wallet-level and identity-level — are preserved
verbatim across load/save, so an older client (or a generic tool like
`ikey`) never destroys another application's extensions.

## License

Apache-2.0 OR BSD-2-Clause-Patent — your choice; see [LICENSE](LICENSE)
for why this pair. © 2026 Identikey Inc.
