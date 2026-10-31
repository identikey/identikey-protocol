# Information Architecture: Secret use

**Date:** 2026-10-29
**Scope:** How IdentiKey, Lightning Mesh, Papyrus, Mjolnir, Recrypt, and the API proxy currently place secret use. This is the structural map of that concept. There is no design brief and no new product surface in this folder.

A secret use is a decision that some bytes may be read or applied. The systems below do not share one screen for that decision. They share a vocabulary, and several of the words already mean different objects. This document records the current placement so a later UI does not collapse them.

The uncommitted `identikey-share` work in this repo is a data-access share. It is listed where it sits. It is not a guild holder class, and the API proxy is not building against it.

## Site Map

These are the places a person or an agent meets secret use. Indentation is which product owns the surface, not a page tree inside one app.

- IdentiKey protocol `/docs/standards/`
  - Identity, possession proof — `identikey-auth-challenge-v1`
  - Agency, what a holder may do — `identikey-capability-v1` (Biscuit)
  - Foreign-secret redeem profile — capability v1 §7
  - Shared key material among identikeys — `identikey-keyspace-v1` (product word: guild)
  - Ciphertext share, local and uncommitted — `identikey-share-v1`
  - Wallet container — `wallet-envelope-format` (membership and cached-capability assertions are reserved, not defined)
  - First secret store — `identikey-secret-v1`, sealed in that same IKEYW file. Local custody only. Not the core database and not the Mjolnir vault.
- IdentiKey core (managed custody and the keyspace consumer)
  - Account, credential, rung — not the key
  - Encapsulation ceremony — export, unwrap, or rewrap of one held X25519
  - Keyspace replica — applied roster and wraps
  - Key recovery — type boundary only; no reconstruction ceremony
- Recrypt
  - PRE of our ciphertext — the recryption key is the bearer for that data
  - Not a foreign-secret vault
- Mjolnir
  - Opaque foreign-secret vault and `POST /api/secrets/redeem`
  - VM exec and other agency profiles — Biscuit, not the vault
  - Guest mailbox and snapshots — not secret use
- API proxy
  - Holder-bound agency gate — one public key
  - Wallet guild provider — applied keyspace tip as data access
  - Secret-use execution — specified, not live; `POST /v1/execute` stays locked
- Lightning Mesh
  - Client SSID / network name — not a guild, not a secret
  - hello.mesh login — may spool an access-node wrap request; the request carries no guild secret
  - Lightning Admin — signs `keyspace.*` ops; guild key material stays in identikey-core
  - House guild versus access-node guild — two profiles of one keyspace object
- Papyrus
  - Agent permission surface — intended first UI for minting and handing a Biscuit; not built
  - Delegation draft — prompts and bounded work; not secret bytes
  - Google session — OAuth refresh token in the OS keychain; not the tokenator
  - Mirror / scrolls — vision gates shared media with Recrypt; that is data access, not a foreign API secret
  - OS and TCC permissions — a different object from a Biscuit

## Navigation Model

Nobody starts in a shared "Secrets" app. Each product has one front door, and secret use is behind a narrower door inside it.

- **Primary navigation:** the product the person already opened. Lightning Admin is guild membership and radio. Papyrus is the human's work surface. Mjolnir is the VM and the redeem API. The proxy has no wallet or guild screen. Recrypt is a library and a service, not a place a person browses secrets.
- **Secondary navigation:** inside a product, secret use is a mode of an existing object, not a top-level section. In Lightning Mesh it sits under guild administration and under hello.mesh login. In Papyrus the intended place is the agent-permission surface beside Terminal, not a new product dimension. In Mjolnir it is `POST /api/secrets/redeem` on the existing API, not a new port.
- **Utility navigation:** identity possession (auth challenge, passkey, OIDC) is the door in. It is not the grant. A wallet unlock reveals local key material. It does not authorize an API call.
- **Mobile and LAN:** hello.mesh on the phone or the LAN gateway is the Lightning entry. Identikey login there can ask for an access-node wrap. The client SSID join does not. Papyrus Google sign-in uses the system browser on loopback, never a stored client secret.

## Content Hierarchy

What each surface puts first when secret use is in play.

### Capability and redeem (Mjolnir, protocol §7)

1. The holder check — one public key, a check in the token, never a `holder` fact the token asserts.
2. The operation bound — redeem this foreign secret, for this audience, with a fresh nonce.
3. The release binding — the secret bytes go to the holder over a channel an intermediary cannot read.
4. The audit line — id, holder, time, result. Never the secret bytes.

### Proxy secret use

1. The agency proof — this caller, this operation, this resource, this policy epoch.
2. The data proof — the proxy holder can unwrap the credential it will inject.
3. The effect — one upstream call, idempotent or reconciled. Secret bytes stay inside the proxy.
4. What is refused — a guild id as the holder, a roster entry as a use grant, PRE of a foreign secret, raw export to the agent.

### Lightning guild

1. The product word guild, and the protocol object keyspace.
2. Whether this is a house guild (secrets may live here) or an access-node guild (login wrap, not house secrets).
3. The signed op (`keyspace.join`, `keyspace.change`, `keyspace.assign-node`, `keyspace.nest`). There is no `guild.*` kind and no rename.
4. The wrap of the PTK to a member's PUK. The wrap is not membership, and membership is not a use grant.

### Papyrus

1. The work being delegated — which words, which agent, what it could do, what happened next.
2. The capability that bounds that agent, when the permission surface exists.
3. Local credentials the app holds for itself (Google refresh token, iroh node key). Those stay in the OS keychain or the process. They are not guild secrets and not tokenator secrets.
4. Shared media encryption, in the vision, as Recrypt data access. It is not the foreign-secret profile.

### Recrypt and identikey-share

1. The ciphertext, and who can read it.
2. For Recrypt, a PRE transform of our key material. The recryption key is the bearer for that data.
3. For `identikey-share`, one DEK, a keyspace v1 wrap per recipient, an optional ML-DSA signature on that recipient set, and an opaque PRE capsule slot. The slot does not implement Recrypt.
4. Neither object authorizes an API operation.

## User Flows

### Foreign secret, thin proxy (the intended secure path)

1. An owner provisions the foreign credential so the proxy's own holder can unwrap it.
2. The owner mints a narrow use grant for an agent. The grant names the operation and the resource. The holder class is one public key.
3. The agent presents that grant and a fresh possession proof to the proxy.
4. The proxy checks agency, then uses its own redeem grant toward the tokenator. It does not forward the agent's token.
   - If either gate fails, no secret bytes are released and no upstream call starts.
   - If both succeed, the proxy injects the credential on the upstream call and returns the result.
5. The agent never receives the credential. Revoking the use grant stops later calls. It does not pull back bytes already copied out, which is why this path avoids copy-out.

This flow is specified. `POST /v1/execute` is locked. The proxy still depends on protocol revision `8cd455c`, which does not include `identikey-share`.

### Foreign secret, Mjolnir redeem (accepted v1)

1. A foreign secret is stored as opaque bytes with a salted Blake3 commitment. Guests do not write that vault.
2. A holder-bound Biscuit names one public key and the redeem operation.
3. The holder calls `POST /api/secrets/redeem` on the existing Mjolnir API. There is no second tokenator port.
   - A reused nonce, a missing holder proof, or a path marked skip-auth fails closed.
   - A successful redeem may copy the secret out. That is the accepted v1 superset.
4. The more secure pattern remains the thin proxy above. Writing copy-out onto virtio-fs is rejected. A guild holder class is not part of this capability's first act. Papyrus is not the minting UI yet.

### Lightning access-node login

1. A person joins the client SSID. That join is a network name. It mints no keyspace membership and carries no secret.
2. The person completes identikey login on hello.mesh and names a wrap recipient.
3. The node, if it has an access-node keyspace id, spools a `keyspace.join` wrap-login request.
   - The request contains no guild secret.
   - The Sign key is not the wrap recipient.
   - A house guild id is not the target.
4. Holders of that access-node guild wrap the node's PTK to the caller's latest PUK. That wrap lets the caller receive access-node key material. It is not a house secret and not an API-use grant.

### Lightning house guild

1. An admin signs `keyspace.join` or a later `keyspace.*` op. The keyspace id is the genesis content hash.
2. Members hold wraps of the house PTK. Secrets for that guild live in this profile, in identikey-core's keyspace consumer, not in the radio config.
3. Leave or blacklist denies plaintext before the epoch commits. A new PTK is used only after one `epoch-commit` applies one `epoch-begin`. Two concurrent begins are not merged.
4. Nothing in this flow authorizes a GitHub token or any other foreign API call.

### Papyrus delegates work to an agent

1. A person keeps text and chooses an agent in Papyrus. The current delegation draft stops at prompts, history, and a bounded send.
2. The intended next surface mints a Biscuit the agent can attenuate. Papyrus is named as the first human UI for that. The permission manager app has not started, and this minting surface is not built.
3. OS permissions (Accessibility, screen capture, the system keychain) stay outside that token.
4. A Google refresh token, if the person connected Drive, stays in the Papyrus keychain item. It is not redeemed through Mjolnir and not wrapped to a guild.

### Share our ciphertext

1. The sender encrypts under one data key.
2. Recrypt wraps that key material to a PRE public key and can transform it to another recipient without the proxy seeing the data key. This is for our ciphertext.
3. `identikey-share`, locally, can instead wrap the same kind of data key to an X25519, Ed25519, or P-256 key, and can carry an opaque Recrypt capsule beside those wraps. A grant signature covers the recipient set. It is not a Biscuit.
4. A foreign API credential does not take this path. The proxy's foreign-secret rule still refuses PRE.

## Naming Conventions

Use the protocol word in specs and the product word only on the product surface that already uses it.

| Concept | Label | Notes |
|---|---|---|
| Who is this? | Identity | Auth challenge. A possession proof is not a grant. |
| What may this holder do? | Agency, capability | Biscuit. Attenuation is the delegation. One public key is the v1 holder class. |
| Who can read this ciphertext? | Data access | Recrypt for our ciphertext. Keyspace wraps for a shared PTK. `identikey-share` for a DEK wrapped to recipient public keys. |
| Product name for a keyspace | Guild | Lightning Mesh and Admin say guild. Op kinds stay `keyspace.*`. Do not title a spec `guild-v1` and do not emit `guild.*`. |
| House secrets | House guild | Keyspace profile `house`. Kick may rekey. |
| Mesh login wrap | Access-node guild | Keyspace profile `access-node`. Join does not rotate the PTK. Not house secrets. |
| Radio name | Network name, SSID | `client-network-name`. Not a guild. |
| Wrap target | PUK, encapsulation key | The public key a PTK or DEK is sealed to. Not the agency holder. The proxy's Sign proof and its PUK are different keys. |
| Shared group secret | PTK | 32-byte keyspace secret, wrapped to each member's latest PUK. Not a foreign API credential. |
| Payload key in a share | DEK | The 32-byte key `identikey-share` wraps. Same wrap encoding as a PTK wrap. Not by itself an authorization. |
| Foreign API credential | Foreign secret | GitHub PAT, API key, or equivalent. Opaque vault. Redeem profile §7. |
| Letting an agent call an API with that credential | Secret use | Proxy injects the credential. The agent does not receive it. |
| Giving the agent the credential bytes | Copy-out | Accepted on Mjolnir redeem v1. Rejected for the proxy path unless chosen as a separate permission. Revocation then needs upstream rotation. |
| Membership | Roster | A keyspace roster entry. Not a grant. Not a wrap. |
| Use grant | Holder-bound Biscuit | Authorizes an operation now. Does not unwrap a PTK. |
| Guild as the holder | Guild holder class | Named as future. v1 must not require a membership lookup to accept a holder-bound token. Not supplied by `identikey-share`. |
| Policy epoch | Proxy-auth epoch | On the use proof. Not the keyspace epoch. |
| Keyspace epoch | Epoch on the PTK | Changes only when `epoch-commit` applies one `epoch-begin`. |
| PRE, recryption key | Recrypt data bearer | Who can read our ciphertext. Not a right to exec a VM. Not the foreign-secret vault. |
| Papyrus "Recrypt keyspaces" | Shared media lock | Vision language in Papyrus. It means Recrypt data access. It is not an identikey-keyspace guild. |
| Cached wallet assertion | `keyspace-membership`, `delegated-capability` | Reserved wallet predicates. Preserved if unknown. Not authority and not a defined membership proof. |
| Account recovery | Access restore | Email, SMS, or social checks at managed custody. Must not yield key bytes. |
| Key recovery | Key restore | Guardian or split reconstruction. Typed so it cannot accept an account-recovery proof. Not implemented. |
| Papyrus Google token | Refresh token | OS keychain item `google-oauth:<subject>`. No OAuth client secret. Not a tokenator secret. |

## Component Reuse Map

| Object | Used by | What stays different |
|---|---|---|
| Auth challenge | Core login, hello.mesh login, OIDC grant, proxy holder proof | Proves possession. Does not authorize an operation or unwrap a key. |
| Biscuit, holder check | Mjolnir redeem, Mjolnir VM exec, proxy agency gate | The redeem token and the proxy-use token are different grants. The proxy does not forward the agent's token to redeem. |
| Keyspace wrap (`x25519-xchacha20poly1305`, `p256-xchacha20poly1305`) | identikey-core encapsulation, keyspace ops, Lightning wrap-login, proxy-wallet data gate, `identikey-share` | Core still has its own seal. The proxy is pinned to revision `8cd455c` and does not link the new crate. |
| Keyspace log ops | Lightning Admin, identikey-core replica, proxy-wallet snapshots | The proxy does not sync the keyspace network and does not invent a merge for concurrent epochs. `identikey-share` does not author these ops. |
| Opaque foreign-secret vault | Mjolnir tokenator | Salted Blake3 commitment. Secret bytes are not the commitment. |
| Recrypt PRE | Recrypt file sharing; Papyrus vision for shared media; a capsule slot on `identikey-share` | Foreign-secret redeem refuses this path. The share crate does not implement a backend. |
| IKEYW wallet | Core and the intended proxy provider | Unlock is local custody. Filename, path, and unknown assertions do not authorize use. |
| OS keychain | Wallet key cache, Papyrus Google refresh token | A different secret from the iroh node key and from a guild PTK. |

## Content Growth Plan

These are the parts that will accumulate, and the rule for where they go.

- More foreign secrets and more API operations belong on the proxy use grant and the tokenator vault. They do not become new holder classes.
- More guilds belong on the keyspace log. House and access-node stay profiles of that object. The SSID list stays a radio fact.
- More ciphertext recipients belong on wraps or on Recrypt capsules. A new recipient invalidates a share grant. It does not mint agency.
- Papyrus will accumulate delegated work before it accumulates a secret browser. The permission surface, when it exists, mints Biscuits. It does not become a second vault.
- Wallet assertions may later cache a keyspace id or a Biscuit. The cache stays non-authoritative until a spec defines the predicate. Unknown assertions are preserved across save so an older wallet does not strip them.
- Test vectors for keyspace ops (`ikp-6yz.2`) are still open. Share-crate tests do not fill them.
- A guild holder class, if it is ever adopted, is a new capability profile in identikey-protocol: a check, a verifier-injected fact, an epoch rule, and vectors. It is not a widening of §7.1 and not a field the proxy may invent.

## URL Strategy

Secret use does not get one URL space. Each product keeps the entry it already has.

- Mjolnir redeem: `POST {api_url}/api/secrets/redeem`. No `tokenator_url` and no extra overlay port. Challenge and redeem are the only authority that branch confers.
- Proxy execution: `POST /v1/execute` is the named future route and it is locked. A use grant is not a reason to open it.
- hello.mesh login: `POST /api/identity` may include a wrap recipient. `POST /api/portal/pass` is the SSID door and writes no wrap request.
- Lightning Admin writes `keyspace.*` ops through the mesh apply path. The keyspace id is the 32-byte genesis hash, not a slug.
- Papyrus Google OAuth redirects to `http://127.0.0.1` on an ephemeral port. Tokens do not appear in page URLs, scroll files, or logs.
- Protocol documents live under `docs/standards/`. The share document is `docs/standards/identikey-share-v1.md`. Publishing that file does not by itself retarget the proxy pin.
