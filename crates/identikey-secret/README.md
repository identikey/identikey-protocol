# identikey-secret

Opaque secrets that belong with an identikey.

A record has a path-safe id, a label, a unix time, a 32-byte salt, and the
secret bytes. The name you can put on a token or in a log is

```text
Blake3("identikey-secret-v1\n" || salt || value)
```

The salt may travel with that commitment. The value must not. An unsalted
hash of the value is not a commitment. This domain is not Mjolnir's
`mjolnir/secret-commit/v1` vault.

`MemorySecretStore` holds the records in process. The first disk store is
the IKEYW wallet in `identikey-wallet`: the same Argon2id file as the
identity, under the wallet predicate `sealed-secret`. Unlocking the wallet
unlocks these secrets. That is local custody, not a redeem grant and not a
guild holder.

identikey-core does not use this store. Its database holds custody scalars
and a cache of keyspace wraps. Those are not foreign-secret records.
