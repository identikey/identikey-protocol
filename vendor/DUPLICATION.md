# These vendored forks are duplicated in two repositories — on purpose

`vendor/bc-shamir/` and `vendor/dcbor/` here are **byte-for-byte copies** of
the same two directories in the Dreamball repository
(`WorldTree/Dreamball/vendor/`). They were created there first, by
`Dreamball-y4t.13`.

## Why duplicate instead of sharing

`[patch.crates-io]` paths are resolved relative to the workspace root, so
sharing one copy would mean committing something like
`{ path = "../../../WorldTree/Dreamball/vendor/dcbor" }` into
`identikey-protocol/Cargo.toml`. That path only exists on one developer's
machine with one particular checkout layout; it would break CI, break any
clone, and silently couple two independently-versioned repositories. A git
submodule would work but buys a submodule's whole cost for two one-line
`Cargo.toml` diffs whose expected lifetime is "until upstream merges".

So: duplicate, and write the duplication down rather than let it be
rediscovered.

## The invariant

The two copies must stay identical. If you change one, change the other:

```sh
diff -ru --exclude=.cargo-ok \
  /path/to/Dreamball/vendor/bc-shamir vendor/bc-shamir
diff -ru --exclude=.cargo-ok \
  /path/to/Dreamball/vendor/dcbor    vendor/dcbor
```

Both should print nothing.

## Deletion criteria — this is temporary debt with a defined end

Upstream issues are filed:

- bc-shamir: <https://github.com/BlockchainCommons/bc-shamir-rust/issues/4>
- dcbor: <https://github.com/BlockchainCommons/bc-dcbor-rust/issues/6>

When a release carrying either fix is published:

1. Bump to it and re-run the check in that crate's `VENDOR.md` § Refresh
   procedure.
2. Delete the vendored directory **in both repositories**.
3. Delete the corresponding line from **both** `[patch.crates-io]` blocks.
4. Delete this file once both are gone.

Until then, the CI job `wasm32` in `.github/workflows/ci.yml` is what proves
the patched graph still builds for the browser target.
