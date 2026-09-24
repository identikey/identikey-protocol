# add-protocol-dco

> **ACTIVE BUILD**

**Rigor:** change
**Capability:** contribution-policy (ADDED)
**Intention:** revisit-contribution-policy

## Why

The protocol tier has to stay reimplementable after a sale. A CLA
is the wrong gate for it. The decided policy is a Developer
Certificate of Origin here, and a licensing CLA only on the product.

## What

- Accept identikey-protocol contributions with a Developer Certificate
  of Origin sign-off.
- Do not require a CLA for this repository.
- Inbound license stays `Apache-2.0 OR BSD-2-Clause-Patent`.

## Impact

- Capabilities: ADDED `contribution-policy`
- ADRs: none. Decision recorded on identikey-core bead
  `identikey-core-ydd.4`.

## User journey & surfaces

No new UI because the sign-off is a commit trailer, not a page.

A person sending a patch adds `Signed-off-by` and is not asked to
assign copyright or sign the product CLA.

## Preparation — 2026-09-24

Outcome: still valid. Authority: user said "decide for me. activate."
on the identikey-core campaign. Bounds: DCO for this repo only. No
CLA. No change to the crate SPDX lines in commons §5c. Vendor trees
keep their own upstream agreements. Sibling product change:
identikey-core `add-product-cla-scope`.

## Out of scope

- Product CLA text
- `vendor/bc-shamir` and `vendor/dcbor` CLA files
- Changing `LICENSE-APACHE` or `LICENSE-BSD-2-CLAUSE-PATENT`
