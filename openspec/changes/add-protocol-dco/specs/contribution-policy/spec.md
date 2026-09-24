## ADDED Requirements

### Requirement: Protocol contributions use a Developer Certificate of Origin

A contribution to identikey-protocol SHALL be accepted only with a
Developer Certificate of Origin sign-off on the commit. It SHALL NOT
require a contributor license agreement. The contribution SHALL be
inbound under `Apache-2.0 OR BSD-2-Clause-Patent`, matching the
repository license. Vendor trees SHALL keep their own upstream
contributor terms.

#### Scenario: Signed-off patch

- GIVEN a patch to an identikey-protocol crate with `Signed-off-by`
- WHEN it is reviewed
- THEN no CLA signature is required
- AND the patch is offered under Apache-2.0 OR BSD-2-Clause-Patent

#### Scenario: Missing sign-off

- GIVEN a patch to an identikey-protocol crate with no `Signed-off-by`
- WHEN it is reviewed
- THEN it is not accepted until the sign-off is present

#### Scenario: Vendor tree

- GIVEN a file under `vendor/`
- WHEN its upstream project asks for that project's own CLA
- THEN this repository's Developer Certificate of Origin does not replace that upstream term
