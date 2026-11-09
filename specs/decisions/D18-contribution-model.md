---
id: D18
title: Contribution model for new attack scenarios
status: decided
decided: 2026-11-09
decided_by: author
source: author, session 2026-11-09
affects: [SPEC-CORPUS 8, SPEC-CORPUS 10, SPEC-CORPUS 14]
related: [D3, D13]
---
# D18. Contribution model for new attack scenarios

## Context

The corpus must grow as new vulnerabilities are disclosed (for example a PHP vulnerability), and outside researchers should be able to contribute attacks. Under the 2026-11-09 capture architecture an attack is a self-contained scenario package (manifest, driver, vulnerable service container pinned by digest, mandatory benign driver for that service, variation file, acceptance expectations), and a recording is a sealed, content-addressed capture of one scenario run on the reference target.

## Options

- **(a) Scenario packages by pull request.** Contributors submit packages; maintainers run accepted packages on the reference target and publish the recordings. Every published recording comes from one target definition and one collector build.
- **(b) Contributed recordings.** Contributors capture on their own instance of the reference target built from the published definition; recordings are accepted if manifest digests match a supported target version and validation passes. Scales better but trusts a host the project does not control.

## Recommendation

The analysis recommended (a) for the published corpus, with (b) permitted only for clearly marked community recordings.

## Decision

**Decided 2026-11-09: option (a).** Recordings captured on contributor-operated hosts are not accepted into the corpus.

## Consequences

- The harness interface (SPEC-CORPUS 8) is a public contract for contributors; registration is enforced by the harness context so it cannot be omitted.
- The maintainers bear the capture cost of every accepted scenario; throughput is bounded by reference-target time.
- Package validation (ATT&CK identifiers, mandatory benign driver, acceptance expectations) runs in CI before a package is accepted.
