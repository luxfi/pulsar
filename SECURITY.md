# Security policy

## Reporting vulnerabilities

Please report cryptographic or implementation vulnerabilities privately to
**security@lux.network** — encrypted with the team key listed at
`https://lux.network/security/key.asc`. Public disclosure happens after a
fix lands and downstream consumers have had a 14-day private window.

## What is in-scope

Pulsar-M is a **research / reference implementation** at this stage. The
following are in-scope for responsible disclosure:

- Specification ambiguity that leads to an exploitable verifier behaviour.
- Threshold-protocol soundness gaps (forgery, key-recovery, share extraction,
  rogue-key, adaptive-corruption breaks).
- Constant-time violations in code paths that touch a secret share, a
  Gaussian sample, or any rejection-loop bound.
- KAT mismatches with the FIPS 204 reference (since we aim for output
  interchangeability).
- Information leaks via logging, panics on secret-correlated paths, or
  variable-time equality.

## What is NOT in-scope

- Performance or implementation efficiency complaints (file an issue).
- DoS attacks against the reference implementation that don't affect the
  threshold-correctness invariants.
- Issues exclusively in upstream `luxfi/pulsar` (R-LWE) — file there.
- Issues exclusively in upstream `luxfi/ringtail` (academic) — file there.

## CVE assignment

Pulsar-M maintainers will request CVEs for any in-scope vulnerability prior
to public disclosure. CVE numbers will be embedded in the ePrint changelog
and the release tag's commit message.

## NIST MPTC submission disclosures

Findings discovered after the 2026-Nov-16 MPTC package submission deadline
will be added to the submission's "known limitations" appendix and
disclosed publicly per NIST's MPTC public-analysis process (no embargo
window for findings against actively-submitted MPTC packages).
