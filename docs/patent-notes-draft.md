# Notes on patent claims (draft)

> Required by NIST MPTC IR 8214C §5 as a package deliverable. This document
> is collected over the development period and finalized for the
> submission.

## Status

**Draft.** No patent claims have been formally identified. This page
tracks claims as contributors disclose them.

## Inherited from upstream

### Pulsar (`luxfi/pulsar`)

Pulsar reuses Pulsar's protocol structure. Pulsar's IP posture per
its README:

- Apache-2.0 licensed.
- Patent grant per Apache 2.0 §3 from each contributor.
- No known active patent claims as of repository creation.

This applies to Pulsar to the extent that Pulsar code or protocol
elements are derivative of Pulsar.

### Corona (`luxfi/corona`)

Pulsar (and therefore Pulsar) is a fork of academic Corona.
Corona (ePrint 2024/1113) authors: Cecilia Boschini, Darya Kaviani,
Russell W. F. Lai, Giulio Malavolta, Akira Takahashi, Mehdi Tibouchi.
Corona's open-source repo is Apache-2.0 with no asserted patent
claims as of mid-2026. Pulsar's M-LWE adaptation does not import
Corona code directly but inherits the protocol structure.

### ML-DSA / FIPS 204

ML-DSA is a NIST-standardized algorithm. The Dilithium team's IP
disclosures during NIST PQC standardization are public on the NIST
PQC website. Pulsar targets output interchangeability with FIPS 204
but does not assert any rights over FIPS 204 itself.

## Contributor disclosures

Per CONTRIBUTING.md, every commit's `Signed-off-by` line is taken as
either:
1. An explicit assertion that the contributor has no relevant patent
   claims, OR
2. A reference to a disclosed claim listed below.

| date | contributor | type | disclosure |
|---|---|---|---|
| 2026-05-10 | Lux Industries Inc | initial repo | no claims asserted |

(Updated as contributions land.)

## Third-party patents we may need to navigate

Live concerns to investigate before submission:

- Lattice-estimator usage (we use the open-source estimator; license
  pass-through to MIT).
- Gaussian sampler implementation (FIPS 204 references CDT; alternate
  rejection samplers may have IP).
- Polynomial multiplication via NTT (standard, no known IP).
- Pedersen commitments (1991 paper, expired patents).

The submission's Notes on Patent Claims will explicitly call out each
of these.

## NIST MPTC submission requirements

NIST IR 8214C §5 (Notes on Patent Claims) requires:

> Submitter(s) shall include a statement of any patent claims known to
> them that may be relevant to the submitted package, regardless of who
> owns the claim. Statements of "no known claims" are acceptable.

Our final statement, once the spec freezes:

> *To be drafted at spec freeze. Will incorporate every disclosure in
> the contributor table above, every inherited claim from Pulsar /
> Corona / ML-DSA, and the third-party investigation outcome.*

## Process

1. Every PR review checks for new IP-relevant code.
2. Significant cryptographic additions (new sampling routine, new
   commitment shape, new aggregation step) trigger an explicit IP
   review with one of the sponsor's IP counsel.
3. Final statement assembled at freeze, included in
   `spec/pulsar.pdf` Appendix A.
