# PATENTS — Pulsar Threshold ML-DSA-65

> **Statement of Intellectual Property and Royalty-Free Patent Grant**
> for the Pulsar threshold-signing construction submitted to the NIST
> Multi-Party Threshold Cryptography (MPTC) project.

## TL;DR

Lux Industries, Inc. ("Lux") grants a **worldwide, royalty-free,
non-exclusive, irrevocable patent license** for any implementation of
Pulsar that conforms to FIPS 204 ML-DSA-65 verifier semantics AND is
either (a) licensed under Apache-2.0 or a compatible OSI-approved
license, OR (b) is part of a NIST MPTC / PQC / ACVP submission,
validation, or interoperability test.

The grant terminates automatically and prospectively against any
party that asserts a patent claim against Pulsar, FIPS 204 ML-DSA, or
any conforming implementation thereof. Defensive termination mirrors
Apache-2.0 §3.

The full text of the grant is in **§3 Patent Grant** below.

## §1 Scope of the IP statement

This document covers patent rights and patent posture for:

- The **Pulsar threshold-signing construction** described in
  `spec/pulsar.tex` (DKG → Round-1 → Round-2 → Combine → Reshare).
- The **reference implementation** in `ref/go/`.
- The **EasyCrypt / Lean / Jasmin proof artifacts** in `proofs/` and
  `jasmin/`.
- The **test-vector format** in `vectors/`.

It does NOT cover, and explicitly DISCLAIMS, the following prior art:

| Component | Status |
|---|---|
| FIPS 204 ML-DSA-65 itself (NIST FIPS 204) | Public domain — NIST standard. Pulsar TARGETS FIPS 204 semantics; the algorithm itself is not novel here. |
| Module-Lattice (M-LWE / M-SIS) primitive | Academic / public domain. |
| Shamir secret sharing (1979) | Public domain. |
| Lagrange polynomial interpolation | Classical mathematics. |
| FROST threshold-signing baseline (academic literature) | Published in IACR ePrint; no novelty asserted here against the published construction. |
| SHAKE128 / SHAKE256 / Keccak (FIPS 202) | Public domain — NIST standard. |
| EasyCrypt, Lean, Mathlib, Jasmin, libjade | Open-source / academic — Lux asserts no patents on these tools. |
| The output-interchangeability concept | Documented in academic literature on threshold signatures; Pulsar's specific Lagrange-aggregation technique that achieves byte-identical output is the novel contribution. |

## §2 What Lux considers patentable (high level)

Subject to attorney review (see `patent-claims.md` for the
detailed numbered claim drafts), Lux considers the following Pulsar
contributions to be candidates for patent protection:

### §2.1 Byte-identical output interchangeability

The specific technique by which a threshold signing protocol's
combine procedure produces a byte-string output that is **bit-equal**
to a single-party FIPS 204 ML-DSA-65 signature on the
Lagrange-reconstructed group secret. The technique combines:

- 2-round protocol structure (commitment → response → aggregation)
  that defers rejection-sampling to the aggregator;
- Lagrange aggregation of per-party partial responses
  `z_i = y_i + c·s_i` such that `aggregate(z_i) = y_central + c·s_central`
  (formalized as `Crypto.Threshold.Lagrange.threshold_partial_response_identity`
  in the Lean proof artifact);
- Coordinate-wise HighBits decomposition + MakeHint aggregation
  preserving the FIPS 204 §6.2 inner-loop semantics under threshold
  composition;
- A specific FIPS 204 §5.4.1 ExternalMu binding that ties the
  threshold session to the centralized message-context binder.

### §2.2 Class N4 reshare with public-key preservation

Proactive secret-sharing protocol that rotates shares across
committee changes while preserving the group public key. Permits
long-lived public identity with rotating custodians. Detailed in
`spec/pulsar.tex` §4.5 and mechanized in `proofs/easycrypt/Pulsar_N4.ec`.

### §2.3 Identifiable abort with third-party-verifiable evidence

TLV-encoded per-kind abort evidence (equivocation / bad-delivery /
MAC-failure / range-failure) that can be verified by any third party
without access to private session state. Implementation in
`ref/go/pkg/pulsar/abort.go`; tests in `test/negative/`.

### §2.4 Pulsar-specific FROST/ML-DSA hybrid construction

The specific composition of FROST-style Lagrange aggregation with
FIPS 204's kappa rejection-sampling loop — including which steps run
per-party vs. at the aggregator, how the rejection condition is
evaluated on the aggregated polynomial vectors, and the
identifiable-abort fall-through path when rejection conditions fail.

## §3 Patent grant (the load-bearing text)

> **PULSAR PATENT GRANT — v1.0**
>
> Lux Industries, Inc. ("Lux"), a Delaware corporation, hereby grants
> to any person or entity ("You") a **worldwide, royalty-free,
> non-exclusive, no-charge, fully-paid-up, irrevocable** (except as
> stated in §3.2 below) patent license to make, have made, use, offer
> to sell, sell, import, and otherwise transfer any implementation of
> the Pulsar threshold-signing construction described in
> `spec/pulsar.tex` (the "Construction"), provided that such
> implementation:
>
> (a) Produces signature outputs that verify under any FIPS 204
>     ML-DSA-65 conformant verifier (the "Output-Interchangeability
>     Condition"); AND
>
> (b) Is licensed to the public under (i) the Apache License, Version
>     2.0, or (ii) any other Open-Source-Initiative-approved license
>     compatible with Apache-2.0, OR (c) is part of a submission to,
>     validation under, or interoperability test for the NIST
>     Multi-Party Threshold Cryptography (MPTC) project, the NIST
>     Post-Quantum Cryptography (PQC) standardization process, or any
>     successor program administered by NIST.
>
> The license granted in this §3 covers all "Necessary Claims" owned
> or controllable by Lux that would, in absence of this license,
> necessarily be infringed by an implementation meeting (a) and (b).
> "Necessary Claims" means claims of any patent or patent
> application that are essential for compliance with the Pulsar
> specification, that Lux has the right at the time of execution to
> grant a license under.
>
> ### §3.1 Documentation and reference-implementation grant
>
> The Pulsar specification (`spec/pulsar.tex`), the reference
> implementation (`ref/go/`), the proof artifacts (`proofs/`), and
> the test vectors (`vectors/`) are released under the Apache License,
> Version 2.0. The patent grant in this document operates in
> addition to (not in lieu of) the patent provisions in the
> Apache-2.0 license.
>
> ### §3.2 Defensive termination
>
> The patent license granted in this §3 terminates automatically and
> prospectively, without notice, with respect to any party (the
> "Asserting Party") if the Asserting Party initiates patent
> litigation (including a cross-claim or counter-claim in a lawsuit)
> alleging that:
>
> (i) The Pulsar construction; or
> (ii) FIPS 204 ML-DSA, or any other NIST-standardized post-quantum
>      signature scheme; or
> (iii) Any implementation of (i) or (ii) — including without
>       limitation the reference implementation in `ref/go/`,
>       independent third-party implementations, NIST ACVP/CAVP
>       reference vectors, or any FIPS 140-3 validated module
>       containing such an implementation,
>
> infringes any patent owned or controllable by the Asserting Party.
> Termination is prospective only; it does not undo the validity of
> any implementation distributed prior to the date the Asserting
> Party initiated the litigation.
>
> Defensive termination mirrors the patent-termination clause of the
> Apache License, Version 2.0, §3, generalized to also cover FIPS 204
> ML-DSA and successor NIST-standardized post-quantum signature
> schemes. The purpose is to deter patent assertion against the
> broader post-quantum signature ecosystem, not only against Pulsar
> itself.
>
> ### §3.3 No trademark license
>
> This grant does not authorize the use of Lux's trademarks
> (including "Pulsar", "Lux", "Lux Industries", and their respective
> logos) except as required for reasonable and customary use in
> describing the origin of the Construction and reproducing the
> content of any NOTICE file.
>
> ### §3.4 Disclaimer
>
> THE CONSTRUCTION AND ALL ASSOCIATED MATERIALS ARE PROVIDED ON AN
> "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, EITHER
> EXPRESS OR IMPLIED. Lux shall not be liable for any damages
> resulting from the use of the patent license granted in this §3.

## §4 Filing strategy (informational)

This section is for transparency; it does not modify the grant
in §3.

Lux intends to pursue patent protection on the Pulsar construction
as follows:

1. **US provisional application** within 12 months of public
   disclosure (the NIST MPTC submission counts as public disclosure
   for §102 purposes; filing before submission preserves priority).

2. **PCT international application** within 12 months of the
   provisional, designating jurisdictions where ML-DSA adoption is
   anticipated (EU, JP, CN, KR, IN, AU, CA, UK, BR).

3. **EPO and major-jurisdiction national-phase entries** at the PCT
   30-month deadline, prioritized by anticipated deployment markets.

4. **Continuation / divisional applications** to cover incremental
   refinements (e.g., the v8 Lean-bridged Lagrange-aggregation
   identity, the v6 ExternalMu byte-layout, the N4 reshare
   pk-preservation algorithm).

The royalty-free grant in §3 applies to ALL such filings, present
and future, that are owned or controllable by Lux.

## §5 Why the grant is structured this way

A few notes for reviewers who might ask "why this language and not
plain public-domain dedication":

### §5.1 Defensive patent ownership protects the ecosystem

Without Lux holding the patents, a third party could observe the
public NIST submission, file blocking patents on the Pulsar
construction, and assert them against open-source implementations.
Lux holding the patents (with a royalty-free grant) removes that
attack surface.

This is the same logic that protects FRAND ecosystems and that
underlies Apache-2.0's patent grant + retaliation clause.

### §5.2 Compatibility with NIST MPTC submission terms

The NIST Multi-Party Threshold Cryptography project's submission
guidelines require submitters to provide a patent statement
specifying the IP terms under which the submitted construction may
be used. The grant in §3 satisfies that requirement and goes beyond
NIST's baseline by extending defensive termination to all
NIST-standardized post-quantum signature schemes.

### §5.3 Compatibility with FIPS 140-3 / FIPS 204 deployments

Vendors validating cryptographic modules under FIPS 140-3 that
include FIPS 204 ML-DSA require unambiguous IP terms for any
threshold extension they ship. The grant in §3 is unambiguous and
royalty-free for FIPS 204-conformant implementations, removing IP
friction for FIPS module vendors who incorporate Pulsar.

### §5.4 Defensive termination for the broader PQ ecosystem

Extending defensive termination to FIPS 204 ML-DSA (and successors)
not just Pulsar itself converts Lux's patent portfolio into a small
deterrent against PQ-signature patent trolls. It costs Lux nothing
(Lux does not intend to assert offensively) and benefits the
ecosystem.

## §6 What this document does NOT do

- It does not assign any Lux patent rights to NIST, IETF, or any
  third party. Lux retains ownership; the grant in §3 is a license.
- It does not commit Lux to maintain or prosecute any specific
  patent application. Lux may abandon applications for business
  reasons; the grant in §3 covers issued patents in proportion to
  what is actually granted.
- It does not waive Lux's right to update the grant text (subject
  to §6.1 below).
- It does not modify the Apache-2.0 license covering the
  reference implementation, specification, proofs, and vectors.

### §6.1 Modifications to this grant

Lux may issue future versions of this PATENTS document with
clarifications or extensions of the grant. Future versions will
apply to implementations published under the future version's
identifier. **The grant in §3 of this v1.0 document is
irrevocable for implementations relying on it**, subject only to
the defensive-termination clause in §3.2.

## §7 Contact

| Purpose | Contact |
|---|---|
| Patent / IP inquiries | `legal@lux.network` |
| Licensing for non-conforming implementations | `legal@lux.network` |
| NIST submission coordination | `mptc@lux.network` |
| Security disclosure | See `SECURITY.md` |

For patent-claim drafting (the document an attorney would work
from), see `patent-claims.md`.

---

**Document metadata**

- Document name: `patents.md`
- Document version: v1.0
- Document date: 2026-05-18
- Construction version: Pulsar v0.1 (NIST MPTC submission package)
- Construction repository: <https://github.com/luxfi/pulsar>
- License of this document: Creative Commons CC-BY-4.0 (so it
  can be freely reproduced in NIST submission packages and audit
  reports without modification).
