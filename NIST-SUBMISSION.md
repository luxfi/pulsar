# NIST MPTC Submission — Pulsar (one-page executive summary)

> **Executive summary** of the Pulsar package for the NIST Multi-Party
> Threshold Cryptography (MPTC) project. The full cover sheet is in
> `SUBMISSION.md`; the package contents map is below.

## Submission metadata

| Field | Value |
|---|---|
| Submission name | **Pulsar** |
| Submitting organisation | Lux Industries, Inc. |
| Algorithm | Threshold ML-DSA-65 (FIPS 204) |
| MPTC classes | **N1** (single-party-compatible threshold signing) + **N4** (multi-party key generation with public-key preservation across resharing) |
| Underlying primitive | FIPS 204 ML-DSA-65 |
| Round count | 2 rounds per signature |
| Output | **Byte-identical** to single-party FIPS 204 ML-DSA-65 |
| Repository | <https://github.com/luxfi/pulsar> |
| Submission tag | `submission-2026-11-16` |
| Spec PDF | `spec/pulsar.pdf` |
| License | Apache-2.0 (code) + CC-BY-4.0 (docs/patents.md) |

## Headline claim

> Every signature produced by a Pulsar threshold ceremony (DKG →
> Round-1 → Round-2 → Combine) is **bit-identical** to a signature
> produced by single-party FIPS 204 ML-DSA-65 on the same message
> and group public key.

**Theorem framing**: accepted-path correctness. *If* the threshold
combine accepts (passes ML-DSA norm + kappa rejection checks),
*then* the produced byte string equals the centralized ML-DSA-65
signature on the same protocol-level inputs, under the stated layout,
algebraic, and byte-walk assumptions enumerated in
`docs/proof-axiom-inventory.md`. Acceptance probability is tracked separately
through `accept_signing_attempt` and `mldsa_accept_lower_bound`.

## Package contents (mapped to NIST IR 8214C requirements)

| NIST requirement | Pulsar artifact |
|---|---|
| Technical specification | `spec/pulsar.tex` → `spec/pulsar.pdf` |
| Open-source reference implementation | `ref/go/` (Apache-2.0) |
| Experimental evaluation report | `docs/evaluation.md` + `bench/results/REPORT.md` |
| Test vectors | `vectors/` (5 JSON sets + per-(n,t) transcripts) |
| Security analysis | `spec/pulsar.tex` §5 + `pulsar-m/*.tex` (separate audit artifact) |
| Patent / IP statement | `docs/patents.md` (royalty-free grant) + `docs/patent-claims.md` (attorney prep) |
| Known limitations | `BLOCKERS.md` + `SUBMISSION.md` §"Does NOT claim" |
| Contact / maintainers | `SUBMISSION.md` §Contact |

## What makes this submission different

1. **Byte-identical output to FIPS 204** — any FIPS-validated ML-DSA
   verifier (BoringSSL FIPS, AWS-LC, OpenSSL 3.0 PQ provider)
   accepts a Pulsar signature without modification. No verifier-side
   changes needed.

2. **Machine-checked refinement proof** — EasyCrypt N1 byte-equality
   theorem `pulsar_n1_byte_equality_extracted` (`proofs/easycrypt/`),
   13 files compile clean with 0/0 admits, Lean ↔ EC bridges verified
   at every CI push (5/5).

3. **Jasmin high-assurance implementation** — Threshold layer
   constant-time-clean under jasmin-ct (blocking gate 3/3); libjade
   single-party sign advisory under tracked issue #2.

4. **N4 reshare with public-key preservation** — proactive secret-
   sharing across committee rotation, preserving the group public
   key (`Pulsar_N4.reshare_preserves_secret_honest` theorem).

5. **Identifiable abort with third-party-verifiable evidence** —
   TLV-encoded per-kind abort evidence; verifier-protocol-independent;
   fuzz-tested at 627K execs (commit `effc648`).

6. **Reproducibility-first** — `scripts/build.sh` is deterministic
   from a 48-byte seed; KAT vectors regenerate bit-identical from
   the same seed; CI enforces drift = build bug.

## Trust footprint (one-screen summary)

After v10 (latest commit on submission branch):

| Category | Count | Notes |
|---|---|---|
| Stage-level byte-walks | 1 | `sign_body_z_spec` only |
| c_tilde dep w sub-stage | 2 | `*_body_w_spec` |
| c_tilde dep w_low sub-stage (v10) | 2 | `*_body_w_low_spec` |
| Combine z extraction (v8) | 2 | `combine_body_{partial_responses,z_via_aggregation}_spec` |
| Codec mu_input layout (v9) | 4 | 3 combine per-range + 1 sign byte-layout |
| Accepted-path no-reject | 2 | `*_no_reject_on_accepted_honest_layout` |
| Lean-bridged algebraic (v8) | 5 | Including `threshold_partial_response_identity` |
| Codec roundtrip (pack_n1) | 1 | `pack_unpack_n1_signature_roundtrip` |
| Per-type FIPS 204 codec roundtrips | ~21 | enumerated in `docs/proof-axiom-inventory.md` §7 |
| **Derived lemmas (no longer primitive)** | 11+ | `*_body_{c_tilde,mu,w1,mu_input,h}_spec` × 2 sides + `combine_body_z_spec` |
| EC admit budget | **0 / 0** | hard-pinned by `scripts/checks/ec-admits.sh` |

Full enumeration: `docs/proof-axiom-inventory.md`. Refinement chain:
`docs/proof-claims.md`. TCB: `docs/tcb.md`. FIPS 204 §-map:
`docs/fips-204-traceability.md`.

## What this submission does NOT claim

| Out-of-scope claim | Why |
|---|---|
| Post-quantum hardness of ML-DSA | Assumed from NIST FIPS 204 analysis |
| ACVP/CAVP algorithm validation certificate | Downstream — lab work post-submission |
| FIPS 140-3 module validation | Downstream — applies to packaged modules |
| Threshold SLH-DSA (FIPS 205) | Tier 3 experimental; not in v0.1 |
| Asynchronous identifiable abort | Synchronous only; async requires Z-Chain Groth16 accountability (separate Lux artifact) |
| 1-round signing | FIPS 204 rejection-sampling precludes 1-round without non-standard preprocessing |
| DKG without external randomness beacon | Honest-majority unbiased; production deployments bind a randomness beacon at the consensus layer |

## Reproducibility commitment

```bash
git clone --branch submission-2026-11-16 https://github.com/luxfi/pulsar
cd pulsar
opam switch jasmin && opam install . --deps-only
scripts/build.sh                # builds reference impl + spec PDF
scripts/check-high-assurance.sh # proof + CT gate (expect green)
scripts/test.sh                 # KAT cross-validation (expect 3-way match)
scripts/bench.sh                # performance (expect within 5% of REPORT.md)
```

Drift between submission tarball and reproduced output is a build
bug — please file at the GitHub issues link above. NIST reviewers
should obtain byte-identical artifacts on reproduction.

## Patent / IP posture (TL;DR)

- **Code**: Apache-2.0.
- **Patents**: Royalty-free grant to any FIPS 204-conformant implementation
  released under Apache-2.0 or compatible OSI license, OR any
  NIST MPTC/PQC/ACVP submission/validation/interoperability test.
- **Defensive termination**: license terminates against any party
  asserting patents against Pulsar, FIPS 204 ML-DSA, or any other
  NIST-standardized PQ signature scheme.
- **Full text**: `docs/patents.md` §3.

## Contact

| Purpose | Contact |
|---|---|
| Submission coordination | `mptc@lux.network` |
| Patent / IP inquiries | `legal@lux.network` |
| Security disclosure | See `SECURITY.md` |
| Public discussion | <https://github.com/luxfi/pulsar/discussions> |
| Primary maintainer | `z@lux.network` (Lux Industries, Inc.) |

## Roadmap (v0.2 and beyond)

| Milestone | Target |
|---|---|
| Close `sign_body_z_spec` via FROST z-aggregation Lean bridge | v0.2 |
| Close `*_body_w_spec` via ExpandA + ExpandMask + mat_vec_mul concretization | v0.3 |
| ACVP/CAVP pre-validation report | v0.3 |
| FIPS 140-3 module validation engagement | v0.4 |
| Rust + C + WASM reference implementations | v0.5 |
| External cryptographic audit (engaged lab) | v0.5 |
| Blockchain integration profiles (EVM, Cosmos, Substrate) | v0.6 |

The roadmap is published at `BLOCKERS.md` and tracked at the
GitHub issues link above.

---

**Document metadata**

- Name: `NIST-SUBMISSION.md`
- Version: v1.0 (post v10)
- Date: 2026-05-18
- Submission package version: Pulsar v0.1 (tagged `submission-2026-11-16` on cut date)
