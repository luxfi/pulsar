# NIST MPTC category targeting

> Reference: NIST IR 8214C, *First Call for Multi-Party Threshold Schemes*
> (January 2026). Package deadline expected 2026-Nov-16. Preview deadline
> 2026-Jul-20.

## Pulsar-M target: **Class N1 + N4**

NIST MPTC subdivides threshold schemes into:

- **Class S** (Special) — threshold-friendly primitives that *are not*
  output-interchangeable with a NIST-specified primitive. Submission
  evaluated for "novel threshold-friendly design."
- **Class N** (Normal-mode) — threshold implementations *of* a NIST-specified
  primitive whose outputs are interchangeable with the corresponding
  non-threshold primitive's outputs.
  - **N1**: signing
  - **N2**: encryption / decryption
  - **N3**: KEM
  - **N4**: ML keygen / DKG (Module-Lattice key generation, distributed)

Pulsar-M aims for **N1 (threshold ML-DSA signing) + N4 (distributed ML-DSA
keygen)**. The headline interchangeability claim:

> A signature `σ` produced by a Pulsar-M threshold ceremony on message `μ`
> against group public key `pk` verifies under unmodified
> [FIPS 204 ML-DSA.Verify(pk, μ, σ)] returning `accept`.

If we can prove and demonstrate this, Pulsar-M is a Class N candidate. If
the output is not bit-for-bit FIPS 204 (e.g. encoding differs in any
field), Pulsar-M falls back to Class S — still valid, but a weaker NIST
positioning.

## Output interchangeability — what has to hold

ML-DSA-65 signatures (FIPS 204 §5.4, Algorithm 26 `sigEncode`) are
encoded as a fixed-length 3309-byte string σ = (c̃, z, h) whose three
components decompose exactly as:

```
σ = (c̃ ‖ z ‖ h)                                              3309 bytes
  c̃ ∈ {0,1}^{2λ}                                              48 bytes
        // FIPS 204 commitment-hash length; 2λ bits with λ=192 = 384 bits.
        // (2λ here is the FIPS 204 commitment-hash parameter, not the
        // security level — the two happen to numerically agree for
        // ML-DSA-65 because the standard ties one to the other at this
        // parameter set.)
  z ∈ R^ℓ_q                                                  3200 bytes
        // ℓ = 5 polynomials, each 256 coefficients, packed at
        // log2(2γ_1) = 20 bits per coefficient.
        // 5 · 256 · 20 / 8 = 3200 bytes.
  h ∈ {0,1}^{ω + k}                                            61 bytes
        // ω = 55 (hint bound), k = 6 (commitment-vector dimension).
        // FIPS 204 Algorithm 22 `hintBitPack` + Algorithm 28
        // `sigEncode` pack ω + k = 61 bits as 61 bytes (one byte per
        // bit position, terminator-first encoding per the standard).
  total: 48 + 3200 + 61 = 3309 bytes                           ✓ FIPS 204 Table 2
```

For Pulsar-M to claim Class N1, the threshold-aggregated signature MUST
deserialize as exactly this triple, with the same byte layout, the same
canonicalization rules, and the same rejection criteria. The threshold
protocol is allowed to perform multiple rounds internally, but its emitted
artifact MUST be a single FIPS 204 σ.

This is non-trivial: ML-DSA's rejection sampling means a single-shot
threshold output can fail rejection and require restart. Pulsar's
2-round structure handles this for R-LWE; Pulsar-M needs to reproduce
the rejection-restart logic for M-LWE without leaking secret information
across the restart.

## Required package deliverables

Per NIST IR 8214C §5:

| element | format | location |
|---|---|---|
| Technical Specification | PDF (LaTeX) | `spec/pulsar-m.pdf` |
| Reference Implementation | open-source code | `ref/go/` |
| Report on Experimental Evaluation | PDF + reproducible scripts | `bench/results/REPORT.md` + `bench/run_all.sh` |
| Notes on Patent Claims | PDF | `docs/patent-notes-draft.md` → finalized |
| Concrete parameter set | section in spec | `spec/parameters.tex` |
| Security analysis (proofs) | section in spec | `spec/security-games.tex` |
| Public repository | GitHub or equiv | `https://github.com/luxfi/pulsar-m` |
| Build/test/benchmark scripts | shell | `scripts/*.sh` |
| Open-source license | text | `LICENSE` (Apache-2.0) |
| I/O test vectors | JSON / RSP | `vectors/kat-v1.{json,rsp}` |

Optional but strongly recommended:
- Executive summary (1-2 pages) at front of spec.
- Threat-model document (`docs/threat-model.md`).
- System-model document (`docs/system-model.md` → `spec/system-model.tex`).
- Known-limitations appendix (so reviewers see the gaps before they find them).

## Required security strengths

NIST MPTC §4.5 gives the required and suggested security-strength targets:

| target | classical | post-quantum (NIST PQ category) | statistical |
|---|---|---|---|
| **required** (≥1 parameterization) | ≥ 128 bits | ≥ Category 1 | ≥ 40 bits |
| **suggested** (additional, optional) | ≥ 192 bits | ≥ Category 3 | ≥ 64 bits |

Pulsar-M will ship parameter sets matching ML-DSA-65 (Category 3) for the
suggested target, and potentially ML-DSA-44 (Category 2) and ML-DSA-87
(Category 5) for full coverage.

## Class N vs Class S decision

Pulsar-M is N if and only if:
1. A working reference implementation produces signatures byte-equal to
   FIPS 204 ML-DSA on the same `(pk, μ)` for some valid threshold ceremony.
2. The threshold key generation produces a `pk` that's a valid FIPS 204
   ML-DSA public key (no extra public material distinguishable from a
   single-party `pk`).
3. The verification relation in the spec is the FIPS 204 verifier
   verbatim, with no Pulsar-specific changes.

If any of (1)-(3) fails, we ship as Class S with a clear "future work:
output interchangeability" note. The class decision is finalized at the
point we freeze the spec encoding.

## Pulsar (R-LWE) for comparison

Pulsar (R-LWE) targets **Class S1 + S4**: special threshold-friendly
two-round signature, not output-interchangeable with any NIST-approved
primitive. The S1/S4 framing is the right framing for Ringtail-derivatives
unless and until NIST blesses Ringtail-shaped outputs as a primitive.

## Status

- [ ] Class declared (N vs S, awaiting spec freeze)
- [ ] Preview writeup drafted
- [ ] Preview submitted (target 2026-Jul-20)
- [ ] Spec freeze
- [ ] Reference impl complete
- [ ] KATs cross-validated against FIPS 204 reference
- [ ] Experimental-evaluation report
- [ ] Patent-claims notes finalized
- [ ] Package submitted (target 2026-Nov-16)
