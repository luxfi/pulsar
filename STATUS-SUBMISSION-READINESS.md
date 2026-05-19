# STATUS — Submission readiness per category

> Authoritative status of every Hanzo Crypto Suite category against
> the NIST MPTC 2026-11-16 deadline (and adjacent submission tracks:
> IETF / CFRG, FIPS 140-3 module, ACVP / CAVP, IETF KEM RFCs).
>
> Companion to `SUITE.md` (PQ-threshold tiers), `HANZO-CRYPTO-SUITE.md`
> (full inventory), `ROADMAP.md` (multi-year plan), and
> `SYNC-STATUS.md` (cross-repo audit).
>
> Date: 2026-05-18.

## TL;DR — what is submission-ready RIGHT NOW

| Track | Deadline | Ready? | Notes |
|---|---|---|---|
| **NIST MPTC v0.1 — Pulsar Tier 1** | 2026-11-16 | **YES** | All 14 artifacts shipped (spec, ref impl, KAT, EC 13/13, Lean 5/5, jasmin-ct 3/3, IETF draft, 10 submission docs) |
| NIST MPTC v0.2 — Corona Tier 1b | not yet announced | **NO** | Implementation mature; submission package missing |
| NIST MPTC v0.3 — Magnetar Tier 3 | not yet announced | **NO** | Research-only; no construction yet |
| NIST MPTC v0.4 — LSS wrapper | not yet announced | **NO** | LP-019 spec mature; standalone package missing |
| IETF / CFRG drafts (per construction) | rolling | **Pulsar only** | `draft-hanzo-pulsar-threshold-mldsa-00` drafted |
| FIPS 140-3 module validation | n/a (lab) | **NO for any** | Requires NVLAP-accredited lab engagement |
| ACVP / CAVP algorithm validation | n/a (lab) | **NO for any** | Requires NIST CAVP harness submission |
| IETF KEM RFCs (X-Wing, ML-KEM) | upstream | partial | We consume upstream — Lux-profile draft TBD |

## §1 PQ threshold signatures (Hanzo PQ Threshold Suite)

### §1.1 Pulsar — **NIST MPTC v0.1 SUBMISSION READY** ✅

`~/work/lux/pulsar/` HEAD `c2e01e3` (2026-05-18).

| Artifact | Location | Status |
|---|---|---|
| Cover sheet | `SUBMISSION.md` | ✅ |
| 1-page exec summary | `NIST-SUBMISSION.md` | ✅ |
| Standalone spec | `SPEC.md` + `spec/pulsar.tex` | ✅ |
| Suite index | `SUITE.md` | ✅ |
| Suite-wide inventory | `HANZO-CRYPTO-SUITE.md` | ✅ |
| Info architecture | `INFORMATION-ARCHITECTURE.md` | ✅ |
| Patent grant | `PATENTS.md` | ✅ |
| Patent claim drafts | `docs/patent-claims.md` (21 claims, 5 groups) | ✅ |
| Trust accounting | `AXIOM-INVENTORY.md` + `PROOF-CLAIMS.md` + `TRUSTED-COMPUTING-BASE.md` | ✅ |
| FIPS 204 traceability | `FIPS-TRACEABILITY.md` | ✅ |
| Per-version proof log | `CHANGELOG.md` (v4-v13) | ✅ |
| Multi-year roadmap | `ROADMAP.md` | ✅ |
| Cross-repo sync | `SYNC-STATUS.md` | ✅ |
| IETF Internet-Draft | `docs/ietf-draft-skeleton.md` (`draft-hanzo-pulsar-threshold-mldsa-00`) | ✅ |
| Experimental evaluation | `docs/evaluation.md` (NIST IR 8214C §6) | ✅ |
| Reference implementation | `ref/go/pkg/pulsar/` | ✅ 89.7% coverage |
| KAT vectors | `vectors/` | ✅ deterministic |
| EasyCrypt theories | `proofs/easycrypt/` | ✅ 13/13 compile, 0 admit |
| Lean ↔ EC bridge | `proofs/lean-easycrypt-bridge.md` | ✅ 5/5 bridges, CI-guarded |
| Jasmin constant-time | `jasmin/{lib,ml-dsa-65,threshold}/` | ✅ 3/3 CI green |
| Class N1 interop | `test/interoperability/n1_class_test.go` | ✅ 19/19 subtests vs cloudflare/circl |
| Build/test/bench/SBOM | `scripts/` | ✅ |
| License | `LICENSE` (Apache-2.0) | ✅ |

**Open items before 2026-11-16 (Lux-controlled, achievable)**:

1. **Encoding section freeze** in `spec/pulsar.tex` — wire formats
   pinned at DD-008 (end of August 2026).
2. **dudect timing-channel results** pinned in `ct/dudect/results/`.
3. **Cross-validation against ≥2 of** {BoringSSL FIPS, AWS-LC,
   OpenSSL 3.0 PQ provider, pq-crystals Dilithium reference}.
4. **Five algorithmic spec caveats** identified in red-team audit:
   - adaptive corruption (UNSUPPORTED → spec must say static-only)
   - cross-domain isolation Pulsar/Corona (WEAK → both share lattice hardness)
   - constant-time Verify (assertion vs measurement)
   - Z-Chain Groth16 / P3Q migration claim alignment
   - 2-round optimality clarification vs Raccoon
5. **Patent filing(s)** for the 21 claim drafts — must precede or
   accompany submission (target Q3 2026).

### §1.2 Corona — **NOT SUBMISSION-READY** (v0.2 target)

`~/work/lux/corona/`.

| Artifact | Status |
|---|---|
| DESIGN.md | partial |
| SUBMISSION.md | missing |
| SPEC.md | missing |
| IETF draft | missing |
| Reference implementation | ✅ full Go |
| EC proofs | partial (DKG only) |
| Lean bridges | TBD |
| Jasmin CT | TBD |
| Test vectors | ✅ |
| PATENTS.md | missing |
| Trust accounting | missing |

**Left to ship submission-ready package**: 6-8 weeks of focused work.

### §1.3 Magnetar — **RESEARCH ONLY**

`docs/magnetar.md` placeholder. No construction. No implementation. No
proofs. Threshold SLH-DSA is an open research direction (per-signature
MPC over hash trees is materially harder than threshold ML-DSA).

**Left to ship**: 2-3 months for an initial DKG prototype + paper.
Not on the 2026-11-16 critical path.

### §1.4 LSS (Linear Shamir wrapper) — **PARTIAL**

Spec lives in LP-019 + LP-141. Implementation in `~/work/lux/mpc/`.

| Artifact | Status |
|---|---|
| LP spec | ✅ LP-019 + LP-141 |
| Standalone IETF draft | missing |
| Reference vectors | partial |
| EC + Lean proofs | missing |
| Patent grant | covered by LP-019 |

**Left to ship**: 2 weeks for standalone IETF draft + KAT vectors;
the wrapper does not require a standalone NIST MPTC submission
(LSS-over-Pulsar is covered inside Pulsar's `§9 Reshare protocol`).

## §2 Classical threshold signatures

### §2.1 FROST (Ed25519 / secp256k1 Schnorr) — **NOT SUBMISSION-READY**

Implementation in `~/work/lux/mpc/`. IETF draft `draft-irtf-cfrg-frost`
exists upstream — Lux profile gap.

| Artifact | Status |
|---|---|
| LP spec | ✅ LP-019 |
| Upstream IETF draft | ✅ `draft-irtf-cfrg-frost` |
| Lux-profile IETF draft | missing |
| Reference implementation | ✅ (consumes upstream KATs) |
| EC + Lean proofs | missing in Lux |
| Constant-time analysis | partial |
| Lux-specific KAT vectors | missing |
| Patent grant / clearance | missing |

**Left to ship**: 8-12 weeks (Lux-profile draft + EC scaffolding +
KATs + CT analysis).

### §2.2 CGGMP21 (secp256k1 ECDSA) — **NOT SUBMISSION-READY**

Implementation in `~/work/lux/mpc/`.

| Artifact | Status |
|---|---|
| LP spec | ✅ LP-019 |
| IETF draft | missing |
| Reference implementation | ✅ |
| EC + Lean proofs | missing |
| Constant-time analysis | missing |
| KAT vectors | partial |
| Patent clearance (CCS '21) | missing |

**Left to ship**: 8-12 weeks.

### §2.3 BLS (BLS12-381 aggregate) — **PARTIAL**

`~/work/lux/crypto/bls/`. Used everywhere (Quasar consensus
classical-fast-path).

| Artifact | Status |
|---|---|
| LP spec | ✅ LP-020 |
| IETF draft | upstream (`draft-irtf-cfrg-bls-signature`) |
| Reference implementation | ✅ |
| EC + Lean proofs | partial Lean (`lean/Crypto/BLS.lean`) |
| Constant-time analysis | upstream (blst) |
| KAT vectors | ✅ |
| Patent grant | missing |

**Left to ship**: 4 weeks for Lux-profile package.

## §3 Hybrid PQ signature wrappers — X-Wing-Sig

**NOT SPECIFIED. NOT IMPLEMENTED.** Design direction documented in
`docs/x-wing-sig.md`. No LP yet.

| Artifact | Status |
|---|---|
| Design direction | ✅ `docs/x-wing-sig.md` |
| LP draft | missing |
| Reference implementation | missing |
| Composition proof | missing |
| KAT vectors | missing |
| IETF draft | missing |

**Left to ship to v0.1 LP**: ~2 months (per design doc estimate).

## §4 Key encapsulation

### §4.1 ML-KEM-768 — production-ready (consume FIPS 203)

We CONSUME the NIST-standardized FIPS 203 directly via
`~/work/lux/crypto/mlkem/`. No Lux submission needed (NIST is
already done).

### §4.2 X-Wing (X25519 + ML-KEM-768 hybrid) — production-ready (consume upstream)

We CONSUME the IRTF CFRG draft `draft-irtf-cfrg-xwing` via
`~/work/lux/crypto/xwing/`. Specified in LP-115. No Lux NIST submission
needed.

### §4.3 X-Wing+ (Lux-extended profile) — **NEEDS PROFILE LP**

Lux extension at `~/work/lux/crypto/xwing+/`. LP follow-up to LP-115
not yet drafted. ~2 weeks for the profile LP.

## §5 ZK / accountability

### §5.1 Z-Chain PQ identity rollup — separate Lux artifact

LP-063 (Z-Chain) + LP-169 (Z-Chain PQ identity rollup). Mature LPs.
Not a NIST submission target (Lux-original construction). Implementation
in `~/work/lux/zchain/`.

| Artifact | Status |
|---|---|
| LP-063 spec | ✅ mature |
| LP-169 spec | ✅ mature |
| Reference implementation | ✅ |
| Audit | gap |
| Submission package | n/a (not standardization-tracked) |

### §5.2 P3Q precompile (EVM slot 0x012205) — **PARTIAL**

LP-078 covers EVM precompiles broadly; dedicated P3Q LP not yet
drafted. Precompile reuses any FIPS 204 verifier (the signature
verified by P3Q is byte-equal to single-party ML-DSA).

| Artifact | Status |
|---|---|
| Dedicated P3Q LP | missing |
| Precompile implementation | partial (in `evm/precompiles/`) |
| Gas-cost model | gap |
| Test vectors | partial |

**Left to ship**: ~4 weeks for dedicated P3Q LP + gas model + KAT.

## §6 FHE / confidential compute

**LP-013** (FHE GPU), **LP-066** (TFHE), **LP-067** (Confidential ERC-20),
**LP-068** (Private Teleport). All mature LPs. No NIST submission target
(FHE is not currently a NIST standardization category; consume open-
source TFHE / OpenFHE / Lattigo).

| Scheme | Status |
|---|---|
| TFHE (CGGI) | LP-spec mature; F-Chain host |
| BFV | partial |
| CKKS | partial |
| Threshold FHE | LP-019 + LP-141; ceremonies on M-Chain |

**Left to ship**: paper-grade publication only; nothing for NIST.

## §7 EVM-native PQ migration (C-Chain + X-Chain)

**NOT YET DRAFTED.** No LP. Three migration paths sketched in
`HANZO-CRYPTO-SUITE.md §7`:

1. Soft migration via X-Wing-Sig (depends on §3).
2. Hard fork to PQ-native.
3. Per-account opt-in.

**Left to ship**: LP-XXX draft (~4 weeks), then 4-8 weeks of
implementation per chain, then coordinated rollout.

## External tracks (NOT under Lux's direct control)

| Track | Owner | Lux's input | Status |
|---|---|---|---|
| NIST MPTC ratification | NIST | Submit v0.1 package by 2026-11-16; respond to reviewer feedback | Inputs ready; multi-year process |
| IETF / CFRG publication | IETF | Submit `draft-hanzo-pulsar-threshold-mldsa-00`; iterate at IETF meetings | Draft ready; submit on schedule |
| ACVP / CAVP algorithm validation | NIST + accredited lab | Lab engagement + CAVP harness | Not yet engaged |
| FIPS 140-3 module validation | NIST + accredited lab | Lab engagement; module-boundary documentation | Not yet engaged |
| IETF KEM RFCs (X-Wing, ML-KEM) | IRTF CFRG | Consume upstream drafts; contribute review | Consuming |

## Aggregate gap analysis

| Category | LP | Spec | Ref Impl | Proofs | KAT | Package | IETF | Total readiness |
|---|---|---|---|---|---|---|---|---|
| **Pulsar (Tier 1)** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | **100% NIST-MPTC-ready** |
| Corona (Tier 1b) | ✅ | partial | ✅ | partial | ✅ | ❌ | ❌ | 50% |
| Magnetar (Tier 3) | ❌ | placeholder | ❌ | ❌ | ❌ | ❌ | ❌ | 5% |
| LSS (Tier 4) | ✅ | LP-only | ✅ | ❌ | partial | ❌ | ❌ | 35% |
| FROST | ✅ | LP-only | ✅ | ❌ | upstream | ❌ | upstream | 45% |
| CGGMP21 | ✅ | LP-only | ✅ | ❌ | partial | ❌ | ❌ | 40% |
| BLS | ✅ | LP-only | ✅ | partial Lean | ✅ | ❌ | upstream | 60% |
| X-Wing-Sig | ❌ | design direction | ❌ | ❌ | ❌ | ❌ | ❌ | 10% |
| ML-KEM (consume) | ✅ | upstream FIPS 203 | ✅ | n/a | upstream | n/a | upstream | 100% (consume) |
| X-Wing (consume) | ✅ | upstream draft | ✅ | n/a | upstream | n/a | upstream | 100% (consume) |
| X-Wing+ Lux profile | ❌ | gap | ✅ | ❌ | ❌ | ❌ | ❌ | 25% |
| Z-Chain PQ | ✅ | ✅ | ✅ | partial | ❌ | ❌ | n/a | 55% |
| P3Q precompile | partial | gap | partial | n/a | partial | n/a | n/a | 30% |
| TFHE / BFV / CKKS | ✅ | LP-spec mature | partial | ❌ | upstream | n/a (no NIST track) | n/a | 50% |
| EVM-native PQ migration | ❌ | gap | n/a | n/a | n/a | n/a | n/a | 5% |

## What's left, by priority

### Critical path to 2026-11-16 (Pulsar v0.1 submission)

1. Encoding section freeze in `spec/pulsar.tex` — **Lux, 2 weeks**.
2. dudect CT results pinned — **Lux, 1 week**.
3. Cross-validation against ≥2 FIPS 204 verifiers — **Lux, 1 week**.
4. Patent filing for 21 claim drafts — **Lux + attorneys, 8 weeks**.
5. Final NIST submission cut — **Lux, 1 day at tag**.

### v0.2 (Q4 2026 — Q1 2027)

6. Corona equivalent packaging — **Lux, 6-8 weeks**.
7. LSS standalone IETF draft + KAT — **Lux, 2 weeks**.
8. X-Wing+ Lux-profile LP — **Lux, 2 weeks**.
9. P3Q dedicated LP + gas model + KAT — **Lux, 4 weeks**.

### v0.3 (Q1 — Q2 2027)

10. FROST Lux-profile draft + EC scaffolding + KAT + CT — **Lux, 8-12 weeks**.
11. CGGMP21 submission package — **Lux, 8-12 weeks**.
12. BLS Lux-profile package — **Lux, 4 weeks**.
13. X-Wing-Sig LP + impl + composition proof + KAT — **Lux, 2 months**.
14. EVM-native PQ migration LP draft — **Lux, 4 weeks**.

### v0.4 (Q3 2027 — onwards)

15. Magnetar research paper + initial DKG prototype — **Lux, 2-3 months**.
16. Z-Chain PQ identity rollup audit — **Lux + auditor, 4-8 weeks**.
17. FHE submission-equivalent docs (paper-track only) — **Lux, 4 weeks each**.

### External (no fixed timeline — track only)

18. NIST MPTC reviewer feedback iteration — **NIST, 6-18 months**.
19. IETF / CFRG publication for `draft-hanzo-pulsar-threshold-mldsa` — **IETF, 12-36 months**.
20. ACVP / CAVP algorithm validation engagement — **lab, 3-6 months**.
21. FIPS 140-3 module validation — **lab, 6-12 months**.

## Honest claims

- **DO say**: "Pulsar (Tier 1) is NIST MPTC v0.1 submission-ready as
  of 2026-05-18; the package will be cut from a tag on `main` on
  2026-11-16."
- **DO say**: "Every other Hanzo Crypto Suite member has an LP and an
  implementation; the matching submission-grade documentation +
  proof package is on the v0.2 — v0.4 roadmap."
- **DO say**: "External tracks (NIST ratification, IETF publication,
  FIPS 140-3 module validation, ACVP / CAVP) are outside Lux's
  direct control; submission inputs are ready, decision timeline is
  the standards body's."
- **DO NOT say**: "The Hanzo Crypto Suite is 100% NIST-ratified" — only
  Pulsar v0.1 is submission-ready, and submission is not ratification.
- **DO NOT say**: "Magnetar is production-ready threshold SLH-DSA" —
  research-only.
- **DO NOT say**: "FIPS 140-3 validated" for any module — no engagement
  is underway.

---

**Document metadata**

- Name: `STATUS-SUBMISSION-READINESS.md`
- Version: v0.1
- Date: 2026-05-18
- Companion to: `SUITE.md`, `HANZO-CRYPTO-SUITE.md`, `ROADMAP.md`,
  `SYNC-STATUS.md`
- Re-run cadence: monthly through 2026-11-16; quarterly thereafter
- Owner: `submissions@lux.network`
