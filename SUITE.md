# Hanzo PQ Threshold Suite — index

> Master index for the **Hanzo PQ Threshold Suite**: a coordinated
> set of post-quantum threshold-signing protocols anchored to NIST
> standards (FIPS 204 ML-DSA, FIPS 205 SLH-DSA) and Lux's R-LWE
> sibling (Corona).

## Tiers

| Tier | Name | Primitive | Status | Home |
|---|---|---|---|---|
| **Tier 1** | **Pulsar** | FIPS 204 ML-DSA (M-LWE) | **v0.1 — NIST MPTC submission-ready** | `~/work/lux/pulsar-mptc/` (this repo) |
| Tier 1b | **Corona** | R-LWE (sibling) | Production reference + DKG impl | `~/work/lux/corona/` |
| Tier 2 | SLH-DSA single-party compatibility | FIPS 205 SLH-DSA | Standard-verifier-compatible | Out-of-scope this suite (use FIPS 205 directly) |
| **Tier 3** | **Magnetar** | FIPS 205 SLH-DSA via MPC | **Research-track — not for v0.1 production** | `docs/magnetar.md` (this repo) |
| Tier 4 | **LSS** | Linear Shamir's Secret Sharing | Wrapper enabling dynamic resharing across Tiers 1 + 1b | `~/work/lux/lps/LP-019-threshold-mpc.md` |

## Naming

| Identifier | Means |
|---|---|
| `HANZO-PQ-THRESHOLD-SUITE-v0.1` | The suite version covered by this index |
| `PULSAR-THRESHOLD-ML-DSA-{44,65,87}` | Pulsar parameter sets (NIST cat 2/3/5) |
| `MAGNETAR-THRESHOLD-SLH-DSA-SHAKE-{192s,256s}` | Magnetar parameter sets (FIPS 205 SHAKE profile) |
| `CORONA-THRESHOLD-RING-LWE-{44,65,87}` | Corona parameter sets (Lux R-LWE) |

## Submission packaging per tier

Each tier targets the **same submission-grade documentation package**
(SUBMISSION.md cover sheet, SPEC.md / IETF draft, EC + Lean proof
artifacts, PATENTS.md, AXIOM-INVENTORY.md, PROOF-CLAIMS.md,
FIPS-TRACEABILITY.md, TRUSTED-COMPUTING-BASE.md, test vectors,
docs/evaluation.md). Status by tier:

| Doc | Pulsar | Corona | Magnetar | LSS |
|---|---|---|---|---|
| Cover sheet (`SUBMISSION.md`) | ✅ | partial (`~/work/lux/corona/DESIGN.md`) | placeholder | LP-019 (LPS) |
| Standalone spec (`SPEC.md`) | ✅ | TBD | TBD | LP-019 (LPS) |
| IETF draft | ✅ `docs/ietf-draft-skeleton.md` | TBD | TBD | TBD |
| Reference impl | ✅ `ref/go/` | ✅ `~/work/lux/corona/` (full Go) | ❌ research-only | ✅ `~/work/lux/lps/` LP-019 + LP-141 |
| EC proofs | ✅ 13/13 compile | partial (DKG only) | ❌ | ❌ |
| Lean bridges | ✅ 5/5 | TBD | TBD | TBD |
| Jasmin CT | ✅ 3/3 | TBD | ❌ | ❌ |
| Test vectors | ✅ `vectors/` | ✅ `~/work/lux/corona/` | ❌ | partial |
| PATENTS | ✅ | TBD | TBD | covered by `~/work/lux/lps/PATENTS-OVERVIEW.md` if it exists |
| Trust accounting | ✅ AXIOM-INVENTORY + PROOF-CLAIMS + TCB | TBD | TBD | TBD |

**Equivalent-packaging roadmap** (post v0.1 submission):
- v0.2 (Q1 2027): Corona full submission package matching Pulsar's
  structure; Corona is the R-LWE sibling so the proof technique
  largely transfers.
- v0.3 (Q2 2027): Magnetar research draft + initial proof-of-concept
  DKG (SLH-DSA is hash-based — threshold construction is materially
  different; expect research-paper-grade artifact, not
  production-grade).
- v0.4 (Q3 2027): LSS full IETF draft (currently LP-019 in `~/work/lux/lps/`).

## Information architecture

```
~/work/lux/
├── pulsar-mptc/              ← Tier 1, this repo (NIST MPTC submission target)
│   ├── SUBMISSION.md         ← NIST cover sheet
│   ├── SUITE.md              ← THIS file (master index)
│   ├── SPEC.md               ← standalone protocol spec
│   ├── PATENTS.md            ← royalty-free grant
│   ├── AXIOM-INVENTORY.md
│   ├── PROOF-CLAIMS.md
│   ├── FIPS-TRACEABILITY.md
│   ├── TRUSTED-COMPUTING-BASE.md
│   ├── NIST-SUBMISSION.md    ← 1-page executive summary
│   ├── CHANGELOG.md          ← per-version proof artifact log
│   ├── docs/
│   │   ├── ietf-draft-skeleton.md      ← Tier 1 IETF draft
│   │   ├── magnetar.md                  ← Tier 3 research placeholder
│   │   ├── patent-claims.md             ← attorney prep (21 claims)
│   │   └── evaluation.md                ← NIST IR 8214C §6
│   ├── spec/pulsar.tex/.pdf
│   ├── ref/go/
│   ├── proofs/easycrypt/
│   ├── jasmin/threshold/
│   └── vectors/
│
├── corona/                   ← Tier 1b R-LWE sibling
│   ├── DESIGN.md, CONSTANT-TIME-REVIEW.md
│   ├── cli/, cmd/, dkg/, dkg2/, ...
│   └── (v0.2 target: parallel SUBMISSION/SPEC/PATENTS structure)
│
├── kms/                      ← key-management service (consumer)
├── mpc/                      ← general MPC infrastructure (consumer)
│
└── lps/                      ← Lux Proposal System (LP-NNN canonical specs)
    ├── CRYPTO-CANONICAL.md   ← master crypto wiring doc
    ├── LP-012-pq-crypto-gpu.md          ← PQ crypto GPU acceleration
    ├── LP-019-threshold-mpc.md          ← Threshold MPC (FROST, CGGMP21, LSS)
    ├── LP-020-quasar-consensus.md       ← Quasar consensus PQ-signature usage
    ├── LP-134-chain-topology.md         ← M-Chain (MPC) + F-Chain (FHE) split
    └── LP-141-threshold-vm.md           ← Threshold VM substrate
```

## Cross-references between tiers

- **Pulsar ↔ Corona**: parallel constructions (M-LWE vs R-LWE);
  each produces byte-identical signatures to its respective NIST
  standard. Quasar consensus (LP-020) uses BOTH as parallel
  options selectable per-chain.
- **Pulsar ↔ Magnetar**: orthogonal primitives (lattice vs
  hash-based); Magnetar deployment is for paranoid scenarios where
  ML-DSA is broken but SLH-DSA remains secure.
- **Pulsar ↔ LSS**: LSS provides the dynamic-resharing wrapper.
  Pulsar's own §9 reshare protocol is conceptually equivalent to
  LSS's zero-secret refresh.
- **Corona ↔ LSS**: LSS works over any linear secret-sharing
  scheme; Corona shares are linear in R_q^l, so LSS applies.

## Suite-level invariants

All Tier 1 / Tier 1b constructions in the Hanzo PQ Threshold Suite
MUST satisfy:

1. **Standard-verifier compatibility**: signatures verify under
   the underlying NIST standard's unmodified verifier.
2. **Public-DKG**: no trusted dealer; all share generation
   publicly verifiable.
3. **Identifiable abort**: synchronous-network blame with
   third-party-verifiable evidence.
4. **Public-key preservation across resharing**: long-lived public
   identity, rotating custodians.
5. **Submission-grade documentation**: every primitive PROOF or
   IMPLEMENTATION axiom enumerated in an AXIOM-INVENTORY-equivalent
   document with explicit closure plan.

## v0.1 submission scope

This v0.1 submission ships **Pulsar Tier 1 only**. Corona, Magnetar,
and LSS exist in the suite but are not packaged for the 2026 NIST
MPTC submission. Their packaging is on the v0.2-v0.4 roadmap above.

---

**Document metadata**

- Name: `SUITE.md`
- Version: v0.1
- Date: 2026-05-18
- Maintainer: `suite@lux.network`
