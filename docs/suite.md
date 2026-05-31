# Hanzo PQ Threshold Suite — index

> Master index for the **Hanzo PQ Threshold Suite**: a coordinated
> set of post-quantum threshold-signing protocols anchored to NIST
> standards (FIPS 204 ML-DSA, FIPS 205 SLH-DSA) and Lux's R-LWE
> sibling (Corona). Pulsar is Tier 1 — the rest of this document
> places it in context across the broader Lux/Hanzo crypto inventory.

## Tiers

| Tier | Name | Primitive | Status | Home |
|---|---|---|---|---|
| **Tier 1** | **Pulsar** | FIPS 204 ML-DSA (M-LWE) | **v0.1 — NIST MPTC submission-ready** | this repo |
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
(SUBMISSION.md cover sheet, docs/spec-overview.md / IETF draft, EC + Lean proof
artifacts, docs/patents.md, docs/proof-axiom-inventory.md, docs/proof-claims.md,
docs/fips-204-traceability.md, docs/tcb.md, test vectors,
docs/evaluation.md). Status by tier:

| Doc | Pulsar | Corona | Magnetar | LSS |
|---|---|---|---|---|
| Cover sheet (`SUBMISSION.md`) | ✅ | partial (`~/work/lux/corona/DESIGN.md`) | placeholder | LP-019 (LPS) |
| Standalone spec (`docs/spec-overview.md`) | ✅ | v0.2+ | v0.3+ | LP-019 (LPS) |
| IETF draft | ✅ `docs/ietf-draft-skeleton.md` | v0.2+ | v0.3+ | v0.2+ |
| Reference impl | ✅ `ref/go/` | ✅ `~/work/lux/corona/` (full Go) | ❌ research-only | ✅ `~/work/lux/lps/` LP-019 + LP-141 |
| EC proofs | ✅ 13/13 compile | partial (DKG only) | ❌ | ❌ |
| Lean bridges | ✅ 5/5 | v0.2+ | v0.3+ | v0.2+ |
| Jasmin CT | ✅ 3/3 | v0.2+ | ❌ | ❌ |
| Test vectors | ✅ `vectors/` | ✅ `~/work/lux/corona/` | ❌ | partial |
| PATENTS | ✅ | v0.2+ | v0.3+ | covered by `~/work/lux/lps/PATENTS-OVERVIEW.md` if it exists |
| Trust accounting | ✅ proof-axiom-inventory + proof-claims + tcb | v0.2+ | v0.3+ | v0.2+ |

**Equivalent-packaging roadmap** (post v0.1 submission):
- v0.2 (Q1 2027): Corona full submission package matching Pulsar's
  structure; Corona is the R-LWE sibling so the proof technique
  largely transfers.
- v0.3 (Q2 2027): Magnetar research draft + initial proof-of-concept
  DKG (SLH-DSA is hash-based — threshold construction is materially
  different; expect research-paper-grade artifact, not
  production-grade).
- v0.4 (Q3 2027): LSS full IETF draft (currently LP-019 in `~/work/lux/lps/`).

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
   IMPLEMENTATION axiom enumerated in a proof-axiom-inventory-equivalent
   document with explicit closure plan.

## v0.1 submission scope

This v0.1 submission ships **Pulsar Tier 1 only**. Corona, Magnetar,
and LSS exist in the suite but are not packaged for the 2026 NIST
MPTC submission. Their packaging is on the v0.2-v0.4 roadmap above.

---

# Appendix — broader Lux/Hanzo crypto inventory

> The PQ threshold suite above is **one subset** of the broader Lux
> crypto landscape. The remainder of this document inventories the
> other constructions (classical threshold, hybrid wrappers, KEM,
> ZK accountability, FHE, EVM PQ migration) for cross-referencing
> only — none of them are in the v0.1 NIST MPTC submission.

## Quick orientation

| Category | Tiers | Section below |
|---|---|---|
| **Post-quantum threshold signatures** | Pulsar, Magnetar, Corona | §A1 |
| **Classical threshold signatures** | FROST, CGGMP21, LSS, BLS | §A2 |
| **Hybrid PQ signature wrappers** | X-Wing-for-Signatures (proposed) | §A3 |
| **Key encapsulation** | ML-KEM, X-Wing | §A4 |
| **Zero-knowledge / accountability** | Z-Chain PQ, P3Q precompile | §A5 |
| **FHE / confidential compute** | TFHE on F-Chain, BFV, CKKS | §A6 |
| **EVM-native PQ migration** | C-Chain + X-Chain → PQ-native | §A7 |

## §A1 PQ threshold signatures (re-summarised)

See the Tiers table at the top of this document. Submission package
home: this repo (Tier 1 Pulsar).

| Tier | Construction | LP | Repo | Spec | Proofs | NIST submission | Status |
|---|---|---|---|---|---|---|---|
| 1 | **Pulsar** (Threshold ML-DSA) | LP-019 ref'd | this repo | ✅ docs/spec-overview.md + spec/pulsar.tex + IETF draft | ✅ EC 13/13, Lean 5/5 | ✅ v0.1 ready | **NIST-MPTC-submission ready** |
| 1b | **Corona** (Threshold R-LWE) | LP-020 | `~/work/lux/corona/` | partial DESIGN.md | partial DKG proofs | ❌ v0.2 target | implementation mature, packaging needed |
| 3 | **Magnetar** (Threshold SLH-DSA) | v0.2+ | none | `docs/magnetar.md` placeholder | ❌ | ❌ research-only | research-direction sketch |
| 4 | **LSS** (Linear Shamir) | LP-019 + LP-141 | `~/work/lux/lps/`, `~/work/lux/mpc/` | LP-019 sections | none mechanized | ❌ wrapper-only | spec exists, no submission package |

## §A2 Classical threshold signatures

Used for bridging to non-PQ chains (Bitcoin secp256k1, Ethereum
legacy, Cosmos Ed25519, Solana, etc.). Specified in
**LP-019: Threshold MPC for Bridge Signing** (`~/work/lux/lps/LP-019-threshold-mpc.md`).

| Scheme | Curve | Use case | LP | Implementation | Submission package status |
|---|---|---|---|---|---|
| **FROST** | Ed25519 / secp256k1 (Schnorr) | Cosmos, Bitcoin Schnorr | LP-019 | `~/work/lux/mpc/` | LP-spec mature; IETF draft `draft-irtf-cfrg-frost` exists upstream; Lux profile gap |
| **CGGMP21** | secp256k1 (ECDSA) | Ethereum, Bitcoin legacy | LP-019 | `~/work/lux/mpc/` | LP-spec mature; submission package gap |
| **LSS wrapper** | n/a (linear Shamir over any of the above) | dynamic resharing | LP-019 + LP-141 | `~/work/lux/mpc/`, `~/work/lux/lps/LP-141` | LP-spec mature; submission package gap |
| **BLS** | BLS12-381 | aggregated sigs, Quasar consensus | LP-020 | `~/work/lux/crypto/`, `~/work/lux/bls/` | spec mature; submission package gap |

## §A3 Hybrid PQ signature wrappers — "X-Wing for Signatures"

X-Wing (LP-115) is a hybrid PQ KEM combining X25519 + ML-KEM-768.
For SIGNATURES, the analogous construct is a hybrid PQ-sig wrapper
that combines classical (Ed25519 / ECDSA) + PQ (ML-DSA / SLH-DSA)
into a single concatenated signature.

**Proposed name**: `X-WING-SIG` (or `X-WING-DSA`).

**Construction sketch**:
```
HybridSig(sk_classical, sk_pq, M)
  = Sign_classical(sk_classical, "X-WING-SIG-v0||" ++ M)
 || Sign_pq(sk_pq, "X-WING-SIG-v0||" ++ M)

HybridVerify(pk_classical, pk_pq, M, sig)
  = Verify_classical(pk_classical, "X-WING-SIG-v0||" ++ M, sig[..classical_len])
  ∧ Verify_pq(pk_pq, "X-WING-SIG-v0||" ++ M, sig[classical_len..])
```

**Security claim**: forgery requires breaking BOTH the classical
AND PQ scheme. Useful for transitional deployment where:
- Legacy wallets cannot upgrade to PQ-only (e.g., hardware HSMs
  pinned to ECDSA).
- Defense-in-depth against either scheme being broken.
- FIPS compliance during the migration window.

**LP status**: not yet drafted. Recommended LP-NNN slot:
"LP-XXX: X-WING-SIG hybrid signature wrapper". See
`docs/x-wing-sig.md` for the current construction notes.

## §A4 Key encapsulation

| Scheme | Standard | LP | Implementation | Status |
|---|---|---|---|---|
| **ML-KEM-768** | FIPS 203 | LP-012 | `~/work/lux/crypto/mlkem` | production |
| **X-Wing** (hybrid X25519 + ML-KEM) | draft IRTF CFRG | LP-115 | `~/work/lux/crypto/xwing` | production |
| **X-Wing+** (Lux-extended profile) | n/a | LP-115 extension | `~/work/lux/crypto/xwing+` | production |

## §A5 ZK / accountability — Z-Chain PQ + P3Q precompile

### §A5.1 Z-Chain PQ

**LP-063: Z-Chain** + **LP-169: Z-Chain PQ Identity Rollup**.

Z-Chain is a Lux-original ZK rollup providing:
- Asynchronous identifiable abort for Pulsar (when synchronous
  network assumption fails).
- ZK-proof-backed key registry (HIP-0078).
- Privacy-preserving identity layer.

### §A5.2 P3Q precompile (EVM, slot 0x012205)

**P3Q** = Post-Quantum Pulsar Proof — an EVM precompile providing
on-chain verification of Pulsar threshold signatures. Pulsar's
signature byte-equality to FIPS 204 means any FIPS 204 verifier
inside the precompile suffices.

## §A6 FHE / confidential compute

**LP-013: FHE GPU**, **LP-066: TFHE**, **LP-067: Confidential ERC-20**,
**LP-068: Private Teleport**.

| Scheme | Use case | LP | Status |
|---|---|---|---|
| **TFHE** (CGGI bootstrapped, gate-level) | Generic confidential compute | LP-066 | LP-spec mature; F-Chain host (LP-134) |
| **BFV** | Vector ops (privacy-preserving inference) | LP-013 sections | partial |
| **CKKS** | Approximate-arithmetic (ML inference) | LP-013 sections | partial |

**Threshold FHE**: threshold key generation for TFHE bootstrapping
keys is hosted on F-Chain (LP-134 split — M-Chain hosts MPC
ceremonies, F-Chain hosts FHE). Specified in LP-019 + LP-141.

**Pulsar ↔ FHE composition**: not directly composed. FHE provides
confidential compute on encrypted data; Pulsar provides
authenticated threshold signatures on plaintext messages.

## §A7 EVM-native PQ migration

**LP-012: PQ Crypto GPU**, **LP-078: EVM precompiles**.

Current Lux native chains:
- **C-Chain** (EVM-compatible): uses ECDSA for transaction signing.
- **X-Chain** (UTXO): uses ECDSA / Ed25519 hybrid.

**Target**: native PQ signing using Pulsar / ML-DSA at the wallet
+ transaction layer. Migration paths:

1. **Soft migration via X-Wing-Sig** (§A3): wallets sign
   transactions with hybrid (ECDSA + ML-DSA); validators accept
   either-or-both signatures during transition.
2. **Hard fork to PQ-native**: protocol change requiring all
   validators to verify ML-DSA exclusively. Breaks legacy wallets.
3. **Per-account opt-in**: new account type that requires PQ
   signing; legacy accounts continue with ECDSA.

## Suite-wide standards conformance matrix

| Construction | NIST standard | IETF draft | EasyCrypt proof | Lean proof | Jasmin CT | Test vectors | LP |
|---|---|---|---|---|---|---|---|
| Pulsar | FIPS 204 (parent) | draft-hanzo-pulsar-threshold-mldsa-00 | ✅ 13/13 | ✅ 5/5 | ✅ 3/3 | ✅ | LP-019 |
| Corona | none (Lux-original) | v0.2+ | partial | v0.2+ | v0.3+ | partial | LP-020 |
| Magnetar | FIPS 205 (parent) | none | none | none | none | none | v0.2+ |
| LSS | none | v0.2+ | none | none | none | partial | LP-019 + LP-141 |
| FROST | draft-irtf-cfrg-frost (upstream) | upstream | none in Lux | none | none | upstream KATs | LP-019 |
| CGGMP21 | none | none | none | none | none | partial | LP-019 |
| X-Wing-Sig | none (proposed) | v0.2+ | v0.3+ | v0.2+ | v0.3+ | v0.2+ | v0.3+ |
| ML-KEM | FIPS 203 | RFC drafts | n/a (KEM) | n/a | partial | upstream | LP-012 |
| X-Wing | draft IRTF | draft-irtf-cfrg-xwing | n/a | n/a | partial | upstream | LP-115 |
| Z-Chain PQ | none (Lux-original) | none | none | partial Lean | none | none | LP-063 + LP-169 |
| P3Q precompile | n/a | n/a | n/a | n/a | n/a | partial | LP-078 (partial) |
| TFHE | academic | none | none | none | none | upstream | LP-066 |

**Honest summary**:
- Pulsar is the only construction with FULL submission-grade packaging.
- All others have varying degrees of LP-level spec maturity but lack
  the matching SUBMISSION.md + proof-claims.md + proof-axiom-inventory.md
  + tcb.md + IETF draft + patents.md package.
- Bringing the full suite to Pulsar-grade packaging is a 6-12 month
  coordinated effort.
