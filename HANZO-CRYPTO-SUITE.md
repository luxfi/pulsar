# Hanzo Crypto Suite — full inventory + packaging status

> Comprehensive inventory of every cryptographic construction in
> the Lux / Hanzo / Zoo / Pars ecosystem, with packaging-status,
> LP cross-references, and submission-readiness gap analysis.
>
> The Hanzo PQ Threshold Suite (`SUITE.md`) is **one subset** of this
> broader inventory. This document is the master index.

## Quick orientation

| Category | Tiers | This document section |
|---|---|---|
| **Post-quantum threshold signatures** | Pulsar, Magnetar, Corona | §1 |
| **Classical threshold signatures** | FROST, CGGMP21, LSS, BLS | §2 |
| **Hybrid PQ signature wrappers** | X-Wing-for-Signatures (proposed) | §3 |
| **Key encapsulation** | ML-KEM, X-Wing | §4 |
| **Zero-knowledge / accountability** | Z-Chain PQ, P3Q precompile | §5 |
| **FHE / confidential compute** | TFHE on F-Chain, BFV, CKKS | §6 |
| **EVM-native PQ migration** | C-Chain + X-Chain → PQ-native | §7 |

## §1 PQ threshold signatures — Hanzo PQ Threshold Suite

Master index: `SUITE.md`. Single canonical home: `~/work/lux/pulsar/`.

| Tier | Construction | LP | Repo | Spec | Proofs | NIST submission | Status |
|---|---|---|---|---|---|---|---|
| 1 | **Pulsar** (Threshold ML-DSA) | LP-019 ref'd | `~/work/lux/pulsar/` (single canonical home) | ✅ SPEC.md + spec/pulsar.tex + IETF draft | ✅ EC 13/13, Lean 5/5 | ✅ v0.1 ready | **NIST-MPTC-submission ready** |
| 1b | **Corona** (Threshold R-LWE) | LP-020 | `~/work/lux/corona/` | partial DESIGN.md | partial DKG proofs | ❌ v0.2 target | implementation mature, packaging needed |
| 3 | **Magnetar** (Threshold SLH-DSA) | TBD | none | `docs/magnetar.md` placeholder | ❌ | ❌ research-only | research-direction sketch |
| 4 | **LSS** (Linear Shamir) | LP-019 + LP-141 | `~/work/lux/lps/`, `~/work/lux/mpc/` | LP-019 sections | none mechanized | ❌ wrapper-only | spec exists, no submission package |

**Gap to "all tiers submission-ready"**:
- Corona: full SUBMISSION.md + SPEC.md + PROOF-CLAIMS.md + AXIOM-INVENTORY.md + PATENTS.md package mirroring Pulsar. Estimate: 2-3 weeks.
- Magnetar: research-paper + initial DKG prototype. Estimate: 2-3 months.
- LSS: standalone IETF draft + reference vectors. Estimate: 2 weeks.

## §2 Classical threshold signatures

Used for bridging to non-PQ chains (Bitcoin secp256k1, Ethereum
legacy, Cosmos Ed25519, Solana, etc.). Specified in
**LP-019: Threshold MPC for Bridge Signing** (`~/work/lux/lps/LP-019-threshold-mpc.md`).

| Scheme | Curve | Use case | LP | Implementation | Submission package status |
|---|---|---|---|---|---|
| **FROST** | Ed25519 / secp256k1 (Schnorr) | Cosmos, Bitcoin Schnorr | LP-019 | `~/work/lux/mpc/` | LP-spec mature; IETF draft `draft-irtf-cfrg-frost` exists upstream; Lux profile gap |
| **CGGMP21** | secp256k1 (ECDSA) | Ethereum, Bitcoin legacy | LP-019 | `~/work/lux/mpc/` | LP-spec mature; submission package gap |
| **LSS wrapper** | n/a (linear Shamir over any of the above) | dynamic resharing | LP-019 + LP-141 | `~/work/lux/mpc/`, `~/work/lux/lps/LP-141` | LP-spec mature; submission package gap |
| **BLS** | BLS12-381 | aggregated sigs, Quasar consensus | LP-020 | `~/work/lux/crypto/`, `~/work/lux/bls/` | spec mature; submission package gap |

**Per user direction "100% up to spec"**: each of FROST, CGGMP21,
LSS, BLS needs:
1. Equivalent of `./SUBMISSION.md` (cover sheet).
2. Equivalent of `./SPEC.md` (text spec) — partially in LP-019.
3. Equivalent of `./PATENTS.md` (FROST and CGGMP21 are
   academically published; need defensive grant statement).
4. Implementation-correctness proof (EC + Lean) — currently absent for FROST/CGGMP21.
5. Constant-time analysis — partial for FROST.
6. Test vectors — KAT format aligned with `./vectors/`.

Estimated total: 8-12 weeks per scheme.

## §3 Hybrid PQ signature wrappers — "X-Wing for Signatures"

> **User direction**: "ala X-Wing but for older crypto wallets"

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
"LP-XXX: X-WING-SIG hybrid signature wrapper".

**Submission-package status**: none. Estimated effort to draft:
- Spec: 1-2 weeks.
- Implementation (Go reference + Rust crate): 1 week.
- Lean proof (composition theorem: hybrid_secure iff classical_secure ∨ pq_secure): 2-3 weeks.
- Test vectors: 1 week.

**Threshold variant**: trivially threshold-izable as
"FROST × Pulsar" — run threshold FROST and Pulsar in parallel,
concatenate outputs. Documented in `~/work/lux/lps/LP-019` future
revision.

## §4 Key encapsulation

| Scheme | Standard | LP | Implementation | Status |
|---|---|---|---|---|
| **ML-KEM-768** | FIPS 203 | LP-012 | `~/work/lux/crypto/mlkem` | production |
| **X-Wing** (hybrid X25519 + ML-KEM) | draft IRTF CFRG | LP-115 | `~/work/lux/crypto/xwing` | production |
| **X-Wing+** (Lux-extended profile) | n/a | LP-115 follow-up | `~/work/lux/crypto/xwing+` | production |

LP-115 has the X-Wing KEM spec. No threshold KEM (not a typical
threshold primitive).

## §5 ZK / accountability layer — Z-Chain PQ + P3Q precompile

### §5.1 Z-Chain PQ

**LP-063: Z-Chain** + **LP-169: Z-Chain PQ Identity Rollup**.

Z-Chain is a Lux-original ZK rollup providing:
- Asynchronous identifiable abort for Pulsar (when synchronous
  network assumption fails).
- ZK-proof-backed key registry (HIP-0078).
- Privacy-preserving identity layer.

**Construction**: Groth16 proofs over the PQ-signature aggregation
identity, posted to Z-Chain rollup, verifiable by L1.

**Status**:
- LP-063: spec mature.
- LP-169: PQ identity rollup spec mature.
- Implementation: `~/work/lux/zchain/` (if exists; verify).
- Submission package: not in scope for v0.1 Pulsar — separate
  Lux artifact.

### §5.2 P3Q precompile (EVM, slot 0x012205)

**P3Q** = "Post-Quantum Pulsar Proof", an EVM precompile at slot
`0x012205` providing on-chain verification of Pulsar threshold
signatures.

**Reference**: per the Lux global guidance, P3Q is a new primitive
at its own slot, not bolted onto existing ZK or Pulsar.

**LP**: covered partially by LP-078 (EVM precompiles); needs a
dedicated LP-XXX for the precompile specification (input format,
gas cost, error cases).

**Implementation**: in `~/work/lux/evm/precompiles/` (verify
path).

**Submission package**: not applicable (precompile, not standalone
algorithm). The Pulsar signature verified by P3Q is the same byte
string as a FIPS 204 ML-DSA signature, so any FIPS 204 verifier
inside the EVM precompile suffices.

## §6 FHE / confidential compute

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
authenticated threshold signatures on plaintext messages. They
operate at different layers.

**Submission-package status**: TFHE is research-grade; no NIST
submission target.

## §7 EVM-native PQ migration

> **User direction**: "should shift all native lux c/x chain and
> evm native PQ"

**LP-012: PQ Crypto GPU**, **LP-078: EVM precompiles**.

Current Lux native chains:
- **C-Chain** (EVM-compatible): uses ECDSA for transaction signing.
- **X-Chain** (UTXO): uses ECDSA / Ed25519 hybrid.

**Target**: native PQ signing using Pulsar / ML-DSA at the wallet
+ transaction layer.

**Migration paths**:

1. **Soft migration via X-Wing-Sig** (§3 above): wallets sign
   transactions with hybrid (ECDSA + ML-DSA); validators accept
   either-or-both signatures during transition.

2. **Hard fork to PQ-native**: protocol change requiring all
   validators to verify ML-DSA exclusively. Breaks legacy wallets.
   Requires coordinated migration window.

3. **Per-account opt-in**: introduce a new account type that
   requires PQ signing; legacy accounts continue with ECDSA;
   block bridge encourages opt-in.

**Submission-package implications**: P3Q precompile (§5.2) is the
on-chain verifier interface. If wallets migrate to native PQ,
P3Q's gas cost becomes the bottleneck.

**LP status**: migration plan not yet drafted. Recommended LP-XXX:
"LP-XXX: C-Chain / X-Chain PQ-native migration plan".

## Suite-wide standards conformance matrix

| Construction | NIST standard | IETF draft | EasyCrypt proof | Lean proof | Jasmin CT | Test vectors | LP |
|---|---|---|---|---|---|---|---|
| Pulsar | FIPS 204 (parent) | draft-hanzo-pulsar-threshold-mldsa-00 | ✅ 13/13 | ✅ 5/5 | ✅ 3/3 | ✅ | LP-019 |
| Corona | none (Lux-original) | TBD | partial | TBD | TBD | partial | LP-020 |
| Magnetar | FIPS 205 (parent) | none | none | none | none | none | TBD |
| LSS | none | TBD | none | none | none | partial | LP-019 + LP-141 |
| FROST | draft-irtf-cfrg-frost (upstream) | upstream | none in Lux | none | none | upstream KATs | LP-019 |
| CGGMP21 | none | none | none | none | none | partial | LP-019 |
| X-Wing-Sig | none (proposed) | TBD | TBD | TBD | TBD | TBD | TBD |
| ML-KEM | FIPS 203 | RFC drafts | n/a (KEM) | n/a | partial | upstream | LP-012 |
| X-Wing | draft IRTF | draft-irtf-cfrg-xwing | n/a | n/a | partial | upstream | LP-115 |
| Z-Chain PQ | none (Lux-original) | none | none | partial Lean | none | none | LP-063 + LP-169 |
| P3Q precompile | n/a | n/a | n/a | n/a | n/a | partial | LP-078 (partial) |
| TFHE | academic | none | none | none | none | upstream | LP-066 |

**Honest summary**:
- Pulsar is the only construction with FULL submission-grade
  packaging.
- All others have varying degrees of LP-level spec maturity but
  lack the matching SUBMISSION.md + PROOF-CLAIMS.md +
  AXIOM-INVENTORY.md + TCB + IETF draft + PATENTS.md package.
- Bringing the full suite to Pulsar-grade packaging is a 6-12
  month coordinated effort.

## Recommended next-quarter work plan

| Q | Work |
|---|---|
| Q3 2026 | Pulsar NIST MPTC submission (Nov 16 deadline) |
| Q4 2026 | Corona equivalent packaging (matching Pulsar) |
| Q1 2027 | FROST + CGGMP21 submission packages (Lux-profile IETF drafts + EC proof scaffolding) |
| Q2 2027 | X-Wing-Sig LP + draft + reference impl |
| Q3 2027 | Magnetar research paper + initial DKG impl |
| Q4 2027 | Z-Chain PQ identity rollup audit + LP-169 finalization |
| 2028+ | Full mechanized closure of codec axioms + Lean ↔ EC translation tooling |

## Information-architecture invariants

All Hanzo Crypto Suite documents MUST satisfy:

1. **Canonical algorithm wiring**: `~/work/lux/lps/CRYPTO-CANONICAL.md`
2. **Per-construction LP**: `~/work/lux/lps/LP-NNN-*.md`
3. **Per-construction repo**: `~/work/lux/<construction>/`
4. **Per-construction submission package** (when production-ready):
   `<repo>/SUBMISSION.md`, `<repo>/SPEC.md`, `<repo>/PATENTS.md`,
   `<repo>/PROOF-CLAIMS.md`, `<repo>/AXIOM-INVENTORY.md`,
   `<repo>/TRUSTED-COMPUTING-BASE.md`, `<repo>/FIPS-TRACEABILITY.md`
   (if FIPS-anchored), `<repo>/docs/evaluation.md`,
   `<repo>/docs/ietf-draft.md`.
5. **Master suite index**: `./SUITE.md` (for the PQ
   Threshold Suite) + `./HANZO-CRYPTO-SUITE.md`
   (this doc, for the broader inventory).

## Why this matters

The user's direction is clear: every novel cryptographic
construction in the Lux ecosystem should reach Pulsar-grade
documentation + proof artifacts BEFORE claiming production
readiness. This document is the gap-analysis showing what work
remains.

Be honest in claims:
- DO say: "Pulsar is submission-ready for NIST MPTC v0.1."
- DO say: "Corona has a mature LP and implementation; submission
  packaging is on the v0.2 roadmap."
- DO say: "X-Wing-Sig is a proposed direction; no LP exists yet."
- DO NOT say: "The Hanzo Crypto Suite is 100% NIST-ratified" —
  only Pulsar v0.1 is submission-ready.
- DO NOT say: "Magnetar is production-ready threshold SLH-DSA" —
  research-only.

---

**Document metadata**

- Name: `HANZO-CRYPTO-SUITE.md`
- Version: v0.1
- Date: 2026-05-18
- Scope: full Lux/Hanzo crypto inventory; broader than
  `SUITE.md` (which covers PQ threshold only).
- Maintainer: `crypto-suite@lux.network`
