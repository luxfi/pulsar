# INFORMATION-ARCHITECTURE — Hanzo PQ Threshold Suite + Lux Crypto

> Cross-repo taxonomy showing where each artifact lives. Updated
> 2026-05-18 to reflect the v0.1 submission package + the broader
> Lux crypto landscape (Corona, KMS, MPC, LPs).

## TL;DR — where to read what

| If you want to read about... | Read here |
|---|---|
| **NIST MPTC submission for Pulsar** | `pulsar-mptc/SUBMISSION.md` + `NIST-SUBMISSION.md` |
| **Hanzo PQ Threshold Suite overview** | `pulsar-mptc/SUITE.md` |
| **Pulsar protocol spec** | `pulsar-mptc/SPEC.md` (text) + `pulsar-mptc/spec/pulsar.pdf` (formal) |
| **Pulsar IETF / CFRG draft** | `pulsar-mptc/docs/ietf-draft-skeleton.md` |
| **What's proved vs not proved** | `pulsar-mptc/PROOF-CLAIMS.md` |
| **Residual EC axioms** | `pulsar-mptc/AXIOM-INVENTORY.md` |
| **TCB / what to trust** | `pulsar-mptc/TRUSTED-COMPUTING-BASE.md` |
| **Op → FIPS 204 § map** | `pulsar-mptc/FIPS-TRACEABILITY.md` |
| **Patent grant** | `pulsar-mptc/PATENTS.md` |
| **Patent claim drafts (internal)** | `pulsar-mptc/docs/patent-claims.md` |
| **Per-version proof changelog** | `pulsar-mptc/CHANGELOG.md` |
| **Performance + correctness evaluation** | `pulsar-mptc/docs/evaluation.md` |
| **Magnetar (Tier 3 SLH-DSA research)** | `pulsar-mptc/docs/magnetar.md` |
| **Lux canonical crypto wiring** | `lps/CRYPTO-CANONICAL.md` |
| **Specific protocol LPs** | `lps/LP-NNN-*.md` (e.g., LP-019 threshold MPC) |

## Three-axis information hierarchy

The Lux crypto information landscape has three independent axes.
Choose your entry point based on what you're doing:

### Axis 1 — by construction / primitive (cryptographic axis)

```
PQ signatures (NIST-standardized)
├── ML-DSA (FIPS 204)
│   ├── Single-party: cloudflare/circl, libjade (external impls)
│   ├── THRESHOLD: PULSAR (Tier 1, Hanzo suite)  ← `pulsar-mptc/`
│   └── DOCS: SUBMISSION, SPEC, IETF, PROOF, PATENTS in pulsar-mptc/
│
├── SLH-DSA (FIPS 205)
│   ├── Single-party: FIPS 205 reference (external)
│   └── THRESHOLD: MAGNETAR (Tier 3 research)  ← `pulsar-mptc/docs/magnetar.md`
│
└── Module-LWE / Ring-LWE (Lux-original)
    ├── Single-party: N/A (FIPS 204 covers it)
    └── THRESHOLD: CORONA (Tier 1b sibling)  ← `~/work/lux/corona/`

Classical signatures
├── ECDSA (secp256k1)
│   └── THRESHOLD: CGGMP21  ← `lps/LP-019` + `~/work/lux/mpc/`
├── Schnorr / Ed25519
│   └── THRESHOLD: FROST  ← `lps/LP-019` + `~/work/lux/mpc/`
└── BLS
    └── THRESHOLD: standard BLS aggregation  ← `lps/LP-NNN` (TBD)

Hybrid / composition
└── HANZO PQ THRESHOLD SUITE  ← `pulsar-mptc/SUITE.md` (master index)

Secret-sharing wrapper
└── LSS (Linear Shamir Secret Sharing)  ← `lps/LP-019` + `lps/LP-141`
```

### Axis 2 — by audience / consumer (use-case axis)

```
NIST submission reviewer
├── Entry: pulsar-mptc/SUBMISSION.md
├── Specs: pulsar-mptc/SPEC.md, spec/pulsar.pdf
├── Trust: PROOF-CLAIMS, AXIOM-INVENTORY, TCB
├── Validation: vectors/, docs/evaluation.md
└── IP: PATENTS.md

IETF / CFRG editor
├── Entry: pulsar-mptc/docs/ietf-draft-skeleton.md
├── Cross-ref: pulsar-mptc/SUITE.md (overview)
└── Conversion: mmark / kramdown-rfc → xml2rfc XML

Lux protocol developer (writing a new precompile, etc.)
├── Entry: lps/CRYPTO-CANONICAL.md (wiring + algorithm list)
├── Per-protocol: lps/LP-NNN-*.md
├── Implementation: `~/work/lux/<repo>/` (e.g., pulsar/, corona/)
└── Bindings: lps/LP-012 (PQ GPU), LP-013 (FHE)

Lux validator operator
├── Entry: lps/LP-015-validator-key-management.md
├── DKG ceremony: lps/LP-019-threshold-mpc.md
└── Operations: lps/LP-141-threshold-vm.md

Attorney / patent reviewer
├── Public-facing: pulsar-mptc/PATENTS.md
├── Claim drafts (internal): pulsar-mptc/docs/patent-claims.md
└── Prior-art map: docs/patent-claims.md §1.4 (per claim group)

Auditor (cryptographic review)
├── Spec: pulsar-mptc/spec/pulsar.pdf
├── Proofs: pulsar-mptc/proofs/easycrypt/ + ~/work/lux/proofs/lean/
├── Bridge doc: pulsar-mptc/proofs/lean-easycrypt-bridge.md
├── Trust: TRUSTED-COMPUTING-BASE.md
└── Validation: scripts/check-high-assurance.sh

Application developer (calling Pulsar from Go / Rust)
├── Reference impl: pulsar-mptc/ref/go/pkg/pulsar/
├── Spec subset: SPEC.md §7 (signing) + §8 (verification)
└── Bindings (future): per language target

External cryptographer (peer review)
├── Honest framing: PROOF-CLAIMS.md
├── Residual trust: AXIOM-INVENTORY.md
└── External-facing: spec/pulsar.pdf + Lean side at ~/work/lux/proofs/lean/
```

### Axis 3 — by Lux organizational structure (governance axis)

```
luxfi/ (open-source NIST-submission entity)
├── pulsar-mptc/         ← this repo (NIST submission)
├── corona/              ← R-LWE sibling (open-source)
├── crypto/              ← canonical Go crypto entry
├── mpc/                 ← general MPC infrastructure
├── kms/                 ← key-management service
└── proofs/              ← Lean / EC / Tamarin / Halmos proofs

luxcpp/ (high-performance C++ + GPU crypto entry)
└── crypto/              ← C++ + CUDA/Metal/WGSL backends

lps/ (Lux Proposal System)
├── LP-001..LP-199       ← canonical protocol specs
├── CRYPTO-CANONICAL.md  ← cross-repo wiring summary
└── LP-019, LP-020, LP-141 ← threshold-MPC, Quasar, ThresholdVM

hanzo/ (downstream consumers)
├── platform/            ← Hanzo PaaS (consumes Pulsar at MPC layer)
└── various AI/llm/etc.

zoo/, pars/, spc/        ← per-org subnets, may consume Pulsar
```

## Cross-axis navigation

A reader can hop axes:
- **From Axis 1 (Pulsar construction) to Axis 3 (governance)**:
  `pulsar-mptc/` is the open-source NIST-submission home; downstream
  consumers (hanzo/, lps/, etc.) reference it for production use.
- **From Axis 2 (NIST reviewer) to Axis 1 (construction)**:
  SUBMISSION.md points to SPEC.md which describes Pulsar's place in
  the Tier-1/2/3 suite.
- **From Axis 3 (LP-019 reader) to Axis 1 (Pulsar / Magnetar)**:
  LP-019 tags Pulsar precompile at 0x000B; reader follows to
  `pulsar-mptc/` for the actual NIST submission package.

## How the suite scales

For each new tier construction:

1. Add a row to `SUITE.md` §Tiers.
2. Add a corresponding tier-N entry to `INFORMATION-ARCHITECTURE.md`
   Axis 1.
3. If production-grade: spin up a parallel doc package
   (SUBMISSION, SPEC, PROOF-CLAIMS, AXIOM-INVENTORY,
   FIPS-TRACEABILITY, PATENTS, TCB, evaluation).
4. If research-grade: a single `docs/<tier>.md` placeholder
   suffices (per `docs/magnetar.md` template).
5. Cross-reference from the relevant LP-NNN in `lps/`.

## Consistency rules

To prevent drift across repos / LPs / docs:

1. **Canonical algorithm wiring lives in `lps/CRYPTO-CANONICAL.md`**.
   All other docs cross-reference; no other doc owns this.
2. **Protocol specs live in `lps/LP-NNN`** as the authoritative
   versioned spec. Submission-package SPEC.md files reference
   the LP-NNN.
3. **Implementation lives in the relevant repo** (`pulsar-mptc/`,
   `corona/`, etc.). Spec docs reference `ref/` paths.
4. **Proof artifacts live in `~/work/lux/proofs/`** (Lean) and
   the relevant repo's `proofs/` (EasyCrypt + Jasmin). Bridge
   docs maintain the cross-prover correspondence.
5. **Submission-package docs (this repo)** are NIST-submission-shaped
   and reference the canonical specs + implementations + proofs.
6. **Patent grants** live with the repo that originated the
   construction (Pulsar's grant in `pulsar-mptc/PATENTS.md`;
   Corona's grant will live in `~/work/lux/corona/PATENTS.md`
   when packaged).

---

**Document metadata**

- Name: `INFORMATION-ARCHITECTURE.md`
- Version: v0.1
- Date: 2026-05-18
- Cross-references: `SUITE.md`, `~/work/lux/lps/CRYPTO-CANONICAL.md`
