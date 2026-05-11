# The Pulsar threshold-signature family

> **Pulsar** is one name for a family of lattice-based threshold signature
> schemes. Variants share the same protocol skeleton (2-round threshold
> sign, Pedersen DKG with proper hiding, proactive resharing,
> identifiable abort) but differ in the underlying lattice problem and
> NIST-compatibility target.

This document is the canonical statement of the family architecture.
Every Pulsar variant references it. Every NIST submission cites it.
Every consumer that wires "the Pulsar family" into a downstream system
points here for the variant table.

## Variants

| variant   | repo                              | lattice basis | hash family (canonical)        | FIPS 204 verifier interchange? | NIST MPTC class | status                        |
|-----------|-----------------------------------|---------------|--------------------------------|--------------------------------|-----------------|-------------------------------|
| **Pulsar.R**  | `github.com/luxfi/pulsar`     | Ring-LWE (`R_q`)        | SHA-3 / cSHAKE256 (SP 800-185) | no — special threshold-friendly primitive    | Class S1 + S4 | shipping, hardened, MPTC-ready |
| **Pulsar.M**  | `github.com/luxfi/pulsar-m`   | Module-LWE (`R_q^k`)    | SHA-3 / cSHAKE256 (SP 800-185) | yes — output is a single FIPS 204 ML-DSA σ   | Class N1 + N4 | bootstrap repo, spec in flight |
| Pulsar.W (reserved)        | TBD                | TBD           | TBD                            | TBD                            | TBD             | reserved for future lattice variant |

All variants share:

- **Protocol skeleton** — 2-round threshold sign, Pedersen DKG, proactive
  resharing with beacon-randomized quorum, identifiable abort with signed
  complaints.
- **Hash suite** — NIST SP 800-185 (cSHAKE256, KMAC256, TupleHash256) is
  canonical for every NIST-track variant. BLAKE3 deltas appear only in
  legacy / academic profiles (`Pulsar.R-BLAKE3`, upstream Ringtail) and
  are explicitly out-of-scope for any MPTC submission.
- **Constant-time discipline** — every secret-touching path constant-time
  via `crypto/subtle` or local equivalents. No stdlib `log` in any
  primitive package; all logging goes through `github.com/luxfi/log` at
  fields the threat model has explicitly classified as public.
- **Implementation language** — Go reference; C / Rust conformance after
  encoding-freeze gate per variant.

What differs between variants:

- **Algebra** — Ring-LWE for Pulsar.R, Module-LWE for Pulsar.M. The
  algebraic shape determines parameter sizes, signature sizes, and the
  structure of the Pedersen commitment scheme.
- **Verification target** — Pulsar.R verifies under its own verifier
  (a custom 2-round-aggregated check); Pulsar.M verifies under
  unmodified FIPS 204 ML-DSA.Verify. The latter is the single highest-
  value property of the family.
- **NIST submission posture** — see Class column above.
- **Production maturity** — Pulsar.R has a hardened reshare path,
  KAT suite, deployed code. Pulsar.M has a spec stub and skeleton repo.

## Why one family

NIST MPTC IR 8214C accepts each variant as a separate submission package
in either Class N or Class S. Submitting two as a coordinated **family**:

1. **Reuses infrastructure once.** The DKG harness, KAT cross-validation,
   transcript binding, constant-time analysis, lattice-estimator runs,
   patent disclosure, and IP review build to a shared `pulsar-test/` and
   `pulsar-spec-common/` set of artifacts both submissions reference.
2. **Cross-validates the protocol skeleton.** A reviewer attacking the
   Pedersen DKG soundness in Pulsar.R is also attacking it in Pulsar.M.
   Soundness arguments compose; reviewers don't have to redo work.
3. **Demonstrates orthogonality.** Both submissions running on the same
   2-round structure with different lattice bases is itself a security
   argument: the family's robustness comes from a small, audited
   protocol skeleton with parameterized algebra, not from a one-off
   primitive.
4. **Forwards-only.** Adding `Pulsar.W` (or whichever future variant)
   becomes a parameter-set + algebra change against the same skeleton,
   not a new project. The naming reservation is pre-paid.

## What goes where

| artifact                          | shared       | Pulsar.R                          | Pulsar.M                            |
|-----------------------------------|--------------|-----------------------------------|-------------------------------------|
| 2-round protocol description      | shared spec  | parameterised for `R_q`            | parameterised for `R_q^k`           |
| Pedersen DKG (proper hiding)      | shared spec  | params for `R_q`                   | params for `R_q^k`                  |
| Proactive resharing (beacon-rand) | shared spec  | params for `R_q`                   | params for `R_q^k`                  |
| Reference Go impl                 | shared testkit | full primitive in `pulsar/`     | full primitive in `pulsar-m/`       |
| KATs                              | shared format | `vectors/` per repo               | `vectors/` per repo                 |
| Lattice estimator                 | shared script | parameter file per variant         | parameter file per variant          |
| Patent claims                     | shared review | repo-local `patent-notes.md`      | repo-local `patent-notes.md`        |
| MPTC technical specification PDF  | NO           | `pulsar/spec/pulsar-r.pdf`         | `pulsar-m/spec/pulsar-m.pdf`        |
| MPTC submission package           | NO — separate Class S vs Class N | one per variant                   | one per variant                     |

Two separate MPTC packages, one shared technical foundation. The shared
material is brought in by reference from each submission's spec PDF,
matching how PQ-CRYSTALS submitted Dilithium and Kyber as related
algorithms in Round 3.

## Naming discipline

- The umbrella name is **Pulsar**. Always capitalised, no hyphen.
- A specific variant is **Pulsar.X** where X is one uppercase letter
  identifying the lattice basis: `Pulsar.R` (Ring-LWE), `Pulsar.M`
  (Module-LWE). The dot is part of the name in prose; in identifiers
  the canonical machine form is `pulsar-r`, `pulsar-m` (lowercase,
  hyphen).
- Variants do **not** carry the lattice basis in the umbrella name.
  Calling Pulsar.R "Ringtail-Pulsar" or "RPulsar" is wrong. Ringtail
  is a separate academic upstream (`luxfi/ringtail`) that Pulsar.R
  forks; Pulsar.R is not Ringtail.
- HashSuiteID byte (per HIP-0077 §"Lux consensus PQ modes") identifies
  the **hash family**, not the variant. Pulsar.R and Pulsar.M canonical
  profiles both use `HashSuiteSHA3 = 2`. A future Pulsar.M with a
  different hash family (e.g. SHAKE256 only) would claim a new
  HashSuiteID without renaming the variant.

## Repo organisation

```
~/work/lux/
├── pulsar/                ← Pulsar.R (R-LWE, production fork of Ringtail)
│   ├── sign/
│   ├── primitives/
│   ├── dkg2/              ← Pedersen DKG over R_q
│   ├── reshare/           ← proactive resharing
│   ├── hash/              ← Pulsar-SHA3 + Pulsar-BLAKE3 (legacy)
│   └── ...
├── pulsar-m/              ← Pulsar.M (M-LWE, FIPS 204-compatible)
│   ├── ref/go/
│   ├── spec/              ← own MPTC technical spec PDF
│   ├── docs/              ← family-architecture.md = THIS file
│   └── ...
├── ringtail/              ← academic upstream (NOT Pulsar; cited as the
│                            R-LWE 2-round skeleton's origin)
└── consensus/
    └── protocol/quasar/   ← witness orchestrator that consumes Pulsar
                              variants via WitnessProducer interface
```

The `consensus/protocol/quasar/` orchestrator binds to Pulsar variants
through `QWitnessProducer` (interface in
`consensus/protocol/quasar/witness_producer.go`). Quasar doesn't know
which variant produces the witness — it gets a `[]byte` and a
HashSuiteID. Variants are interchangeable at the orchestration layer,
which is exactly the orthogonality the family architecture claims.

## NIST submission strategy

Per CTO Decision 4 (recorded in this branch's HIP-0077 process notes):

> Submit BOTH. Pulsar.M leads (Class N1+N4, FIPS 204 verifier-interchangeable,
> highest strategic value). Pulsar.R parallel (Class S1+S4, established
> production code, demonstrates the family's R-LWE branch). Withdrawing
> either wastes existing work; submitting both forces the team to factor
> shared infrastructure into reusable modules — the orthogonality
> requirement.

Single Git tag, simultaneous cut: `mptc-preview-2026` on `pulsar` and
`pulsar-m` at the same SHA discipline. Both submissions reference frozen
artifacts. Drift between the two repos after the tag is only allowed
via amendments NIST permits in the public-analysis window.

## Status

- [x] Pulsar.R production code (shipping in Lux primary network)
- [x] Pulsar.R hardening: F8 (no log of secret state), F9 (constant-time reshare), F12 (LIGHT_MNEMONIC guard)
- [ ] Pulsar.R MPTC spec doc finalised (`pulsar/spec/pulsar-r.pdf` to be added)
- [ ] Pulsar.R `mptc-preview-2026` tag
- [x] Pulsar.M repo bootstrap (`pulsar-m/`)
- [ ] Pulsar.M Module-LWE algorithm body in spec (in flight via scientist agent)
- [ ] Pulsar.M reference implementation
- [ ] Pulsar.M FIPS 204 cross-validation (output interchangeability proof)
- [ ] Pulsar.M `mptc-preview-2026` tag
- [ ] Family architecture cross-reference baked into HIP-0077

## See also

- HIP-0077 (`hanzo/hips/HIPs/hip-0077-mesh-identity-gossip-and-payments.md`)
  — defines the PQMode enum that selects which Pulsar variant the
  consensus layer asks for.
- HIP-0078 (in flight) — Q-Chain PQ-rollup. Replaces Z-Chain Groth16/BN254
  with a PQ-secure SNARK. Pulsar.M's per-validator ML-DSA-65 sigs are the
  rollup target.
- NIST IR 8214C — *First Call for Multi-Party Threshold Schemes* (January
  2026, package deadline 2026-Nov-16).
