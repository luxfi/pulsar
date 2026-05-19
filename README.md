# Pulsar — NIST MPTC submission package

> **Threshold ML-DSA** — a 2-round threshold signing and DKG system whose
> generated signatures are verifiable by **unmodified FIPS 204 ML-DSA
> verification**. Targeting NIST MPTC Class N1 (signing) + N4 (ML keygen / DKG).

This repository is the **active NIST MPTC submission package** for Pulsar
and the canonical home for the submission artifacts (spec, KAT vectors,
reference implementation, interop harness, ct analysis, scripts). The
submission tarball for NIST is cut from a tag on `main` at deadline —
the repository itself stays active so reviewer feedback and post-
submission patches land here, not in a fork.

The production Go library has split into its own stable module identity
(`github.com/luxfi/pulsar` / `github.com/luxfi/corona`); this repository
keeps the original `github.com/luxfi/pulsar` module path because that
is the identifier NIST receives and reviews against.

## Library identities (post-2026 split)

`Pulsar` is the Module-LWE threshold ML-DSA construction. The 2-round
threshold protocol structure operates on ML-DSA-65's polynomial-vector-
over-`R_q` algebra so the per-party-aggregated signature is bit-identical
to a single-party FIPS 204 signature on the same message + public key.

| Repository | Module path | Role |
|---|---|---|
| **luxfi/pulsar** (this repo) | `github.com/luxfi/pulsar` | Active NIST MPTC submission package |
| [luxfi/pulsar](https://github.com/luxfi/pulsar) | `github.com/luxfi/pulsar` | Production Module-LWE Go library |
| [luxfi/corona](https://github.com/luxfi/corona) | `github.com/luxfi/corona` | Production Ring-LWE Go library (sibling kernel) |

The module path inside this submission package remains
`github.com/luxfi/pulsar` because that is the identifier NIST receives
and reviews against the submitted KAT vectors and spec. Downstream
consumers who want the live production library should pin
`github.com/luxfi/pulsar@v1.0.x` (Module-LWE) or
`github.com/luxfi/corona@v0.2.x` (Ring-LWE) instead.

> **Status: Research / Reference (not production hardened, not FIPS validated).**
> NIST-profile vectors use SHAKE / cSHAKE / KMAC. Any BLAKE3 deltas are
> experimental and out-of-scope for the MPTC submission.

## High-assurance headline

The high-assurance stack is now structurally ready for final
mechanized closure. All local EasyCrypt theorem bodies are admit-free,
per-push gates are green, threshold Jasmin CT is blocking, fuzz / KAT /
interop / dudect gates are wired at documented budgets, and the
extracted N1 theorem has no section-local module-contract axioms. The
only remaining implementation-refinement assumptions are **two
localized byte-walk axioms** over pure signature output, each with a
committed proof roadmap. The Lean↔EC algebraic bridge is named, cited,
and CI-guarded.

The dependency graph is acyclic and each EC file owns one concern:

```text
Memory             → pure byte-memory model
Signature_Codec    → FIPS signature packing
Combine_Layout     → combine ABI only
Sign_Layout        → sign ABI only
Combine_Refinement → combine byte-walk only
Sign_Refinement    → sign byte-walk + ghost contract only
Combine_Wrapper    → combine wrapper bridge only
Sign_Wrapper       → sign wrapper bridge only
Extracted          → final composition theorem only
```

Hard boundary:

- 2 implementation-refinement byte-walk axioms, named/scoped with roadmaps
- 4 Lean-bridged algebraic axioms, cited inline and CI-guarded
- 0 admits
- 0 section-local module-contract axioms in the extracted N1 corollary

See `proofs/easycrypt/README.md` for the per-file dashboard and
`proofs/lean-easycrypt-bridge.md` for the Lean↔EC correspondence.

The next proof-count milestone is `combine_body_compute_sig_spec`:
closing it reduces the implementation-refinement cone from 2 to 1.

## Why

NIST FIPS 204 (ML-DSA) is the only NIST-approved post-quantum digital
signature in 2026. Threshold variants of ML-DSA are not yet standardized —
NIST's [Multi-Party Threshold Cryptography](https://csrc.nist.gov/projects/threshold-cryptography)
project is collecting them now (IR 8214C, January 2026; first call package
deadline expected 2026-Nov-16).

Pulsar aims to enter that process with a credible, output-interchangeable
threshold ML-DSA candidate. The 2-round threshold protocol skeleton is
the same one Lux ships in production for Ring-LWE (see
[`luxfi/corona`](https://github.com/luxfi/corona)), retargeted to the
Module-LWE primitives ML-DSA itself uses; the resulting per-party-
aggregated signature is bit-identical to a single-party FIPS 204 ML-DSA
signature on the same message + public key.

The win, if Pulsar's Sign output is byte-equal to FIPS 204 Sign:
- Threshold-produced signatures verify under unmodified FIPS 204 verifiers.
- Existing FIPS-validated ML-DSA modules (BoringSSL FIPS, AWS-LC, OpenSSL
  3.0 PQ provider) consume Pulsar certs without code changes.
- The threshold layer can be Class-N-claimed at NIST without a parallel
  algorithm standardization track.

## Repository layout

```
pulsar/
├── BLOCKERS.md               PRODUCTION-GO-LIVE BLOCKER LIST (13 critical findings from red-team audit, 5 weak claims from scientist)
├── docs/                     human-readable design notes
│   ├── threat-model.md
│   ├── nist-mptc-category.md
│   ├── design-decisions.md
│   └── patent-notes-draft.md
├── spec/                     LaTeX technical specification (MPTC package)
│   ├── pulsar.tex          main spec
│   ├── security-games.tex    EUF-CMA / TS-UF / robustness / adaptive corr.
│   ├── system-model.tex      network / setup / abort / preprocessing
│   ├── parameters.tex        concrete parameter sets, lattice-estimator
│   └── references.bib
├── ref/
│   ├── go/                   reference implementation (Go, no assembly)
│   │   ├── cmd/              CLI entry points
│   │   ├── internal/         private helpers
│   │   └── pkg/              public API (sign/, dkg/, primitives/, hash/, fmt/)
│   └── c/                    conformance implementation (post-encoding-freeze)
├── vectors/                  Known Answer Tests (KATs)
│   ├── kat-v1.json           input/output vectors per MPTC §IO-Testing
│   ├── kat-v1.rsp            CAVS-style response file (compatibility)
│   └── transcripts/          full-protocol KATs (n,t sweeps)
├── bench/                    reproducible benchmark harness
├── test/                     fuzz / negative / interoperability tests
├── ct/dudect/                constant-time analysis harness
├── estimator/                lattice-estimator parameter scripts
├── jasmin/                   high-assurance Jasmin sources (initial track)
│   ├── ml-dsa-65/             libjade single-party baseline (fetched on demand)
│   └── threshold/             Pulsar threshold layer (round1 + round2 + combine implemented)
├── proofs/easycrypt/         high-assurance EasyCrypt theories
│   ├── Pulsar_N1.ec                       Class N1 protocol-level spec + generic byte-equality theorem
│   ├── Pulsar_N4.ec                       Class N4 reshare public-key preservation
│   ├── Pulsar_N1_Memory.ec                byte-memory model (0 axioms)
│   ├── Pulsar_N1_Signature_Codec.ec       FIPS 204 sig codec
│   ├── Pulsar_N1_Combine_Layout.ec        combine ABI byte layout
│   ├── Pulsar_N1_Sign_Layout.ec           libjade sign ABI byte layout
│   ├── Pulsar_N1_Combine_Refinement.ec    combine refinement scaffold
│   ├── Pulsar_N1_Sign_Refinement.ec       sign refinement scaffold + ctx/rho_rnd ghost contract
│   ├── Pulsar_N1_Combine_Wrapper.ec       combine wrapper module + bridge lemma
│   ├── Pulsar_N1_Sign_Wrapper.ec          sign wrapper module + bridge lemma
│   ├── Pulsar_N1_Extracted.ec             concrete extracted N1 byte-equality corollary
│   ├── lemmas/MLDSA65_Functional.ec       FIPS 204 functional ops
│   ├── lemmas/Pulsar_CT.ec                constant-time obligations
│   └── README.md                          trust-boundary dashboard + per-file concerns
├── proofs/lean-easycrypt-bridge.md        Lean↔EC algebraic-bridge correspondence
├── scripts/
│   ├── check-high-assurance.sh            per-push proof gate orchestrator
│   ├── test.sh                            per-push test gate orchestrator
│   ├── nightly.sh                         cron-scheduled REAL-budget gate
│   │                                        (1h fuzz + 10^9 dudect)
│   ├── check-lean-bridge.sh               Lean↔EC bridge guard
│   ├── checks/                            per-check scripts (independently runnable)
│   │   ├── jasmin.sh, ec-{admits,compile,regressions,refinement-scaffold}.sh,
│   │   ├── extraction.sh
│   │   └── test/{go-unit,no-secret-logs,kat,interop}.sh
│   └── build.sh / bench.sh / sbom.sh / gen_vectors.sh / extract-jasmin-ec.sh
└── go.mod
```

## Quickstart

The repository is **live and self-validating**. A fresh clone runs the
full per-push submission gate end-to-end in under 60 seconds:

```bash
git clone https://github.com/luxfi/pulsar
cd pulsar
./scripts/build.sh                  # Go ref + spec PDF (MacTeX / TeX Live)
./scripts/test.sh                   # Go unit + DD-007 linter + KAT replay
                                    # + Class N1 interop
./scripts/gen_vectors.sh            # deterministic KAT regen
./scripts/check-high-assurance.sh   # Jasmin + EasyCrypt + Lean↔EC bridge guard
                                    # (skips per-tool if not installed)
./scripts/bench.sh                  # signing / verification benchmarks
```

Each per-push script is an **orchestrator** that sequences per-check
scripts under `scripts/checks/` (and `scripts/checks/test/`). Per-check
scripts are independently runnable for fast iteration:

```bash
bash scripts/checks/ec-compile.sh        # just the EC compile gate
bash scripts/checks/jasmin.sh            # just jasminc + jasmin-ct
bash scripts/checks/test/kat.sh          # just KAT replay
```

`build.sh`, `test.sh`, and `check-high-assurance.sh` exit non-zero on
any failure. Reproducibility is the load-bearing CI invariant. The
per-push gates run **real-budget checks only** — no smoke tests; the
fuzz + dudect REAL-budget runs live in the nightly gate (`hours`,
cron-scheduled):

```bash
./scripts/nightly.sh                # 1h-per-target parser fuzz
                                    # + 1h differential fuzz
                                    # + 10^9-sample dudect (per target)
```

## NIST MPTC submission

| package element | location | status |
|---|---|---|
| Technical Specification | `spec/pulsar.pdf` (1,536-line LaTeX → 28 pages, 491 KB) | drafted; encoding freeze 2026-Aug |
| Reference Implementation | `ref/go/pkg/pulsar/` (89.7% coverage) | shipped |
| KAT vectors | `vectors/{dkg,keygen,sign,threshold-sign,verify}.json` | deterministic from seed |
| Class N1 E2E interop | `test/interoperability/` (19/19 subtests vs cloudflare/circl) | passing |
| Symbolic / Lean proofs | `~/work/lux/proofs/lean/Crypto/Pulsar/` (3 files, **zero `sorry`**) | mechanized |
| Constant-time analysis | `ct/dudect/` | harness present; results TBD |
| Jasmin high-assurance | `jasmin/{ml-dsa-65,threshold,lib}/` | libjade pinned at 9426b32; round1 + round2 + combine implemented (~2,600 lines threshold + lib) |
| EasyCrypt theories | `proofs/easycrypt/Pulsar_{N1,N4}.ec` + `lemmas/Pulsar_CT.ec` | theory shells; N1 reduction core remains `admit` (needs EasyCrypt expert) |
| Report on Experimental Evaluation | `bench/results/REPORT.md` | TBD |
| Patent posture | `docs/patent-notes-draft.md` | drafted |
| License | `LICENSE` (Apache-2.0) | ✓ |
| Build/test/bench scripts | `scripts/` | shipped |
| SUBMISSION cover sheet | `SUBMISSION.md` | shipped |

Target dates:
- **2026-Jul-20** preview writeup (NIST third preview deadline)
- **2026-Nov-16** package submission (NIST first call deadline; submission tag `submission-` cut from `main`)

## Relationship to upstream

**Scope of this submission.** Pulsar is the standalone NIST MPTC
submission for the Module-LWE threshold ML-DSA construction. The spec,
KAT vectors, reference implementation, and proofs are self-contained.
Reviewers do not need to fetch any sibling repository to evaluate the
submission.

**Earlier R-LWE work.** The 2-round threshold construction line begins
with Boschini–Kaviani–Lai–Malavolta–Takahashi–Tibouchi's Ring-LWE
paper ([ePrint 2024/1113](https://eprint.iacr.org/2024/1113)). The
production R-LWE library Lux deploys is
[`luxfi/corona`](https://github.com/luxfi/corona) — same 2-round
threshold algorithm retargeted at production lifecycle (Pedersen DKG
over `R_q` with proper hiding + proactive resharing). Corona and
Pulsar are **independent libraries** with no shared types; Pulsar
is reviewable on its own merits and Corona is documented separately.

| repo | role | lattice basis | hash family |
|---|---|---|---|
| [luxfi/corona](https://github.com/luxfi/corona) | production R-LWE threshold ML-DSA — Pedersen DKG over `R_q` + proactive resharing | Ring-LWE (`R_q`) | SHA-3 / cSHAKE256 (SP 800-185) |
| [luxfi/pulsar](https://github.com/luxfi/pulsar) | production M-LWE threshold ML-DSA — same protocol skeleton retargeted to ML-DSA's polynomial-vector-over-`R_q^k` algebra; output byte-equal to FIPS 204 ML-DSA | Module-LWE (`R_q^k`) | SHA-3 / cSHAKE256 (SP 800-185) |
| **luxfi/pulsar** (this repo) | NIST MPTC submission package for the M-LWE construction — frozen spec, KATs, reference impl, interop harness, proofs | Module-LWE (`R_q^k`) | SHA-3 / SHAKE256 (NIST profile) only |

**Optional layered defence on a downstream chain.** A downstream
consumer (e.g. Lux's primary-network QuasarCert) MAY combine Corona
(Ring-LWE) and Pulsar (Module-LWE) as a **Double Lattice** PQ pair so
a break in one lattice family does not break finality. That layered
combination is the consumer's design choice and is not part of this
submission. Pulsar stands alone as an MPTC Class N1 + N4 candidate.

### Where the identity rollup lives

Pulsar is *just* the threshold sign + DKG layer. The per-validator
ML-DSA-65 identity attestation that QuasarCert separately carries
(`MLDSARollup`) is **succinct via STARK / FRI** through the **P3Q**
backend — Lux's Plonky3 fork with a cSHAKE256 Merkle commitment.
P3Q is post-quantum end-to-end (no Groth16/BN254 wrapper; no KZG;
no pairings). The rollup statement is

```
∀ i ∈ [N]: ML-DSA.Verify(mldsa_pk_i, msg, mldsa_σ_i) = 1
```

and the resulting proof is constant in validator count. Specs:
`ProofPolicySTARKFRISHA3PQ` (0x10) + `ProofBackendP3QSTARKFRISHA3`
(0x22) in `github.com/luxfi/consensus/config/pq_mode.go`. The
historic "Z-Chain Groth16 / BN254" framing was retired alongside the
classical-curve rip in 2026-Q2; any residual reference in this
package's older drafts is being swept out before submission.

## Security

`SECURITY.md` describes how to disclose vulnerabilities and what's in-scope for
bug bounty.

## License

Apache-2.0 — same as `luxfi/pulsar` and `luxfi/corona`. See `LICENSE`.
