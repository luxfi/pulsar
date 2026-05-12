# Pulsar

> **Threshold ML-DSA** — a 2-round threshold signing and DKG system whose
> generated signatures are verifiable by **unmodified FIPS 204 ML-DSA
> verification**. Targeting NIST MPTC Class N1 (signing) + N4 (ML keygen / DKG).

`Pulsar` is the Lux **Module-LWE** post-quantum threshold signature library.
Its 2-round threshold protocol structure operates on ML-DSA-65's polynomial-
vector-over-`R_q` algebra so the per-party-aggregated signature is bit-
identical to a single-party FIPS 204 signature on the same message + public
key. The Ring-LWE sibling library is [`luxfi/corona`](https://github.com/luxfi/corona).

## Version note

This repository previously held the Ring-LWE codebase under tags `v0.1.0`,
`v0.1.1`, `v0.1.2`, and `v0.1.5`. Following the 2026 Pulsar / Corona split:

- **Ring-LWE** code moved to [`luxfi/corona`](https://github.com/luxfi/corona),
  inheriting the `v0.1.x` history under the new name.
- **Module-LWE** code (this repository) starts at `v1.0.0` to signal the
  identity break.

Use:

```sh
go get github.com/luxfi/pulsar@v1.0.0          # Module-LWE (this repo)
go get github.com/luxfi/corona@v0.2.0          # Ring-LWE (sibling repo)
```

The legacy `v0.1.x` tags on this repository have been retired. If you
need the historical Ring-LWE code line, pin `luxfi/corona@v0.1.x`.

## Quasar composition

Both libraries are independently complete; `luxfi/consensus/protocol/quasar`
consumes them as parallel kernels selected per-chain via `FinalitySchemeID`.

> **Status: Research / Reference (not production hardened, not FIPS validated).**
> NIST-profile vectors use SHAKE / cSHAKE / KMAC. Any BLAKE3 deltas are
> experimental and out-of-scope for the MPTC submission.

## Why

NIST FIPS 204 (ML-DSA) is the only NIST-approved post-quantum digital
signature in 2026. Threshold variants of ML-DSA are not yet standardized —
NIST's [Multi-Party Threshold Cryptography](https://csrc.nist.gov/projects/threshold-cryptography)
project is collecting them now (IR 8214C, January 2026; first call package
deadline expected 2026-Nov-16).

Pulsar aims to enter that process with a credible, output-interchangeable
threshold ML-DSA candidate — built from the production-tested protocol
machinery shipping in `luxfi/corona` (Ring-LWE), retargeted to the
Module-LWE primitives ML-DSA itself uses.

The win, if Pulsar's Sign output is byte-equal to FIPS 204 Sign:
- Threshold-produced signatures verify under unmodified FIPS 204 verifiers.
- Existing FIPS-validated ML-DSA modules (BoringSSL FIPS, AWS-LC, OpenSSL
  3.0 PQ provider) consume Pulsar certs without code changes.
- The threshold layer can be Class-N-claimed at NIST without a parallel
  algorithm standardization track.

## Repository layout

```
pulsar/
├── docs/                     human-readable design notes
│   ├── threat-model.md
│   ├── nist-mptc-category.md
│   ├── design-decisions.md
│   ├── BLOCKERS.md
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
├── scripts/                  build.sh / test.sh / bench.sh / gen_vectors.sh / sbom.sh
└── go.mod
```

## Quickstart

> **Pulsar is in pre-spec stage.** Reference impl, vectors, and bench harness
> ship after the spec freezes. Track [BLOCKERS.md](BLOCKERS.md)
> for what's stable vs in-flight.

```bash
git clone https://github.com/luxfi/pulsar
cd pulsar
./scripts/build.sh       # checks spec compile + Go build
./scripts/test.sh        # runs unit + KAT suite (when available)
./scripts/bench.sh       # reproduces bench/results/ (when available)
./scripts/gen_vectors.sh # regenerates KATs from reference impl (when available)
```

## NIST MPTC submission

| package element | location | status |
|---|---|---|
| Technical Specification | `spec/pulsar.pdf` (built from `spec/pulsar.tex`) | draft |
| Reference Implementation | `ref/go/` | skeleton |
| Report on Experimental Evaluation | `bench/results/REPORT.md` | TBD |
| Notes on Patent Claims | `spec/patent-notes.tex` | TBD |
| Open-source license | `LICENSE` (Apache-2.0) | ✓ |
| Build/test/benchmark scripts | `scripts/` | skeleton |
| I/O test vectors | `vectors/kat-v1.{json,rsp}` | TBD |

Target dates:
- **2026-Jul-20** preview writeup (NIST third preview deadline)
- **2026-Nov-16** package submission (NIST first call deadline)

## Relationship to upstream and siblings

Pulsar is independent of its sibling and academic predecessor — no
import line, no shared types. The relationship table is provenance,
not dependency.

| repo | role | lattice basis | hash family | status |
|---|---|---|---|---|
| [luxfi/nasua](https://github.com/luxfi/nasua) | **academic** R-LWE 2-round threshold sig (Boschini–Kaviani–Lai–Malavolta–Takahashi–Tibouchi, ePrint 2024/1113); trusted-dealer DKG only | Ring-LWE (`R_q`) | BLAKE3 | historical reference fork (no public-chain use) |
| [luxfi/corona](https://github.com/luxfi/corona) | **production** R-LWE threshold ML-DSA — Pedersen DKG over `R_q` + proactive resharing | Ring-LWE (`R_q`) | SHA-3 / cSHAKE256 (SP 800-185) | production library |
| **luxfi/pulsar** (this repo) | **production** Module-LWE threshold ML-DSA; output byte-equal to FIPS 204 ML-DSA | Module-LWE (`R_q^k`) | SHA-3 / cSHAKE256 (SP 800-185) | production library |
| [luxfi/pulsar-mptc](https://github.com/luxfi/pulsar-mptc) | NIST MPTC submission package (frozen artifact for review) | Module-LWE (`R_q^k`) | SHA-3 / SHAKE256 (NIST profile) | active submission package |

## Composition with Corona as optional layered PQ defense

Pulsar and Corona are independently usable: a chain can pick either as
its sole PQ threshold layer, no cross-dependency. Lux primary-network
QuasarCert combines them as a **Double Lattice** layered defence —
Module-LWE plus Ring-LWE — so a break in one lattice family does not
break finality:

```
QuasarCert {
    BLS         — optional classical fast-path (BLS-12-381 aggregate)
    Corona      — Ring-LWE threshold ML-DSA   (luxfi/corona)
    Pulsar      — Module-LWE threshold ML-DSA (this repo)
    MLDSARollup — per-validator ML-DSA-65 rolled up via STARK/FRI (P3Q)
}
```

Each layer is checkable independently with no shared code; selecting
the layer happens at chain-construction time via the `FinalitySchemeID`
axis on the chain's `ChainSecurityProfile`. The pure-PQ profile drops
BLS entirely and runs on `Corona + Pulsar`.

## Security

`SECURITY.md` describes how to disclose vulnerabilities and what's in-scope for
bug bounty.

## License

Apache-2.0 — same as `luxfi/corona` and `luxfi/nasua`. See `LICENSE`.
