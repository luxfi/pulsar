# SYNC-STATUS — single canonical pulsar

> Cross-repo sync audit. As of the consolidation tagged below, the
> previous two-repo arrangement (`luxfi/pulsar` production library
> + `luxfi/pulsar-mptc` NIST submission framework) is collapsed
> into a single canonical home at `github.com/luxfi/pulsar`.
>
> Audit date: 2026-05-18.

## TL;DR

| Question | Answer |
|---|---|
| Where does the canonical Pulsar implementation live? | `github.com/luxfi/pulsar` — single repo, single module path. |
| Where does the NIST submission framework live? | Same repo. Cover sheet (`SUBMISSION.md`), spec (`spec/`), proofs (`proofs/`), Jasmin (`jasmin/`), KATs (`vectors/`), cut tool (`scripts/cut-submission.sh`) are all in-tree. |
| Does `~/work/lux/proofs/` have an index? | Yes — `~/work/lux/proofs/INDEX.md` regenerated 2026-05-18. |
| Does `~/work/lux/papers/` have an index? | Yes — `~/work/lux/papers/INDEX.md` regenerated 2026-05-18. |
| Do the LPs match the v0.1 submission package? | LP-180 may still reference legacy `pulsar-m` / `pulsarm` naming and should be refreshed; `LP-073` is current; `CRYPTO-CANONICAL.md` lists `luxfi/pulsar` as the canonical NIST-submission home. |

## Repository layout

```
~/work/lux/
├── pulsar/                  ← Single canonical home for Pulsar
│   ├── SUBMISSION.md NIST-SUBMISSION.md     Cover sheets
│   ├── SPEC.md SUITE.md SYNC-STATUS.md      Companion docs
│   ├── PATENTS.md AXIOM-INVENTORY.md PROOF-CLAIMS.md
│   ├── FIPS-TRACEABILITY.md TRUSTED-COMPUTING-BASE.md
│   ├── HANZO-CRYPTO-SUITE.md INFORMATION-ARCHITECTURE.md
│   ├── ROADMAP.md CHANGELOG.md README.md
│   ├── docs/                  ietf-draft-skeleton, magnetar, evaluation,
│   │                          patent-claims, x-wing-sig, design-decisions,
│   │                          family-architecture, threat-model,
│   │                          nist-mptc-category, patent-notes-draft
│   ├── spec/                  pulsar.tex + 9 supplements (.tex / .bib)
│   ├── ref/go/                Canonical Go reference implementation
│   ├── proofs/easycrypt/      EC theories (13/13 admit-free + 4 cited axioms)
│   ├── proofs/lean-easycrypt-bridge.md
│   ├── jasmin/lib/ jasmin/ml-dsa-65/ jasmin/threshold/
│   ├── ct/dudect/             Constant-time analysis sources
│   ├── bench/                 Reproducible benchmark harness
│   ├── scripts/               build + test + gen-vectors + bench + cut +
│   │                          check-high-assurance + check-lean-bridge +
│   │                          nightly + sbom + extract-jasmin-ec
│   ├── test/interoperability/ Class N1 cross-validation vs cloudflare/circl
│   ├── vectors/               KAT vectors
│   └── CRYPTOGRAPHER-SIGN-OFF.md
│
├── proofs/                  ← All non-Pulsar mechanized proofs
│   ├── INDEX.md
│   ├── lean/                 .lean files (Crypto/ Consensus/ ...)
│   ├── tla/                  TLA+ specs + MC harnesses
│   ├── tamarin/              .spthy protocols
│   ├── halmos/               Solidity symbolic-exec suites
│   └── property/             Go property tests
│
└── papers/                  ← LaTeX papers (publication-grade)
    ├── INDEX.md
    └── ...
```

## What this consolidation closes

Prior to 2026-05-18 the artifacts split between two repos:

| Artifact | Old location | New location |
|---|---|---|
| Canonical Go implementation | `luxfi/pulsar/ref/go/pkg/pulsar/` | unchanged |
| Cover sheet (`SUBMISSION.md`) | `luxfi/pulsar-mptc/SUBMISSION.md` | `luxfi/pulsar/SUBMISSION.md` |
| LaTeX spec (formal) | both | `luxfi/pulsar/spec/` |
| EasyCrypt + Lean bridge | `luxfi/pulsar-mptc/proofs/` | `luxfi/pulsar/proofs/` |
| Jasmin sources | `luxfi/pulsar-mptc/jasmin/` | `luxfi/pulsar/jasmin/` |
| dudect harness | both (stub vs full) | `luxfi/pulsar/ct/dudect/` |
| Cut tool | `luxfi/pulsar-mptc/scripts/cut-submission.sh` | `luxfi/pulsar/scripts/cut-submission.sh` |
| Submission docs (16 files) | `luxfi/pulsar-mptc/*.md` | `luxfi/pulsar/*.md` |
| Class N1 interop test | `luxfi/pulsar-mptc/test/interoperability/` | `luxfi/pulsar/test/interoperability/` |

The `luxfi/pulsar-mptc` repository is archived/redirected to
`luxfi/pulsar` post-consolidation.

## Cross-repo coherence checks (CI-guarded)

These scripts must remain green for every push to `main`:

| Script | What it checks |
|---|---|
| `scripts/check-high-assurance.sh` | EasyCrypt admit count = 0 on all theorems; refinement scaffolding present; cited-axiom list matches `AXIOM-INVENTORY.md`. |
| `scripts/check-lean-bridge.sh` | The 5 named Lean ↔ EC algebraic bridges are present in `~/work/lux/proofs/lean/` and referenced from `proofs/lean-easycrypt-bridge.md`. |
| `scripts/gen_vectors.sh` (with `--replay-only`) | Regenerated KATs are byte-identical to committed `vectors/*.json`. |
| `test/interoperability/n1_class_test.go` | Every committed KAT verifies under both the in-tree pulsar verifier and cloudflare/circl FIPS 204 verifier (19/19 subtests). |
