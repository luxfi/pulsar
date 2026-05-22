# SYNC-STATUS — pulsar-mptc ↔ pulsar ↔ proofs ↔ papers ↔ LPs

> Cross-repo sync audit answering: *"is `~/work/lux/pulsar` up to date
> and integrated with the latest `pulsar-mptc` submission package?
> Do `~/work/lux/proofs` and `~/work/lux/papers` have full indexes?
> Do the LPs match?"*
>
> Audit date: 2026-05-18. Updated after every cross-repo sync action.

## TL;DR

| Question | Answer |
|---|---|
| Is `~/work/lux/pulsar` integrated with `pulsar-mptc`? | **Two repos by design.** pulsar/ = production library; pulsar-mptc/ = NIST submission package. Same Go module path. Not a fork-and-merge relationship. |
| Are they in sync where they overlap? | **Partially.** `spec/pulsar.tex` is current in both; supplementary `.tex` (design-decisions, family-architecture, threat-model, nist-mptc-category, patent-notes) lives in `pulsar/spec/` only; proofs + jasmin live in `pulsar-mptc/` only. |
| Does `~/work/lux/proofs/` have an index? | **Yes now** — `proofs/INDEX.md` regenerated 2026-05-18 (104 Lean + 24 TLA+ + 10 Halmos + 6 Tamarin + 5 Go property + 22 LaTeX). |
| Does `~/work/lux/papers/` have an index? | **Yes** — `papers/INDEX.md` regenerated 2026-05-18 (17 root + 124 directory papers = 141 documents). |
| Do the LPs match the v0.1 submission package? | **LP-180 needs path refresh** (still references `pulsar-m` / `pulsarm` / `Pulsar_M` post-`af3d669` rename in `pulsar/`); `LP-073` is current; `CRYPTO-CANONICAL.md` does not yet list `pulsar-mptc` as the canonical NIST-submission home. |

## Repository roles

```
~/work/lux/
├── pulsar/                  ← Production Go library (luxfi/pulsar)
│   ├── spec/                  Full LaTeX spec set (pulsar.tex + 6 supplements)
│   ├── ref/go/                Go reference implementation
│   ├── bench/ ct/ scripts/ test/ vectors/   Production engineering
│   ├── LLM.md BLOCKERS.md README.md
│   └── *** NO proofs/ or jasmin/ ***
│
├── pulsar-mptc/             ← NIST MPTC submission package (this repo)
│   ├── SUBMISSION.md NIST-SUBMISSION.md     Submission cover sheets
│   ├── SPEC.md SUITE.md SYNC-STATUS.md      Companion docs
│   ├── PATENTS.md AXIOM-INVENTORY.md PROOF-CLAIMS.md
│   ├── FIPS-TRACEABILITY.md TRUSTED-COMPUTING-BASE.md
│   ├── HANZO-CRYPTO-SUITE.md INFORMATION-ARCHITECTURE.md
│   ├── ROADMAP.md CHANGELOG.md README.md
│   ├── docs/                  ietf-draft-skeleton, magnetar, evaluation,
│   │                          patent-claims, x-wing-sig
│   ├── spec/                  pulsar.tex + 3 supplements
│   ├── ref/go/                Same Go module path as pulsar/, frozen for NIST
│   ├── proofs/easycrypt/      EC theories (v4-v13 work)
│   ├── proofs/lean-easycrypt-bridge.md
│   ├── jasmin/lib/ jasmin/ml-dsa-65/ jasmin/threshold/
│   ├── scripts/               build + gen-vectors + bench + check-lean-bridge
│   └── vectors/               KAT vectors
│
├── proofs/                  ← All non-Pulsar mechanized proofs
│   ├── INDEX.md (regenerated 2026-05-18)
│   ├── README.md            Lean inventory + run commands
│   ├── lean/                 104 .lean files (Crypto/ Consensus/ ...)
│   ├── tla/                  24 specs + MC harnesses
│   ├── tamarin/              6 .spthy protocols
│   ├── halmos/               10 Solidity symbolic-exec suites
│   ├── property/             5 Go property tests
│   ├── pulsar/               9 LaTeX claim documents (mirror EC + Lean)
│   ├── quasar/ fhe/ lss/     LaTeX claim documents
│   ├── definitions/          Shared TeX definitions
│   ├── strict-e2e-pq/        E2E-PQ profile soundness
│   ├── pq-finality-no-bls.pdf
│   ├── quasar-cert-soundness.pdf
│   └── *** Pulsar EC + Jasmin live in pulsar-mptc/, NOT here ***
│
└── papers/                  ← All Lux research papers
    ├── INDEX.md (regenerated 2026-05-18)
    ├── 17 root-level .tex/.pdf (lux-pq-crypto-suite, lux-chain-architecture, ...)
    └── 124 directory papers (lp-073-pulsar/, lp-020-quasar-consensus/, ...)
```

## What changed in this audit

| Action | File | Status |
|---|---|---|
| Built top-level proofs index | `~/work/lux/proofs/INDEX.md` | **created** |
| Regenerated papers index from disk | `~/work/lux/papers/INDEX.md` | **refreshed (121 → 141)** |
| Wrote this sync status | `~/work/lux/pulsar-mptc/SYNC-STATUS.md` | **this file** |
| Wrote submission-readiness status | `~/work/lux/pulsar-mptc/STATUS-SUBMISSION-READINESS.md` | **created** |
| Wrote single-impl merge plan | `~/work/lux/pulsar-mptc/SINGLE-IMPL-PLAN.md` | **created** |
| Fix LP-180 stale `pulsar-m` paths | `~/work/lux/lps/LP-180-nist-mptc-submission.md` | **patched** |
| Add pulsar-mptc to CRYPTO-CANONICAL | `~/work/lux/lps/CRYPTO-CANONICAL.md` | **deferred — single-line cross-ref** |

## Open work: collapse to single Go implementation

`pulsar/ref/go/pkg/pulsar/` (37 files, 8 328 LOC) and
`pulsar-mptc/ref/go/pkg/pulsar/` (28 files, 7 383 LOC) have **diverged
in parallel** — all 23 shared files differ, 5 files are unique to
pulsar-mptc (identity, zeroize, n1_byte_equality_test, fuzz_test),
14 files are unique to pulsar (large_*, round, verify_batch, etc.).

Collapsing to a single canonical implementation requires a real merge,
not a wholesale deletion. The merge specification lives in
`SINGLE-IMPL-PLAN.md`. Until executed, the duplicate trees stand and
this audit flags the divergence as open work blocking "one and only
one implementation" suite invariant.

## File-level comparison: `pulsar/` ↔ `pulsar-mptc/`

### Shared (`pulsar.tex` and `pulsar-m.tex`)

`pulsar/spec/pulsar.tex` (May 13, 78 433 bytes) post-dates the `-M`
qualifier removal (`pulsar` commit `af3d669`).
`pulsar-mptc/spec/pulsar.tex` (May 16, 77 007 bytes) is the
submission-frozen copy. The two diverge on layout / supplementary
appendices but agree on the protocol body — they are not expected to
be byte-identical.

### Only in `pulsar/spec/`

These supplementary `.tex` are intentional historical/reference
material in the production-library spec and are NOT carried into the
submission package:

```
spec/blockers.tex
spec/design-decisions.tex
spec/family-architecture.tex
spec/nist-mptc-category.tex
spec/patent-notes.tex
spec/threat-model.tex
```

### Only in `pulsar-mptc/`

The full NIST-submission documentation package + all formal-method
artifacts:

```
SUBMISSION.md NIST-SUBMISSION.md SPEC.md SUITE.md SYNC-STATUS.md
PATENTS.md AXIOM-INVENTORY.md PROOF-CLAIMS.md FIPS-TRACEABILITY.md
TRUSTED-COMPUTING-BASE.md HANZO-CRYPTO-SUITE.md
INFORMATION-ARCHITECTURE.md ROADMAP.md CHANGELOG.md
docs/ietf-draft-skeleton.md docs/magnetar.md docs/evaluation.md
docs/patent-claims.md docs/x-wing-sig.md
proofs/easycrypt/ (28 files; v4-v13 decomposition complete)
proofs/lean-easycrypt-bridge.md
jasmin/lib/ jasmin/ml-dsa-65/ jasmin/threshold/
```

## LP-180 stale paths

`LP-180-nist-mptc-submission.md` was drafted 2026-05-12 against the
pre-rename `pulsar-m` identifiers. The `pulsar/` repo dropped the
`-M` qualifier on 2026-05-16 (commits `af3d669` + `dff9e84`). LP-180
still uses:

| Stale path | Current path |
|---|---|
| `spec/pulsar-m.tex` | `spec/pulsar.tex` |
| `ref/go/pkg/pulsarm/` | `ref/go/pkg/pulsar/` |
| `Crypto/Pulsar_M/OutputInterchange.lean` | `Crypto/Pulsar/OutputInterchange.lean` |
| `Crypto/Pulsar_M/Unforgeability.lean` | `Crypto/Pulsar/Unforgeability.lean` |
| `Crypto/Pulsar_M/Shamir.lean` | `Crypto/Pulsar/Shamir.lean` |
| `proofs/easycrypt/PulsarM_N1.ec` | `proofs/easycrypt/Pulsar_N1.ec` |
| `proofs/easycrypt/PulsarM_N4.ec` | `proofs/easycrypt/Pulsar_N4.ec` |
| `lemmas/PulsarM_CT.ec` | `lemmas/Pulsar_CT.ec` |
| Module path `github.com/luxfi/pulsar-m` | `github.com/luxfi/pulsar` |

Patch lands in `lps` commit alongside this audit.

## Recommendations

1. **Keep two-repo split.** The `pulsar/` (production) ↔ `pulsar-mptc/`
   (submission) split is intentional per the pulsar-mptc README and
   LP-180. Do not merge.
2. **Cross-link the two READMEs.** Add a "submission package" pointer
   in `pulsar/README.md` and a "production library" pointer in
   `pulsar-mptc/README.md`. (Both READMEs already reference each
   other in prose — the pointer is the explicit Markdown link.)
3. **Promote SYNC-STATUS to a recurring artifact.** Re-run this audit
   each quarter or whenever a major rename / restructuring lands in
   either repo, and refresh the table.
4. **Add `pulsar-mptc` as a row in `CRYPTO-CANONICAL.md`.** Single
   line under the Module-LWE section pointing at this repo as the
   NIST-submission home, separate from the production library home.

## Per-repo status snapshot

| Repo | HEAD as of audit | Drift severity |
|---|---|---|
| `pulsar/` | `af3d669` (2026-05-16) — drop `-M` qualifier | None vs production role |
| `pulsar-mptc/` | `c2e01e3` (2026-05-18) — HANZO-CRYPTO-SUITE + X-Wing-Sig | None vs submission role |
| `proofs/` | post `2026-05-18` (INDEX.md added) | None |
| `papers/` | post `2026-05-18` (INDEX.md regenerated) | None |
| `lps/` | pre LP-180 path refresh | **needs LP-180 path patch** |

---

**Document metadata**

- Name: `SYNC-STATUS.md`
- Version: v0.1
- Date: 2026-05-18
- Owner: `submissions@lux.network`
- Re-run cadence: quarterly + after any cross-repo rename
