# SINGLE-IMPL-PLAN — collapse `pulsar-mptc/ref/go/pkg/pulsar/` into `luxfi/pulsar`

> Plan to honor "one and only one implementation" by making
> `pulsar-mptc/` a thin **submission framework** that depends on the
> canonical Go library at `github.com/luxfi/pulsar` rather than
> carrying a parallel implementation tree.
>
> Date: 2026-05-18. Status: **plan-only — no code deleted yet.**

## TL;DR

`pulsar-mptc/ref/go/pkg/pulsar/` and `pulsar/ref/go/pkg/pulsar/`
have **diverged in parallel**. Both trees have implementation work the
other lacks. A clean collapse requires a real merge into the canonical
`luxfi/pulsar`, then a Go-module dependency rewire — not a wholesale
deletion.

| Tree | Files | Lines | Notes |
|---|---:|---:|---|
| `pulsar-mptc/ref/go/pkg/pulsar/` | 28 | 7 383 | submission focus: identifiable abort, identity stage, n1 byte-equality test, fuzz, zeroize |
| `pulsar/ref/go/pkg/pulsar/` | 37 | 8 328 | production focus: large-scale variants, round abstraction, batch verify, shamir over GF(q), precompile e2e |

## Divergence inventory

### Only in `pulsar-mptc/` (5 files, ~600 lines)

| File | Purpose |
|---|---|
| `identity.go` | identity-stage logic |
| `identity_test.go` | identity tests |
| `n1_byte_equality_test.go` | submission-headline test for Class N1 byte equality |
| `fuzz_test.go` | go-test fuzz harness |
| `zeroize.go` | secret-material zeroization |

### Only in `pulsar/` (14 files, ~1500 lines)

| File | Purpose |
|---|---|
| `large_dkg.go`, `large_threshold.go`, `large_types.go`, `large_reshare.go` | large-scale variants (n ≫ 7) |
| `large_e2e_test.go` | large-scale e2e |
| `largeshamir.go`, `largeshamir_test.go` | shamir for large committees |
| `shamir_gfq.go`, `shamir_gfq_test.go` | shamir over generic field GF(q) |
| `round.go`, `round_test.go` | abstract round-state machine |
| `verify_batch.go`, `verify_batch_test.go` | batched verification (consensus throughput) |
| `precompile_e2e_test.go` | EVM-precompile end-to-end |

### Common 23 files — **all DIFFER**

`abort.go` `abort_test.go` `bench_test.go` `dkg.go` `dkg_test.go` `doc.go`
`kat_test.go` `keygen.go` `keygen_test.go` `params.go` `pulsar_test.go`
`reshare.go` `reshare_test.go` `shamir.go` `shamir_test.go` `sign.go`
`sign_test.go` `threshold.go` `threshold_test.go` `transcript.go`
`transcript_test.go` `types.go` `verify.go`

Sample delta: `abort.go` is 411 lines in pulsar-mptc vs 137 in pulsar
(274-line difference). Sample causes (from spot-check): submission-grade
abort-evidence verification was extended in pulsar-mptc; pulsar trimmed
back to a smaller production surface. Other large deltas in
`reshare.go` (+117), `threshold.go` (+59), `dkg.go` (+91).

## Merge strategy (forward direction = pulsar absorbs mptc)

The canonical destination is `~/work/lux/pulsar/` (production library).
The merge direction is **pulsar-mptc → pulsar**:

1. **Adopt the 5 mptc-only files into pulsar/** verbatim
   (`identity.go`, `identity_test.go`, `n1_byte_equality_test.go`,
   `fuzz_test.go`, `zeroize.go`).
2. **Reconcile the 23 common-but-divergent files** per-file. For
   each: 3-way merge using last common ancestor + mptc + pulsar. Land
   the **superset** of both trees' work into pulsar.
3. **Keep pulsar's 14 unique files** (large_*, round, batch, etc.) —
   they are already canonical.
4. **Run the union test suite** in `pulsar/` (all 37 + 5 = 42 source
   files, ~9 000 LOC). Confirm zero regressions.
5. **Tag `luxfi/pulsar` v1.1.0** with the merged surface.

## Rewire pulsar-mptc as a dependent (after merge)

After pulsar v1.1.0 ships:

1. **`pulsar-mptc/go.mod`** — add:
   ```
   require github.com/luxfi/pulsar v1.1.0
   replace github.com/luxfi/pulsar => ../pulsar   // local dev only
   ```
2. **Delete** `pulsar-mptc/ref/go/pkg/pulsar/` entirely (28 files).
3. **Repoint 3 imports** (currently `github.com/luxfi/pulsar-mptc/ref/go/pkg/pulsar` →
   `github.com/luxfi/pulsar/ref/go/pkg/pulsar`):
   - `ref/go/cmd/genkat/main.go:23`
   - `ct/dudect/verify_ct.go:66`
   - `ct/dudect/combine_ct.go:53`
4. **Fix `scripts/gen_vectors.sh:22`** — currently references
   stale `./ref/go/pkg/pulsarm/` (note the trailing `m`, removed by
   pulsar commit `af3d669` in 2026-05). Change to
   `github.com/luxfi/pulsar/ref/go/pkg/pulsar` package path.
5. **At submission cut**: `go mod vendor` under `pulsar-mptc/` so the
   NIST tarball contains a frozen snapshot of `luxfi/pulsar@v1.1.0`
   under `pulsar-mptc/vendor/github.com/luxfi/pulsar/`. NIST reviewers
   get a self-contained tarball without network fetch.

## Submission-package layout after collapse

```
pulsar-mptc/                  ← submission framework (Go-module dependent)
├── go.mod (require luxfi/pulsar v1.1.0)
├── go.sum
├── vendor/                    ← produced at submission cut via `go mod vendor`
│   └── github.com/luxfi/pulsar/   (frozen at v1.1.0)
├── ref/go/cmd/genkat/         ← KAT generator (imports vendored pulsar)
├── test/interoperability/      ← Class N1 cross-validation (independent verifier)
├── test/fuzz/                  ← submission-specific fuzz scenarios
├── test/negative/              ← submission-specific negative tests
├── ct/dudect/                  ← constant-time analysis harness
├── proofs/easycrypt/           ← EC theories (untouched)
├── proofs/lean-easycrypt-bridge.md
├── jasmin/                     ← Jasmin sources (untouched)
├── scripts/                    ← build/test/bench/gen_vectors (updated to use canonical)
├── vectors/                    ← KAT JSON output (unchanged)
├── bench/                      ← benchmark configs + results
├── *.md                        ← all submission docs (unchanged)
```

## What this buys

- **DRY**: 7 383 lines of Go in pulsar-mptc/ref/go/pkg/pulsar/ collapse
  to zero (one canonical impl in luxfi/pulsar).
- **Drift impossible**: every CI change in pulsar/ is automatically
  picked up by pulsar-mptc/ via go.mod.
- **NIST review surface clear**: SUBMISSION.md points NIST at the
  vendored snapshot under `vendor/github.com/luxfi/pulsar/` — single
  algorithm implementation, single test surface.
- **Production library stays the source of truth**: changes go into
  pulsar/, then a tag picks them up everywhere.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Merge introduces a subtle behavior change that breaks a KAT | Regenerate KATs from merged impl; diff against committed; only land if identical or with a documented seed change |
| pulsar's smaller `abort.go` is intentional (production-stripped) and merging back the larger mptc version reintroduces dead code | Per-file review with comments; reconcile not by union but by intent |
| Vendoring breaks the IETF / NIST `submission-2026-11-16` tag reproducibility if pulsar's HEAD drifts | Pin to exact commit/tag in go.mod; vendor produces a frozen tree |
| Local dev `replace ../pulsar` directive leaks into the submitted tarball | `scripts/cut-submission.sh` strips the replace directive at tag time |

## Execution checklist

- [ ] **Sub-session 1 — file-by-file merge (1-2 days)**: adopt 5
      mptc-only files into pulsar/; merge 23 common-divergent files;
      verify pulsar test suite passes on the union.
- [ ] **Sub-session 2 — release pulsar v1.1.0**: tag, push.
- [ ] **Sub-session 3 — pulsar-mptc rewire (½ day)**: go.mod, delete
      ref/go/pkg/pulsar/, update 3 imports + 1 script, vendor at submission cut.
- [ ] **Sub-session 4 — CI gate (¼ day)**: add `scripts/check-single-impl.sh`
      that fails if `pulsar-mptc/ref/go/pkg/pulsar/` re-appears.
- [ ] **Sub-session 5 — docs update (¼ day)**: refresh
      `SUBMISSION.md`, `STATUS-SUBMISSION-READINESS.md`, `SYNC-STATUS.md`
      to reflect single-impl.

## Why not just delete now

The two trees are not duplicates of each other — they have
PARALLEL EVOLUTIONS with **real implementation differences in
all 23 common files plus 19 unique files (5+14)**. A wholesale
deletion would drop ~600 lines of submission-grade work
(identifiable-abort extensions, identity-stage logic, n1 byte
equality test, zeroize, fuzz harness) from pulsar-mptc, OR drop
~1500 lines of production work (large-scale variants, batch verify,
round abstraction) from pulsar. Either is unacceptable.

The clean path is a deliberate merge. This document is the
specification for that merge.

---

**Document metadata**

- Name: `SINGLE-IMPL-PLAN.md`
- Version: v0.1
- Date: 2026-05-18
- Owner: `crypto-merge@lux.network`
- Blocks: NIST submission tarball cut (2026-11-16) — recommended but
  not strictly required (submission tarball can ship with current
  duplicate-impl layout if merge slips)
