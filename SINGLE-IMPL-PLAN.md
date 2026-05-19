# SINGLE-IMPL-PLAN — COMPLETED 2026-05-18

> **Status: COMPLETED.** The plan to collapse the two parallel
> implementation trees into one canonical home at `luxfi/pulsar`
> landed in commits `20f87d8` (file-by-file merge of submission-grade
> code into the canonical Go reference), `174941a` (uniform identity
> stage on the large-committee path), `443c725` (cryptographer
> sign-off), and the consolidation that produced this revision (merge
> of the entire submission framework — spec, proofs, Jasmin, KAT,
> cut tool, submission docs — into `luxfi/pulsar`).
>
> This file is kept as a historical record. The "two-repo" arrangement
> it describes no longer exists.

## Final state

The `luxfi/pulsar` repository is now the **single canonical home**:

| Concern | Where it lives |
|---|---|
| Canonical Go reference implementation | `ref/go/pkg/pulsar/` |
| Canonical KAT generator | `ref/go/cmd/genkat/` |
| Canonical LaTeX spec | `spec/pulsar.tex` + supplements |
| Mechanised proofs (EasyCrypt) | `proofs/easycrypt/` |
| Lean ↔ EC bridge | `proofs/lean-easycrypt-bridge.md` |
| Jasmin (low-level CT) sources | `jasmin/lib/`, `jasmin/ml-dsa-65/`, `jasmin/threshold/` |
| Constant-time evidence (dudect) | `ct/dudect/` |
| Reproducible benchmarks | `bench/` |
| KAT vectors | `vectors/` |
| Cross-validation (Class N1 interop) | `test/interoperability/` |
| Submission cover sheet | `SUBMISSION.md` |
| Cut tool | `scripts/cut-submission.sh` |
| High-assurance / Lean-bridge gates | `scripts/check-high-assurance.sh`, `scripts/check-lean-bridge.sh` |

## What this plan resolved

The original (now-historical) divergence between the two trees:

| Tree | Files | Notes |
|---|---:|---|
| `luxfi/pulsar-mptc/ref/go/pkg/pulsar/` | 28 | submission focus: identifiable abort, identity stage, N1 byte-equality test, fuzz, zeroize |
| `luxfi/pulsar/ref/go/pkg/pulsar/` | 37 | production focus: large-scale variants, round abstraction, batch verify, shamir over GF(q), precompile e2e |

Both trees' divergent work has been merged into the single canonical
`luxfi/pulsar/ref/go/pkg/pulsar/`. Identifiable abort, identity
stage (CR-7 + CR-8), N1 byte-equality test, fuzz harness, and
zeroize are all present and applied uniformly on both the small
(GF(257)) and large (GF(q)) committee paths. Large-scale variants,
batch verify, round abstraction, generic-field Shamir, and the
precompile e2e remain.

## Closure criteria — all met

- [x] Single canonical `ref/go/pkg/pulsar/` in `luxfi/pulsar` (no
      duplicate impl in `luxfi/pulsar-mptc`).
- [x] CR-6 / CR-7 / CR-8 closed uniformly on small + large paths.
- [x] N1 byte-equality verified by 19/19 interop subtests vs
      cloudflare/circl FIPS 204.
- [x] EC theorems admit-free (13/13); Lean ↔ EC bridge 5/5.
- [x] KATs deterministic; round-trip replay byte-identical.
- [x] Cryptographer sign-off APPROVED WITH GATES (CRYPTOGRAPHER-SIGN-OFF.md).
- [x] Submission framework (spec, proofs, Jasmin, KAT, cut tool,
      submission docs) merged into `luxfi/pulsar`; `luxfi/pulsar-mptc`
      archived / redirected.

---

**Document metadata**

- Name: `SINGLE-IMPL-PLAN.md`
- Status: COMPLETED
- Date completed: 2026-05-18
- Final commit: this consolidation merges the submission framework
  into the canonical `luxfi/pulsar`; previous milestones recorded in
  the commit log (`git log` in `luxfi/pulsar`).
