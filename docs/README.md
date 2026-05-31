# docs/ — Pulsar documentation index

Supporting documentation for the Pulsar NIST MPTC submission. The
submission cover sheet (`/SUBMISSION.md`), `BLOCKERS.md`,
`CHANGELOG.md`, `LICENSE`, `SECURITY.md`, and `CONTRIBUTING.md` live
at the repository root. Everything else is here.

## Reviewer reading path

If you have limited time:

1. `proof-claims.md` — narrow N1 byte-equality claim; what's proved vs not.
2. `proof-axiom-inventory.md` — residual EC axioms with closure plans.
3. `tcb.md` — what's trusted (EC / Jasmin / OCaml).
4. `fips-204-traceability.md` — op/lemma → FIPS 204 § map.
5. `cryptographer-sign-off.md` — independent review (APPROVED WITH GATES).
6. `evaluation.md` — performance + correctness evidence.
7. `deployment.md` — operator runbook.

## Submission-package documents

| File | Purpose |
|---|---|
| `proof-claims.md` | Narrow Class N1 byte-equality claim — what is and is not proved. |
| `proof-axiom-inventory.md` | Per-axiom residual EC trust accounting + closure plans. |
| `tcb.md` | Trusted computing base — EC / Jasmin / OCaml / Lean layers. |
| `fips-204-traceability.md` | Reference-impl op + EC lemma → FIPS 204 § map. |
| `evaluation.md` | Experimental evaluation per NIST IR 8214C §6. |
| `cryptographer-sign-off.md` | Independent cryptographer review + four pre-publish gates. |
| `deployment.md` | Operator runbook for the v0.3 algebraic aggregator. |
| `spec-overview.md` | Text protocol spec mirroring `spec/pulsar.tex` §§ 1-19. |
| `ietf-draft-skeleton.md` | IETF / CFRG draft skeleton (`draft-hanzo-pulsar-threshold-mldsa-00`). |
| `nist-mptc-category.md` | MPTC class N1 + N4 mapping. |
| `threat-model.md` | Adversary classes + assumptions. |
| `design-decisions.md` | Frozen design decisions (DD-001 …). |
| `family-architecture.md` | Pulsar / Corona / Magnetar primitive split. |
| `magnetar.md` | Tier 3 SLH-DSA threshold research placeholder. |
| `x-wing-sig.md` | Proposed hybrid classical+PQ signature wrapper. |

## Patent + license documents

| File | Purpose |
|---|---|
| `patents.md` | Royalty-free patent grant text + defensive termination. |
| `patent-claims.md` | 21 attorney-prep claim drafts (internal). |
| `licensing-notes.md` | Apache-2.0 placement in the Lux three-tier IP strategy. |

## Suite + cross-repo orientation

| File | Purpose |
|---|---|
| `suite.md` | Hanzo PQ Threshold Suite index (Tiers 1-4) + broader Lux/Hanzo crypto inventory appendix. |
| `information-architecture.md` | Cross-repo taxonomy — where each artifact lives. |
| `sync-status.md` | Cross-repo audit between `pulsar`, `corona`, `proofs`, `papers`, `lps`. |
| `single-impl-plan.md` | Historical: merge plan from `pulsar-mptc` into `pulsar`. |

## Roadmap + status

| File | Purpose |
|---|---|
| `status.md` | Live submission-readiness status across NIST / IETF / FIPS / ACVP tracks. |
| `roadmap.md` | Multi-year roadmap (v0.2 Corona packaging, FIPS 140-3, etc). |
