# Deployment Runbook — luxfi/pulsar

> Operational guidance for deploying Pulsar (threshold ML-DSA-65) in
> production validator sets. Discloses the v0.1 trust-model caveat
> mandated by the cryptographer sign-off (GATE-1) and pins the
> safe operating envelope.

## Audience

- Validator operators bringing up a Pulsar-enabled Lux chain (or
  any chain consuming `github.com/luxfi/pulsar`).
- Coordinator-service operators running the witness-aggregator
  pattern.
- Security reviewers validating production posture against the
  cryptographer sign-off (`CRYPTOGRAPHER-SIGN-OFF.md`).

## Trust-model disclosure (load-bearing)

### The v0.1 reconstruction-aggregator caveat

> **Operators MUST acknowledge this before running v0.1 in production
> on funds-bearing networks.** It is the GATE-1 deferred disclosure
> from the cryptographer sign-off.

Pulsar v1.0.8 ships the **v0.1 reveal-and-aggregate** flow as the
runnable reference. In this flow, `Combine` (in
`ref/go/pkg/pulsar/threshold.go`) briefly reassembles the master
ML-DSA-65 seed in the aggregator process's memory by computing
Lagrange reconstruction over the revealed partial signatures and
invoking `mldsa65.NewKeyFromSeed`. The seed exists in memory only
for the duration of a single `KeyFromSeed` call and is zeroized on
every exit path via `ref/go/pkg/pulsar/zeroize.go`
(`zeroizeBytes` / `zeroizeSeed` / `zeroizeU16` /
`zeroizePrivateKey`), including error paths.

**TCB implication**: the aggregator process is in the trusted
computing base for that brief window. An adversary who fully
compromises the aggregator host (root-equivalent) during that
window observes the seed and can forge signatures going forward.

**Operational mitigations** (all production deployments MUST
satisfy at least items 1–4):

1. **Aggregator host hardening**: dedicated host, no general-purpose
   workloads, no shared memory, no /proc access for non-root users,
   hugepages disabled (prevents same-page deduplication side-channels).
2. **Memory isolation**: the aggregator process runs with locked
   pages (`mlock`), core-dumps disabled (`setrlimit RLIMIT_CORE=0`),
   ptrace disabled (`prctl PR_SET_DUMPABLE 0`).
3. **TEE attestation (recommended)**: aggregator runs inside SGX,
   SEV-SNP, or TDX with remote attestation pinned to the
   reproducible build of `luxfi/pulsar v1.0.8`.
4. **Operational scope limits**: aggregator role is a single-purpose
   process; no network listener beyond the consensus message bus;
   no shell access; no debugger attachment in production.
5. **Defense-in-depth (v0.2 migration target)**: the v0.2 FSwA
   Lagrange-linearity flow eliminates the reconstruction step
   entirely. v0.2 is the high-assurance target and EasyCrypt N1
   reduction is stated against it; v0.2 Jasmin sources type-check.
   Production migration v0.1 → v0.2 is on the roadmap (see
   `~/work/lux/lps/ROADMAP-CRYPTO-STACK.md`).

### What v0.1 does NOT do

- Does NOT persist the reconstructed seed to disk.
- Does NOT leak the seed to any other process under normal
  operation.
- Does NOT have a code path that copies the seed to a buffer that
  outlives the `KeyFromSeed` call.
- Does NOT survive a process crash with seed material present (the
  seed lives entirely on the stack of one goroutine; OS process
  teardown reclaims it).

The TCB equivalence is "aggregator process == single-party FIPS
204 signer". The distributed threshold property holds against the
participating committee adversaries (any t-1 collusion among the
n parties), but it does NOT extend to an attacker who compromises
the aggregator host itself.

## Pre-deployment checklist

Before bringing up a Pulsar-enabled validator:

- [ ] Operator-readable acknowledgement of the v0.1 trust caveat
      above on file (RACI sign-off).
- [ ] Aggregator host meets items 1–4 above.
- [ ] If running on funds-bearing mainnet: item 3 (TEE attestation)
      satisfied OR documented compensating control approved by
      security review.
- [ ] `scripts/check-high-assurance.sh` exits 0 against the
      deployed binary's source tag (i.e., the binary you are
      deploying was built from a commit where the high-assurance
      gates were green).
- [ ] `CRYPTOGRAPHER-SIGN-OFF.md` reviewed; all four gates either
      satisfied or have a compensating control on file.
- [ ] Run `go test -race ./ref/go/pkg/pulsar/` against the deployed
      tag; PASS.
- [ ] Run `test/interoperability/` against the deployed tag;
      19/19 N1 subtests PASS.

## At-runtime monitoring

The aggregator process should expose:

- A metric for every `Combine` invocation (counter +
  latency-histogram).
- A metric for every zeroize call on the seed material (counter;
  should match Combine invocations 1:1).
- A panic / signal handler that wipes the seed memory before exit.

Anomalous values for the zeroize counter (lower than the Combine
counter) indicate a missed cleanup path — page immediately.

## v0.1 → v0.2 migration plan

See `~/work/lux/lps/ROADMAP-CRYPTO-STACK.md` §Pulsar v0.2 milestones. The migration is
backward-incompatible at the wire level (v0.2 partial-signature
encoding differs) but byte-equivalent at the output (final FIPS 204
signature is identical). Coordinated validator-set rollover is
required.

## Reference: Cryptographer GATEs

The four gates from `CRYPTOGRAPHER-SIGN-OFF.md`:

| Gate | Status as of v1.0.8 |
|---|---|
| GATE-1 — Aggregator trust runbook disclosure | **CLOSED by this document.** |
| GATE-2 — SUBMISSION.md cross-link to BLOCKERS "Spec ↔ Go-reference protocol drift" | **CLOSED** in `SUBMISSION.md` "Headline claim" + "What to read first" §12. |
| GATE-3 — dudect ≥ 10⁹ samples for submission grade | **OPEN** — harness wired (`ct/dudect/run-submission.sh`); awaiting next nightly window. Per-push smoke runs are informational only per `PROOF-CLAIMS.md` §3.2. |
| GATE-4 — Minor doc nits | **CLOSED**: 89.7%→84.2% coverage corrected in SUBMISSION.md; Ed25519→ML-DSA-65 in spec/pulsar.tex §Identifiable abort; PROOF-CLAIMS.md §3.2 dudect cross-link added; zeroize.go row added. |

## Contact

- Operations: `ops@lux.network`
- Security: `security@lux.network`
- Submission package: `submissions@lux.network`

---

**Document metadata**

- Name: `DEPLOYMENT-RUNBOOK.md`
- Version: v0.1 (matches Pulsar v1.0.8)
- Date: 2026-05-18
- Closes: `CRYPTOGRAPHER-SIGN-OFF.md` GATE-1.
