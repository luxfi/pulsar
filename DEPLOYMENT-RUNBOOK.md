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

## v0.2 algebraic threshold — public-BFT path

> **Status (v1.0.13)**: v0.2 wire shape ships in
> `ref/go/pkg/pulsar/threshold_v02.go`. The protocol surface
> implements the FROST-for-FSwA flow: parties hold polynomial-vector
> Shamir shares of `(s_1, s_2, t_0)` over GF(q) (not seed shares),
> Round 1 commits `w_i = A·y_i`, an intermediate `w`-reveal pass
> exchanges per-party `w_i` under MAC, Round 2 contributes
> `(z_i, cs2_i, ct0_i)` algebraically, and `AlgebraicCombine`
> aggregates after verifying every commit-bind and Round-2 MAC.

### Two paths, two trust models

Pulsar v1.0.13 ships **both** trust-model targets in parallel:

- **v0.1 reveal-and-aggregate path** — `pulsar.Combine` in
  `ref/go/pkg/pulsar/threshold.go`. The aggregator briefly
  reconstructs the master ML-DSA seed (via Lagrange interpolation
  over byte-wise GF(257) shares) and emits the signature through
  `mldsa{44,65,87}.SignTo`. **TEE-attestation is mandatory** for
  funds-bearing networks; the aggregator process is in the trusted
  computing base for the duration of one sign call.

- **v0.2 algebraic-threshold path** — `pulsar.AlgebraicCombine` in
  `ref/go/pkg/pulsar/threshold_v02.go`. The protocol-side wire shape
  is the FROST-for-FSwA structure with polynomial-vector shares as
  the carrier. Parties never hold the master seed in any form. **At
  the inner sign step the current v1.0.13 implementation invokes
  `mldsa{44,65,87}.SignTo` via the `AlgebraicSetup.SkBytes` field;
  see the file header status block for the v0.3 work that closes
  this transitional gap.** The wire shape, share distribution,
  Round-1 commitments, intermediate `w`-reveal, and Round-2 MACs are
  all production-grade and exercised by the test suite.

### Public-BFT custody choice

The v0.2 path is the **target** for public-BFT custody surfaces (Lux
consensus quorums where no single operator can be assumed in the TCB).
While the v0.3 work to remove the transitional `SkBytes` field is in
flight, integrators MUST choose between:

1. **v0.1 with TEE attestation** — production-ready today; operator
   sign-off on the TEE requirement is on file.
2. **v0.2 wire-shape adoption** — production-deploy the protocol
   surface today (the consensus-layer message routing, share
   directory, and commit-and-reveal exchange match v0.3 byte-for-
   byte); the inner sign step delegates to the v0.1 reconstruction
   path **at the aggregator role only**, gated behind the same TEE
   requirement until v0.3 ships. Adopters get the v0.2 wire-shape
   migration done; the v0.3 inner-sign swap is a drop-in replacement
   that preserves the message flow and test vectors.

### What v0.2 buys today (v1.0.13)

- **No seed-share leakage at parties**: polynomial-vector shares are
  the only secret material parties hold. A `PolyKeyShare` is
  information-theoretically `(t-1)`-secret against any coalition of
  fewer than `t` parties.
- **Wire-shape stability**: the v0.2 message flow (commit /
  intermediate w-reveal / sign-contribute / aggregate) is stable
  across v0.2 → v0.3. Consensus integrators that adopt the v0.2
  protocol surface today get the message routing right;
  v0.3 only changes the cryptographic content of `AlgebraicCombine`.
- **Identifiable-abort gates**: every MAC and commit-bind check in
  `AlgebraicCombine` emits `AbortEvidence` on tamper detection,
  matching v0.1's complaint taxonomy.

### What v0.2 does NOT yet do (v1.0.13)

- The inner sign step still uses the master FIPS 204 packed sk via
  `AlgebraicSetup.SkBytes`. This means the aggregator side of the
  v0.2 path has the same TCB property as v0.1 at sign time. The v0.3
  patch removes `SkBytes` from `AlgebraicSetup` and emits the
  signature from the aggregated per-party contributions directly.
- The byte-equality test (`v0.2 algebraic signature byte-equal to
  stock FIPS 204 ML-DSA on the same y aggregate`) is delivered via
  the transitional path; the v0.3 pure-algebraic emission requires
  a self-contained FIPS 204 sign-side polynomial-ring implementation
  in `mldsa_lattice.go` (NTT, Montgomery, decompose, MakeHint) that
  currently has a subtle Montgomery-scaling discrepancy against
  cloudflare/circl's internal package — see `threshold_v02.go`
  header status block for the diagnosis.

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
