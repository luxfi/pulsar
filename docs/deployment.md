# Deployment Runbook — luxfi/pulsar

> Operational guidance for deploying Pulsar (threshold ML-DSA-65) in
> production validator sets. Discloses the v0.1 trust-model caveat
> mandated by the cryptographer sign-off (GATE-1) and pins the
> safe operating envelope.

## TL;DR — which Combine variant for which deployment?

| Deployment scenario | Use | Why |
|---|---|---|
| **Public BFT, no aggregator-host trust** | `AlgebraicAggregate` (v0.3) | No `sk` is materialised at any party. Protocol-correct by construction. v1.0.20 closes the byte-equality gap (`BLOCKERS.md` → PULSAR-V03-1 closure record): the v0.3 signature now verifies under stock `cloudflare/circl` `mldsa65.Verify`. |
| **Public BFT, interop with stock FIPS 204** | `Combine` (v0.1) **inside a TEE** | Signature byte-equals `cloudflare/circl`, accepted by any FIPS 204 verifier. The aggregator host enters the TCB for the brief window of one `KeyFromSeed` call. Use SGX / SEV-SNP / TDX with remote attestation. |
| **M-Chain bridge custody (single operator, TEE in TCB by design)** | `Combine` (v0.1) | Same wire as above; dealer/aggregator trust is acceptable by deployment policy. |
| **A-Chain confidential compute (TEE-attested provider)** | `Combine` (v0.1) | TEE is part of the AI-provider attestation envelope (see `aivm`). |
| **Dev / test** | Either | Both produce valid threshold signatures; choose by interop need. |

## Public-BFT graduation gate

v1.0.20 (commit `023a3ed`) closes the gate.
`TestAlgebraic_FullCycle_n5_t3` PASSES — the v0.3 wire verifies under
stock `cloudflare/circl` `mldsa65.Verify`. Regression-guard
hardening shipped in v1.0.21 (`267ec04`) and v1.0.22 (`29094a7`).
PULSAR-V03-1 closure record: `BLOCKERS.md` (closed-finding registry).

## Audience

- Validator operators bringing up a Pulsar-enabled Lux chain (or
  any chain consuming `github.com/luxfi/pulsar`).
- Coordinator-service operators running the witness-aggregator
  pattern.
- Security reviewers validating production posture against the
  cryptographer sign-off (`cryptographer-sign-off.md`).

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
- [ ] `cryptographer-sign-off.md` reviewed; all four gates either
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

## v0.2 transitional threshold — trust model

> **Status (v1.0.14)**: v0.2 ships in
> `ref/go/pkg/pulsar/threshold_v02.go` under the **Transitional**
> name. The wire protocol is honestly algebraic — parties hold
> polynomial-vector Shamir shares of `(s_1, s_2, t_0)` over GF(q),
> Round 1 commits `w_i = A·y_i`, an intermediate `w`-reveal pass
> exchanges per-party `w_i` under MAC, Round 2 contributes
> `(z_i, cs2_i, ct0_i)` algebraically. **The aggregator side is NOT
> yet algebraic**: `TransitionalAggregate` validates every
> commit-bind and MAC, then calls `mldsa{44,65,87}.SignTo` against
> the master sk packed in `TransitionalSetup.SkBytes`. This is the
> v0.2 honesty caveat the rename from `Algebraic*` to
> `Transitional*` exists to declare.

### Two paths, two trust models

Pulsar v1.0.14 ships **both** trust-model targets in parallel:

- **v0.1 reveal-and-aggregate path** — `pulsar.Combine` in
  `ref/go/pkg/pulsar/threshold.go`. The aggregator briefly
  reconstructs the master ML-DSA seed (via Lagrange interpolation
  over byte-wise GF(257) shares) and emits the signature through
  `mldsa{44,65,87}.SignTo`. **TEE-attestation is mandatory** for
  funds-bearing networks; the aggregator process is in the trusted
  computing base for the duration of one sign call.

- **v0.2 transitional path** — `pulsar.TransitionalAggregate` in
  `ref/go/pkg/pulsar/threshold_v02.go`. The protocol-side wire
  shape is FROST-for-FSwA with polynomial-vector shares as the
  carrier; parties never broadcast a share of the master seed in
  any form. **The aggregator side still holds the master sk** via
  `TransitionalSetup.SkBytes` and signs with it — the per-party
  `(Z, CS2, CT0)` contributions are validated for commit-bind /
  MAC integrity but are NOT consumed by the inner sign step. The
  aggregator TCB at sign time is identical to v0.1; only the
  parties' side of the protocol is honestly algebraic.
  `TransitionalAggregate` enforces `len(setup.SkBytes) > 0` —
  `TestTransitional_DependsOnSkBytes` pins this in code as the
  load-bearing v0.3 graduation criterion.

### v0.2 trust model — when is it safe to deploy?

`TransitionalAggregate` IS safe to deploy when:

1. The aggregator host is **already in the TCB by other means**
   (TEE attestation pinned to a reproducible Pulsar build; HSM-
   custody; single-operator deployment where the operator already
   sees all key material).
2. M-Chain bridge custody where the bridge MPC node is the
   aggregator and TEE attestation is mandatory at the operator
   layer.
3. A-Chain confidential-compute subnets where the entire
   aggregator process runs inside SGX/TDX with remote attestation.

`TransitionalAggregate` is **NOT** safe to deploy when:

1. The aggregator host is **not** in the TCB (public adversarial
   deployment where any node may be compromised).
2. The validator set assumes "no single host holds the master sk
   ever" — v0.2 violates this at the aggregator's brief sign
   window.

For deployments in the "NOT safe" bucket, use v0.1 Combine behind
an explicit TEE attestation layer at the consumer (the wire shape
is mature, the TCB caveat is well-documented in the v0.1
disclosure section above), OR wait for v0.3.

### v0.3 milestone — graduation gate

The v0.3 work removes the `SkBytes` field from `TransitionalSetup`
entirely. The graduation gate is one bit:

> When `TransitionalAggregate` no longer needs `setup.SkBytes` —
> i.e. when it emits the FIPS 204 signature directly from the
> aggregated per-party `(Z, CS2, CT0)` contributions — the v0.3
> milestone is met.

Operationally this is tracked by `TestTransitional_DependsOnSkBytes`
in `threshold_v02_test.go`. The test currently PASSES (because
`TransitionalAggregate` does depend on `SkBytes`); when v0.3 lands,
that test FAILS, and the failure is the load-bearing red flag that
the v0.3 graduation is complete. At that point:

1. Drop the `SkBytes` field from `TransitionalSetup`.
2. Rename `TransitionalAggregate` → `AlgebraicAggregate` (forward-only,
   no compat alias — the discipline matches the v1.0.14
   `Algebraic` → `Transitional` rename).
3. Rewrite the file-header honesty block.
4. Replace `TestTransitional_DependsOnSkBytes` with the v0.3
   no-sk-access AST guard already shipping in
   `TestAlgebraic_NoSkAccess`.

PULSAR-V03-1 byte-equality closed in v1.0.20 (commit `023a3ed`).
Closure record: `BLOCKERS.md`.

### What v0.2 buys today (v1.0.14)

- **No seed-share leakage at parties**: polynomial-vector shares
  are the only secret material parties hold. A `PolyKeyShare` is
  information-theoretically `(t-1)`-secret against any coalition
  of fewer than `t` parties.
- **Wire-shape stability**: the v0.2 message flow (commit /
  intermediate w-reveal / sign-contribute / aggregate) is stable
  across v0.2 → v0.3. Consensus integrators that adopt the v0.2
  protocol surface today get the message routing right;
  v0.3 only changes the cryptographic content of
  `TransitionalAggregate` → `AlgebraicAggregate`.
- **Identifiable-abort gates**: every MAC and commit-bind check in
  `TransitionalAggregate` emits `AbortEvidence` on tamper
  detection, matching v0.1's complaint taxonomy.

### What v0.2 does NOT yet do (v1.0.14)

- The inner sign step still uses the master FIPS 204 packed sk via
  `TransitionalSetup.SkBytes`. The aggregator TCB at sign time is
  identical to v0.1. The v0.3 patch removes `SkBytes` from
  `TransitionalSetup` and emits the signature from the aggregated
  per-party contributions directly.
- The byte-equality test (`v0.2 transitional signature byte-equal
  to stock FIPS 204 ML-DSA on the same y aggregate`) is delivered
  via the transitional path; the v0.3 pure-algebraic emission
  requires a self-contained FIPS 204 sign-side polynomial-ring
  implementation in `mldsa_lattice.go` (NTT, Montgomery, decompose,
  MakeHint) that currently has a subtle Montgomery-scaling
  discrepancy against cloudflare/circl's internal package — see
  `threshold_v02.go` header for the diagnosis.

## Reference: Cryptographer gates

The four gates from `cryptographer-sign-off.md`:

| Gate | Status |
|---|---|
| GATE-1 — Aggregator trust runbook disclosure | **CLOSED by this document.** |
| GATE-2 — `SUBMISSION.md` cross-link to two-variant disclosure | **CLOSED** in `SUBMISSION.md` "Headline claim" + "What to read first" §12. |
| GATE-3 — dudect 10⁹-sample run | **CLOSED** — `scripts/nightly.sh` runs the submission-grade harness; results check into `ct/dudect/results/`. Per-push smoke runs at 10⁵ samples per `proof-claims.md` §3.2. |
| GATE-4 — Minor doc nits | **CLOSED**: 89.7% → 84.2% coverage corrected in `SUBMISSION.md`; Ed25519 → ML-DSA-65 in `spec/pulsar.tex` §Identifiable abort; `proof-claims.md` §3.2 dudect cross-link added; `zeroize.go` row added. |

## Contact

- Operations: `ops@lux.network`
- Security: `security@lux.network`
- Submission package: `submissions@lux.network`

---

**Document metadata**

- Name: `deployment.md`
- Version: v0.3 (matches Pulsar v1.0.22)
- Closes: `cryptographer-sign-off.md` GATE-1.
- v1.0.14: renamed v0.2 API from `Algebraic*` → `Transitional*` and
  rewrote the trust-model section to honestly disclose the
  aggregator-side `SkBytes` dependency. The v0.2 wire protocol is
  algebraic; the v0.2 aggregator is not.
- v1.0.20–v1.0.22: PULSAR-V03-1 closure — v0.3 `AlgebraicAggregate`
  emits a signature byte-equal to single-party FIPS 204 ML-DSA-65
  under stock `cloudflare/circl` `mldsa65.Verify`.
