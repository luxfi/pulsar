# Closed-finding registry — luxfi/pulsar

**Status: submission-ready. No open items.**

Forward-looking v1.2 extensions are tracked under
`## Forward-looking (v1.2)` below; they are EXTENSIONS surfaced by the
2026-06 fresh four-dimension audit (`AUDIT-2026-06.md`), not flaws in
the v1.1.1 claims.

This file is the closed-finding registry. New findings open under
`## Open`; on fix they move to `## Closed` with commit + tag. IDs
are cited from source-code comments and from
`docs/cryptographer-sign-off.md`, `docs/deployment.md`,
`SUBMISSION.md`, `spec/blockers.tex`.

Earlier IDs `CR-6` / `CR-7` / `CR-8` (KEM-wrap of DKG envelopes,
ephemeral per-pair session keys, identity-bound MAC layer) survive
only as source-code references. They closed in the
luxfi/pulsar-mptc → luxfi/pulsar consolidation (commit `7be057b`,
v1.0.7 sign-off); the canonical narrative lives in `CHANGELOG.md`
and the v1.0.7 sign-off.

## Open

### PULSAR-V13-HINT-LEAK (CRITICAL)

The v0.3/v0.4 `AlgebraicAggregate*` path broadcasts `CS2 = c·λ_i·s_{2,i}`
and `CT0 = c·λ_i·t_{0,i}` **unmasked** (`ref/go/pkg/pulsar/threshold_v03.go`
round2EmitFull, ~:930-963) and reconstructs `c·s2_joint`, `c·t0_joint` at
the aggregator (~:1131-1168). Both are secret-key-derived: `c`, `λ_i`
public ⇒ `s_{2,i} = (c·λ_i)^{-1}·CS2` (one session when `c` invertible;
else accumulate). Worse, `c·s2_joint = c·s2_master` (Shamir), so revealing
the **aggregate** over varying public `c` leaks the long-term secret-key
components `s2` (and likewise `t0`) via a linear system, plus the secret
relation `A·s1 = (t1·2^d + t0) − s2`; whether or not this immediately
recovers short `s1` (a lattice/preimage problem), threshold secrecy and
transcript simulation are already broken. Leaderless ⇒ every
quorum member aggregates ⇒ every corrupt validator learns it each round.
The in-code `PUBLIC-BFT-SAFETY NOTE` claiming `(z_i,cs2_i,ct0_i)` are
`(t−1)`-secret is **false** — it only covers the `y_i`-masked `z_i`.

Confirmed by adversarial audit (`AUDIT-2026-06.md` re-audit) + direct code
read. Masking the individual shares is necessary but **not** sufficient —
the aggregate reconstruction still leaks the master key. The fix must
never reconstruct `c·s2`/`c·t0`/`r0`.

**Containment (landed, branch `fix/threshold-mldsa-hint-leak`):**
`Round2Sign` now **fails closed** with `ErrUnsafeThresholdV03HintPath`
unless `AllowUnsafeThresholdV03ForTests` is set (test
`TestThresholdV03DisabledByDefault`). The dangerously-false `(t−1)`-secret
note is corrected.

**Replacement design + verified math core:** boundary-cleared nonces +
carry elimination (`spec/threshold-mldsa-boundary-clearance.tex`,
`threshold_bcc.go`). The hint is computed from the **public**
`w' = A·z − c·t1·2^d` and `w1 = HighBits(w)` strictly via FIPS `UseHint`
(`findHintToTarget`); boundary clearance (margin `2β`) keeps the small
`c·s2` shift off the boundary; `c·t0` is structurally
`‖c·t0‖∞ ≤ τ·2^{d-1} < γ2` for **ML-DSA-65/87 only** (param-guarded).
Verified (`threshold_bcc_test.go`, all green): `FindHintToTarget↔UseHint`
round-trip, `BoundaryClear ⇒ HighBits-stable + r0-bound`, exact off-by-one
edges, offline yield ≈ **9.8 %**.

**NOT RESOLVED.** The math is verified but the production path is not built.
Resolution criteria (all required for NIST/consensus):
- [x] `AlgebraicAggregate*` disabled in production builds (hard gate).
- [x] Hint derived only via public `FindHintToTarget(w', w1)` (FIPS `UseHint`).
- [x] No production code computes `c·s2`/`c·t0`/`r0`/`LowBits(residual)`.
- [x] Boundary predicate proves the hidden `r0` bound; ML-DSA-65 scope enforced.
- [ ] `CS2`/`CT0` and all hint-secret wire fields **deleted** from production messages (reflection test).
- [ ] **Full `w` never public / reconstructible** (PULSAR-V13-W-LEAK) — needs the ZK clearance proof.
- [ ] Partial-`z` correctness proof (PULSAR-V13-PARTIAL-Z-PROOF).
- [ ] Canonical, non-grindable nonce selection.
- [ ] DKG never reconstructs the master key / `t0`; certifies the `t0` bound.
- [ ] Rejected attempts simulatable, not publicly leaked; coarse abort classes.
- [ ] Tree aggregation (z-sums + bitmaps + proof roots) for ~1000 signers.
- [ ] Two-certificate consensus artifact (ML-DSA sig + signer bitmap/transcript root).
- [ ] Final sigs verify under ≥2 independent FIPS 204 verifiers on the BCC path.
- [ ] External cryptographic review of the no-MPC leaderless instantiation.

### PULSAR-V13-W-LEAK (CRITICAL — replacement-design hazard)

The boundary-cleared nonce certificate must **not** publish the full
commitment `w = A·y`. Once `z` is assembled, `w' = A·z − c·t1·2^d` is
public, so anyone with full `w` computes `w' − w = c·t0 − c·s2 = Δ` — the
same challenge-multiplied long-term-secret residual as PULSAR-V13-HINT-LEAK,
in a different form. Production may publish only `w1 = HighBits(w)`, a
commitment to `w`, and a **zero-knowledge boundary-clearance proof** (that a
hidden `w = A·y` is boundary-clear), never full `w`, `w_i` shares that
reconstruct it, `LowBits(w)`, or `w' − w`. The current `BoundaryClear(w)`
Go predicate and `spec` are **debug-oracle/prototype**: production needs the
ZK proof machinery, which does not yet exist ⇒ the BCC/CEF signing path is
**prototype, not production**, even though the arithmetic tests pass.

### PULSAR-V13-PARTIAL-Z-PROOF (HIGH — consensus robustness)

BCC/CEF removes the hint-path leakage, but leaderless consensus also needs
proof-carrying `z`-partials: each signer proves `z_i = λ_i·y_i + c·λ_i·s_{1,i}`
bound to `(session_id, nonce_id, party_id, DKG share commitment, nonce
commitment)` without revealing `y_i`/`s_{1,i}`. Otherwise one bad partial
fails the aggregate with no clean blame path (leaderless DoS). Verify
partials **without** `c·s2_i`/`c·t0_i`/`r0_i`/hint shares (those fields must
not exist).

## Forward-looking (v1.2)

These are EXTENSIONS surfaced by the 2026-06 fresh four-dimension audit
(`AUDIT-2026-06.md`). Both are independent of every closed finding;
both ship as decomplected hooks that do NOT touch existing wire form,
ABI, or any FIPS 204 byte-equality contract. Neither is a flaw in the
current claims — they are deferred-by-design forward-pointing items
filed for the next minor.

### PULSAR-V12-TEE-BIND — TEE-quote binding helper for permissionless quorum gating

**Status**: SCAFFOLDED at audit time (commit pending). One pure
function `AttestationContext(setup, msg)` in
`ref/go/pkg/pulsar/attest.go` returning the canonical 32-byte TBS
digest a validator's TEE quote should bind to when the host chain
gates permissionless-quorum admission on attestation presence. Five
unit tests pin stability + nil-input safety + full input-coverage
sensitivity + customisation domain-separation
(`ref/go/pkg/pulsar/attest_test.go`).

**Why v1.2 not v1.1.x**: the audit treats the existing v1.1.1 claims
(byte-equality, public-BFT safety, FIPS 204 §5.4 ctx-bound) as the
single canonical home. The TEE-binding helper extends the surface
without altering it; bundling under v1.2 keeps the v1.1.x cut focused
on PULSAR-V04-CTX closure.

**What this is NOT**: it is not a TEE attestation verifier. The
chain-validating attestation verifier lives at
`github.com/luxfi/mpc/cc/attest`. Pulsar's role is to declare the
canonical TBS bytes; the verifier role belongs to the consensus
envelope.

**Custody-mode TEE path**: unchanged.
`github.com/luxfi/threshold/protocols/mldsa-tee` already ships the
SEV-SNP / TDX / NRAS-attested custody surface that materialises the
master seed inside an attested TEE. The permissionless v0.3 path does
NOT materialise sk at any party by construction, so attestation there
is a policy gate, not a safety primitive.

### PULSAR-V12-GPU-NTT-WIRE — route Round-2 NTTs through gpu-kernels batched dispatch

**Status**: SPEC only. The substrate
(`lux-private/gpu-kernels/ops/lattice/ntt_mldsa`, q = 8380417, R = 2^32,
byte-equal to PQClean `MLDSA65_CLEAN_ntt`) ships across all five
backends (CUDA, HIP, Metal, Vulkan, WGSL). The C ABI
`lux_lattice_ntt_mldsa_batch` is the natural batched-NTT entry. The
existing `pulsar/gpu.UseAccelerator` keeps the SubRing-dispatch
threshold above pulsar's N=256 production ring so single-poly GPU
dispatch is intentionally off (it loses to pure-Go at N=256 on every
host). The batched dispatch (22 forward NTTs per Round-2-party-attempt
on independent polys) is where the GPU win lives.

**Three discrete pieces**:

- **Substrate**: lift `lux_mldsa_verify_batch` and
  `lux_lattice_ntt_mldsa_batch` from `ErrNotSupported` stub
  (`luxfi/accel/internal/capi/capi.go:503-531`) to a real call.
- **Pulsar batched NTT entry**: package-private `batchNTT(polys []poly)`
  in `mldsa_lattice.go` that dispatches via accel iff
  `pulsar/gpu.Enabled()` and `accel.Available()` and
  `len(polys) >= batchThreshold`; otherwise falls back to the existing
  per-poly pure-Go `ntt()`.
- **Round-2 batched call sites**: replace per-poly loops in
  `threshold_v03.go:680-913` with `batchNTT` calls per logical batch
  (yHat, s1Hat, cs2-input, ct0-input).

**Byte-equality contract**: enforced by the existing
`TestPulsar_GPU_ByteEqual` regression guard
(`threshold_v03_gpu_byte_eq_test.go`). Today it passes vacuously (both
legs run pure-Go); after PULSAR-V12-GPU-NTT-WIRE lands it pins the
accel-engaged leg byte-equal to the pure-Go leg.

**Engine-layer batch verify**: pulsar's CPU
`VerifyBatch` already defers GPU acceleration to the engine layer per
`verify_batch.go:11-23`. The substrate (`MLDSAVerifyBatch`) is the
forward-looking item, not pulsar code; engine wiring at
`/Users/z/work/lux/consensus/engine/gpu_batch_pipeline.go` adds the
MLDSA batch path once the substrate ships.

## Closed

### PULSAR-V04-CTX — v0.4 ctx-bound threshold sign (FIPS 204 §5.4)

**Status**: CLOSED in v1.1.1 (tag pending — see CHANGELOG.md for the
exact commit).
**Owner**: cryptographer.

#### Root cause

`OrchestrateV03Sign` (and the underlying `AlgebraicAggregate` +
`AlgebraicThresholdSigner.round2EmitFull`) hardcoded the FIPS 204
§5.4 step-2 ctx prefix to the empty-ctx encoding:

```go
// BEFORE (v1.0.x): μ derivation
h := sha3.NewShake256()
h.Write(tr[:])
h.Write([]byte{0x00, 0x00})   // ← always empty ctx
h.Write(message)
h.Read(mu[:])
```

ctx-bound permissionless threshold sign was therefore impossible:
operators that needed FIPS 204 §5.2 domain separation (e.g. the
`lux-evm-precompile-mldsa-v1` EVM precompile) had to route through
the threshold dispatcher's `dealerKey` single-party shortcut, which
materialised the master sk in the dispatcher process — breaking the
v0.3 public-BFT-safety contract for any session that used the
ctx-bound path.

#### Fix

Decomplect μ derivation into a single helper `deriveMuCtx(tr, ctx,
msg, out)` (threshold_v03.go) that the v0.4 path threads ctx into the
FIPS 204 §5.4 prefix:

```go
// AFTER (v1.1.1): single source of truth
func deriveMuCtx(tr [64]byte, ctx, msg, out []byte) {
    h := sha3.NewShake256()
    h.Write(tr[:])
    h.Write([]byte{0x00, byte(len(ctx))})   // FIPS 204 §5.4 single-byte length
    if len(ctx) > 0 { h.Write(ctx) }
    h.Write(msg)
    h.Read(out[:64])
}
```

New ctx-aware API surface:

- `NewAlgebraicThresholdSignerCtx(..., ctx, ...)` — adds `Ctx`
  field on `AlgebraicThresholdSigner`.
- `AlgebraicAggregateCtx(..., ctx, ...)` — companion to
  `AlgebraicAggregate`.
- `OrchestrateV03SignCtx(..., ctx, ...)` — companion to
  `OrchestrateV03Sign`.

Backwards-compatibility invariants:

- `OrchestrateV03Sign(msg)` is now a thin wrapper that calls
  `OrchestrateV03SignCtx(nil, msg)`. Output bytes are
  byte-identical to historical v0.3 (pinned by
  `TestOrchestrateV03SignCtx_EmptyCtx_MatchesV03Sign`).
- `AlgebraicAggregate(...)` is now a thin wrapper that calls
  `AlgebraicAggregateCtx(..., nil, ...)`. Same byte-identity.
- `NewAlgebraicThresholdSigner(...)` is now a thin wrapper that calls
  `NewAlgebraicThresholdSignerCtx(..., nil, ...)`. The `Ctx` field is
  nil on the historical constructor.

ctx-length guard: `ErrCtxTooLarge` (alias of `ErrCtxTooLong` from
sign.go) at all three boundaries — constructor, aggregator, and
orchestrator.

#### Graduation gate

All currently TRUE on the tip of `main` at v1.1.1:

1. `TestOrchestrateV03SignCtx_Mu_Includes_Ctx` PASS — distinct ctx
   yields distinct μ; the production `deriveMuCtx` matches the
   reference SHAKE-256 byte-for-byte; empty `nil` ctx equals empty
   `[]byte{}` ctx (FIPS 204 §5.4 step-2 encoding).
2. `TestOrchestrateV03SignCtx_EmptyCtx_MatchesV03Sign` PASS —
   under identical deterministic RNG seeds, `OrchestrateV03Sign(msg)`
   and `OrchestrateV03SignCtx(nil, msg)` emit bit-identical wire
   bytes. Existing chain certs remain valid.
3. `TestOrchestrateV03SignCtx_CtxTooLarge_Rejected` PASS — 256-byte
   ctx rejected with `ErrCtxTooLarge` at constructor, aggregator,
   and orchestrator; 255-byte ctx accepted at the boundary.
4. `TestOrchestrateV03SignCtx_VerifyMatchesFIPS204` PASS — the
   output verifies under cloudflare/circl's stock FIPS 204
   `mldsa65.Verify(pub, msg, ctx, sig)` and is REJECTED under
   different ctx or empty ctx (ctx binding is real). Aggregator-
   side ctx mismatch against the signers' ctx fails at MAC verification
   or norm rejection — never produces a valid sig under a different
   ctx than the signers used.
5. `TestAlgebraic_NoSkAccess/AlgebraicAggregate` and
   `TestAlgebraic_NoSkAccess/AlgebraicAggregateCtx` PASS — AST guard
   now covers BOTH the wrapper and the ctx-bound entry point. No
   sk-bearing parameter, no sk-bearing call, no sk-bearing identifier.
6. All v1.0.22 graduation gates remain TRUE (`TestAlgebraic_FullCycle_n5_t3`,
   `TestAlgebraic_ByteValid`, `TestAMatrix_IsAlreadyInNTTDomain`,
   `TestCirclInternalShape_VsPulsar`).
7. Race-clean: `cd ref/go && GOWORK=off go test -race -count=1 -short
   -timeout 900s ./pkg/pulsar/`.

### PULSAR-V03-1 — v0.3 algebraic sign: byte-equality with circl Verify

**Status**: CLOSED in v1.0.20 (commit `023a3ed`).
Regression-guard hardening in v1.0.21 (`267ec04`) and v1.0.22 (`29094a7`).
**Owner**: cryptographer.

#### Root cause

`deriveKeyMaterial` in `ref/go/pkg/pulsar/mldsa_keyderive.go` was
applying a spurious forward NTT to the public matrix `A` AFTER
sampling it via `polyDeriveUniform`:

```go
// BEFORE (buggy, v1.0.19 and earlier), per (i,j) over K×L:
polyDeriveUniform(&km.a[i][j], &km.rho, ...)   // already NTT-domain
// ... later, separate K×L pass over the same matrix:
km.a[i][j].ntt()                               // EXTRA NTT — wrong
```

Per FIPS 204 §3.5 Algorithm 32 (`ExpandA`), `A` is sampled DIRECTLY
into the NTT representation; no separate forward-NTT step exists.
`polyDeriveUniform` is exactly that algorithm — byte-identical to
cloudflare/circl@v1.6.3's `PolyDeriveUniform`. The post-step produced
double-NTT'd values.

Why the bug was invisible before v0.3:

- **v0.1** calls `circl.SignTo`, which maintains its own `A`.
- **v0.2** emits via `circl.SignTo(setup.SkBytes, ...)`; the wrong `A`
  only entered transcript-level commits, which are self-consistent
  across parties.
- **keygen** consumes `km.a` BEFORE the spurious NTT step (in
  `t = A·s1 + s2`), so the public key matched circl byte-for-byte.
  Only the post-step contaminated the cached `km.a` that v0.3 sign
  later consumed as `setup.A`.

v0.3 was the first mode that propagated the wrong `A` all the way to
the output signature.

#### Fix

Drop the post-sample NTT loop in `deriveKeyMaterial`. The same
redundant `.ntt()` in `manualVerifyOnce` (`threshold_v03_bytediff_test.go`)
and in `TestPrimDiff_VerifyPipeline_OnCirclSig` was removed.

Regression guards pin the convention byte-for-byte against circl's
stored `pk.A`: `TestAMatrix_IsAlreadyInNTTDomain` compares `km.a` (the
contaminated field) at corners `[0][0]` and `[K-1][L-1]`;
`TestCirclInternalShape_VsPulsar` mirrors circl's `PublicKey` via
unsafe-pointer and asserts `km.a == pk.A`. v1.0.22 also hardened the
AST guard in `TestAlgebraic_NoSkAccess` to walk `*ast.SelectorExpr.Sel.Name`
and `*ast.Ident`, so an indirect dispatch (`var fn = polyDeriveUniformLeqEta;
fn(...)`) cannot bypass the banned-call check on `AlgebraicAggregate`.

#### Graduation gate

All currently TRUE on the tip of `main` at v1.0.22:

1. `TestAlgebraic_FullCycle_n5_t3` PASS — v0.3 sig verifies under
   stock `mldsa65.Verify`.
2. `TestAlgebraic_NoSkAccess` PASS — public-BFT safety contract:
   `AlgebraicAggregate` has no `*PrivateKey`/`SkBytes`/`seed`
   parameter; AST walks confirm no sk-bearing primitive is reachable
   from its body (including indirect dispatch).
3. `TestAMatrix_IsAlreadyInNTTDomain` and
   `TestCirclInternalShape_VsPulsar` PASS — byte-equality vs circl
   `pk.A`.
4. `TestTransitional_DependsOnSkBytes` PASS — v0.2 still declares
   its SkBytes dependency honestly. (The original gate expected this
   to FAIL on the assumption v0.2 would be edited in place; the
   actual closure shipped v0.3 as a parallel track and left v0.2
   honest. Both paths now coexist.)
5. Class N1 byte-equality preserved: `TestN1_ByteEquality_*` PASS.
6. Full suite green under `-race`:
   `cd ref/go && GOWORK=off go test -count=1 -short -timeout 300s ./pkg/pulsar/`.
