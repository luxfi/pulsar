# Closed-finding registry — luxfi/pulsar

**Status: submission-ready. No open items.**

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

None.

## Closed

### PULSAR-V04-CTX — v0.4 ctx-bound threshold sign (FIPS 204 §5.4)

**Status**: CLOSED in v1.1.0 (tag pending — see CHANGELOG.md for the
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
// AFTER (v1.1.0): single source of truth
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

All currently TRUE on the tip of `main` at v1.1.0:

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
