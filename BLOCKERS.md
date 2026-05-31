# BLOCKERS — luxfi/pulsar

Closed-finding registry. New findings go under `## Open`; on fix they
move to `## Closed` with commit + tag. IDs are cited from source-code
comments and from `docs/cryptographer-sign-off.md`, `docs/deployment.md`,
`NIST-SUBMISSION.md`, `spec/blockers.tex`.

Earlier IDs `CR-6`/`CR-7`/`CR-8` (KEM-wrap of DKG envelopes, ephemeral
per-pair session keys, identity-bound MAC layer) survive only as
source-code references. They closed in the luxfi/pulsar-mptc →
luxfi/pulsar consolidation (commit `7be057b`, v1.0.7 sign-off);
canonical narrative lives in `CHANGELOG.md` + v1.0.7 sign-off.

## Open

None.

## Closed

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
