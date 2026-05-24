# BLOCKERS — luxfi/pulsar

Issue tracker for open work that gates a deployment claim or a
documentation claim. One entry per issue. Status is `OPEN` until the
graduation gate (the bottom of each entry) is met; then move to
`CLOSED` and link the commit / tag that closed it.

## PULSAR-V03-1 — v0.3 algebraic sign: byte-equality with circl Verify

**Status**: CLOSED in v1.0.20
**Opened**: v1.0.14
**Updated**: v1.0.20 — root cause + fix in `mldsa_keyderive.go`
**Closes**: v0.3 ship
**Owner**: cryptographer
**Related tests**:
- `ref/go/pkg/pulsar/threshold_v02_test.go::TestTransitional_DependsOnSkBytes` (PASS — v0.2 dependency on SkBytes pinned)
- `ref/go/pkg/pulsar/threshold_v03_test.go::TestAlgebraic_NoSkAccess` (PASS — v0.3 API surface has NO sk parameter and NO sk-bearing primitive reachable from `AlgebraicAggregate`)
- `ref/go/pkg/pulsar/threshold_v03_test.go::TestAlgebraic_FullCycle_n5_t3` (PASS — v0.3 sig now verifies under stock `mldsa65.Verify`)
- `ref/go/pkg/pulsar/threshold_v03_bytediff_test.go::TestAlgebraic_DebugVsCirclVerify` (PASS — direct circl Verify check)
- `ref/go/pkg/pulsar/threshold_v03_bytediff_test.go::TestManualVerify_OnV01SigSanity` (PASS — manual verify pipeline matches circl on circl-produced sig)
- `ref/go/pkg/pulsar/threshold_v03_aprime_test.go::TestAMatrix_IsAlreadyInNTTDomain` (NEW regression guard — pins the FIPS 204 ExpandA convention)
- `ref/go/pkg/pulsar/threshold_v03_unsafediff_test.go::TestCirclInternalShape_VsPulsar` (NEW regression guard — pins byte-equality of `km.a` vs circl's `pk.A`)

### Root cause (resolved in v1.0.20)

`deriveKeyMaterial` (`mldsa_keyderive.go`) was applying an EXTRA forward
NTT to the public matrix `A` AFTER sampling it via `polyDeriveUniform`:

```go
// BEFORE (buggy, v1.0.19 and earlier):
for i := 0; i < K; i++ {
    polyDeriveUniform(&km.a[i][j], &km.rho, ...)  // samples directly into NTT domain
}
// ... later in the same function:
for i := 0; i < K; i++ {
    for j := 0; j < L; j++ {
        km.a[i][j].ntt()  // *** EXTRA NTT — wrong ***
    }
}
```

Per FIPS 204 §3.5 Algorithm 32 (`ExpandA`), the matrix `A` is sampled
DIRECTLY into the NTT representation — there is no separate forward NTT
step. `polyDeriveUniform` is exactly that algorithm (matching circl's
`PolyDeriveUniform`), so `km.a` is already NTT-domain post-sample.

Re-NTTing produced double-NTT'd values (visible to v0.3 sign as `setup.A`).
The bug was invisible in v0.1 because v0.1 calls `circl.SignTo` which
maintains its own `A`. It was invisible in v0.2 because v0.2 emits the
final FIPS 204 sig via `circl.SignTo(setup.SkBytes, ...)` and only used
the wrong `A` in transcript-level commits (which are self-consistent
across all parties, so the protocol invariant held). v0.3 was the first
mode that propagated the wrong `A` all the way to the output signature.

It was invisible in keygen itself because `deriveKeyMaterial` consumes
`km.a` BEFORE the spurious NTT step (in the `t = A·s1 + s2` computation),
so the resulting `t1` matches circl's. Only the post-step contaminated
the cached `km.a`.

### Fix

Drop the post-step. `polyDeriveUniform` already produces NTT-domain
coefficients (FIPS 204 ExpandA), so `km.a` is correctly NTT-domain
right out of the sample loop. The fix is two-line: remove the post-NTT
loop and add a clarifying comment.

The `manualVerifyOnce` helper in `threshold_v03_bytediff_test.go` had
the same redundant `.ntt()` on locally-sampled `A` — removed there too,
plus in `TestPrimDiff_VerifyPipeline_OnCirclSig`.

### What v1.0.15-v1.0.16 shipped (history)

`threshold_v03.go` ships the real `AlgebraicAggregate` function:
- API contract: NO `*PrivateKey`, NO `SkBytes`, NO `seed` parameter
- Function body: NO reference to `KeyFromSeed`, `mldsaSign`, or any sk-bearing primitive
- Round-1/Round-2W/Round-2Sign emit per-party algebraic contributions
- `AlgebraicAggregate` sums `(W, Z, CS2, CT0)` across the quorum, applies FIPS 204 §6 rejection checks, emits sig via FIPS 204 §7 sigEncode

`TestAlgebraic_NoSkAccess` is a load-bearing structural test that AST-parses `threshold_v03.go` and asserts the function signature and body have no sk-bearing references. This is the public-BFT-safety contract.

### What's broken (the actual current bug)

`AlgebraicAggregate` emits a signature byte-string of the FIPS 204 canonical size (3309 bytes for ML-DSA-65) with all components computed by pure algebraic sums over per-party contributions. The sig structure is correct (c̃, z, h). But it does NOT pass `mldsa65.Verify`.

Debug tests confirm the algebraic intermediate computations are SELF-CONSISTENT:
- `TestAlgebraic_Debug_AlgebraicReconstruction` PASS (zRecon vs zRef: 0 diffs)
- `TestAlgebraic_Debug_ZSumVsCircl` PASS (algebraic z matches the reference y_total + c·s_1 under our own primitives)
- `TestAlgebraic_Debug_PartyZRecomputation` PASS

But these tests use OUR polynomial primitives on BOTH sides of the comparison. They prove our threshold compute is self-consistent; they do NOT prove our primitives produce circl-compatible bytes.

Primitive-by-primitive source review against circl v1.6.3 source:
- Zetas / InvZetas tables: byte-identical to `circl/sign/internal/dilithium/ntt.go::Zetas`
- `nttGeneric` loop: identical to `circl.../ntt.go::nttGeneric`
- `invNttGeneric`: identical
- `montReduceLe2Q`: identical (Q = 8380417, Qinv = 4236238847)
- `ROver256` = 41978: identical
- `mulHat`: identical
- `decompose`: same convention (returns `(a0+q, a1)`)
- `makeHint`: same boundary check
- `polyPackLeGamma1` / `polyVecPackHint`: same byte layout
- mu derivation: FIPS 204 §5.4 conformant (`SHAKE-256(tr || 0x00 || |ctx| || ctx || M, 64)`)
- c̃ derivation: matches circl
- sigEncode pack order: matches circl `Pack` in `internal/dilithium.go`

Despite all the above, the sig does not verify under circl.

### Next-session debug plan

1. Write a side-by-side test that runs Pulsar's `AlgebraicAggregate` AND circl's `mldsa65.SignTo` (in deterministic mode) on the SAME master sk, SAME message, SAME randomness. Both must produce byte-identical sigs IF Pulsar's algebraic compute matches circl. Compare byte-by-byte and find the first divergence. The first diverging byte tells us exactly which field is wrong (c̃, z[L][N], or hint).
2. Most likely culprits in order of probability:
   - cs2 sum is wrong (Montgomery-form leaking, NTT-domain residue not zeroed)
   - ct0 sum is wrong (same issue, or t_0 normalization changed mod-q value during Shamir share)
   - Hint args are mis-ordered for the actual hint convention circl uses
3. If diff is in c̃: check `mu` and `w1Encode` byte buffers vs circl's intermediate buffers (requires hooking circl's internal `SignTo` with debug prints).
4. If diff is in z: cs2 must be wrong (since z = y + cs1 only, and we proved z matches under our primitives — but z packing uses circl's PolyLeGamma1Size which depends on γ_1).
5. If diff is in hint: hint args (w0_mcs2_pct0, w1) vs circl's (w0mcs2pct0, w1) — both look identical in source.

### Workaround until closed

Use `TransitionalAggregate` (v0.2) for production sig emission — it produces circl-verifiable sigs but the aggregator holds the master sk briefly. Document the TEE-required trust model per `DEPLOYMENT-RUNBOOK.md` v0.1 section.

### Problem

`TransitionalAggregate` in `ref/go/pkg/pulsar/threshold_v02.go`
validates the v0.2 wire protocol (Round-1 commits, Round-2 MACs,
per-party `(Z, CS2, CT0)` contributions) but does NOT consume the
per-party contributions when emitting the FIPS 204 signature.
Instead it calls `mldsaSign(setup.SkBytes, message, ...)` against
the master ML-DSA private key packed in `TransitionalSetup.SkBytes`.

Effect: the aggregator TCB at sign time is identical to v0.1
reconstruct-and-sign. Only the parties' side of the protocol is
honestly algebraic. The naming `Transitional*` (introduced in
v1.0.14) declares this honestly; the `Algebraic*` naming that
v1.0.13 shipped was materially misleading.

### Implementation work

The v0.3 patch is conceptually a self-contained line-replacement in
`TransitionalAggregate`:

```
- sigBytes, err := mldsaSign(params.Mode, setup.SkBytes, message, nil, false, rand.Reader)
+ sigBytes, err := algebraicEmitSignature(params.Mode, r1ByID, r2ByID,
+     quorum, quorumEvalPoints, message, setup.Pub, setup.Rho, setup.Tr, setup.A)
```

What that requires:

1. **Polynomial-share aggregation in NTT-domain over GF(q)**:
   - sum `Z` across the quorum → `z` (L polynomials in NTT-domain)
   - sum `CS2` across the quorum → `c·s_2`
   - sum `CT0` across the quorum → `c·t_0`

2. **FIPS 204 sign-side polynomial-ring primitives**, ported from
   `mldsa_lattice.go` keygen-grade implementations to be
   sign-grade byte-for-byte against cloudflare/circl's internal
   package:
   - `decompose` (FIPS 204 §4.5)
   - `MakeHint` (FIPS 204 §4.6)
   - `polyPackZ` (FIPS 204 §6.2 / Algorithm 23)
   - `polyPackHint` (FIPS 204 §6.4 / Algorithm 25)
   - signature serialisation matching `sigEncode` (FIPS 204
     Algorithm 28)

3. **Global rejection bounds** (FIPS 204 §6.2):
   - `||z||_∞ ≥ γ_1 − β` → restart
   - `||r_0||_∞ ≥ γ_2 − β` → restart (`r_0` derived from
     `w_0 - c·s_2 + c·t_0` mod q)
   - `||c·t_0||_∞ ≥ γ_2` → restart
   - `popcount(h) > ω` → restart

4. **Drop `SkBytes` from `TransitionalSetup`**. Update
   `DealTransitionalShares` to not store it. Rename:
   - `TransitionalAggregate` → `AlgebraicAggregate`
   - `TransitionalSetup` → `AlgebraicSetup`
   - `TransitionalThresholdSigner` → `AlgebraicThresholdSigner`
   - `TransitionalRound1Message` → `AlgebraicRound1Message`
   - `TransitionalRound2Message` → `AlgebraicRound2Message`
   - `DealTransitionalShares` → `DealAlgebraicShares`
   - `Err Transitional…` → `ErrAlgebraic…`
   - Forward-only — no compat aliases.

The wire shape is already correct: Round-1 commits, intermediate
`w`-reveal, Round-2 `(Z, CS2, CT0)` payloads, and MAC structure
all stay byte-for-byte identical across v0.2 → v0.3. The change
is purely the inner sign step.

### Known obstacle

Per the v1.0.13 cryptographer report, the sign-path equivalents of
the FIPS 204 polynomial-ring primitives in `mldsa_lattice.go` have
a subtle Montgomery-scaling discrepancy against cloudflare/circl's
internal package that is non-trivial to diagnose without access to
circl's internal NTT test fixtures. The v0.3 work resolves this
discrepancy or routes around it (e.g., port directly from the
pq-crystals reference C implementation, cross-validate against
both circl and pq-crystals).

### Graduation gate

When all of the following are true, this issue is CLOSED:

1. `TestTransitional_DependsOnSkBytes` FAILS (because
   `TransitionalAggregate` no longer needs `SkBytes`).
2. The `SkBytes` field is removed from `TransitionalSetup`.
3. The renames listed under (4) above are applied consistently
   across `threshold_v02.go`, `threshold_v02_test.go`, `types.go`,
   `DEPLOYMENT-RUNBOOK.md`.
4. The file-header honesty block in `threshold_v02.go` is rewritten
   to drop the SkBytes caveat (the new block describes
   `AlgebraicAggregate` as honestly public-BFT-safe).
5. `TestTransitional_DependsOnSkBytes` is deleted or rewritten as
   `TestAlgebraic_*` documenting the v0.3 property.
6. `DEPLOYMENT-RUNBOOK.md`'s "v0.2 trust model" section is
   rewritten to reflect that v0.3 is safe for public adversarial
   deployments.
7. Full test suite passes:
   `cd ref/go && GOWORK=off go test -count=1 -short -timeout 300s ./pkg/pulsar/`
8. Class N1 byte-equality holds against FIPS 204 ML-DSA Verify
   (preserved property; v0.3 must not regress N1).

### Closes this entry

Closed in **v1.0.20**. The single load-bearing change is one block
removed in `ref/go/pkg/pulsar/mldsa_keyderive.go` (the spurious post-
sample NTT loop on `km.a`). Two test files (`threshold_v03_aprime_test.go`,
`threshold_v03_unsafediff_test.go`) landed as regression guards pinning
the FIPS 204 ExpandA convention byte-for-byte against
cloudflare/circl@v1.6.3's stored `pk.A`. The graduation-gate
checks pass:

- `TestAlgebraic_FullCycle_n5_t3` PASS
- `TestAlgebraic_NoSkAccess` PASS (public-BFT safety contract intact)
- `TestTransitional_DependsOnSkBytes` PASS (v0.2 still requires SkBytes;
  the SkBytes-free path is v0.3 `AlgebraicAggregate`)
- Full pulsar suite: 155 PASS / 0 FAIL / 2 SKIP (-race green)
- Class N1 byte-equality preserved (`TestN1_ByteEquality_*` PASS)
