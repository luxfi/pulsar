# BLOCKERS — luxfi/pulsar

Issue tracker for open work that gates a deployment claim or a
documentation claim. One entry per issue. Status is `OPEN` until the
graduation gate (the bottom of each entry) is met; then move to
`CLOSED` and link the commit / tag that closed it.

## PULSAR-V03-1 — v0.3 algebraic sign: remove SkBytes dependency from TransitionalAggregate

**Status**: OPEN
**Opened**: v1.0.14
**Closes**: v0.3 ship
**Owner**: cryptographer
**Related test**: `ref/go/pkg/pulsar/threshold_v02_test.go::TestTransitional_DependsOnSkBytes`

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

Tag: `pulsar v0.3.x` ship. Update this entry with the closing
commit SHA, tag, and date when graduated.
