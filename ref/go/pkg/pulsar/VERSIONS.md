# Pulsar `pkg/pulsar` — version & track ledger (claim hygiene)

> One file, one truth about what each version of the committee threshold
> ML-DSA path IS and is NOT. Read alongside the repo-root `PROOF-CLAIMS.md`
> (the gate-read assurance vocabulary) and `BLOCKERS.md` (open findings).

## Signing-path versions

| Version | Status | What it is | Why it is gone / current |
|---|---|---|---|
| **v0.3 — algebraic broadcast** | **REMOVED** | The `AlgebraicAggregate` path broadcast per-party `c·s2` / `c·t0` residual shares and reconstructed the leaking `MakeHint` residual at the aggregator. | Closed as **PULSAR-V13-HINT-LEAK** — broadcasting those shares leaks the long-term key. Ripped out (commit `b185533`); **no backward-compatible re-entry**. |
| **v0.4 — BCC/CSCP no-reconstruct** | **CURRENT (production sign path)** | Boundary-Cleared Carry-elimination (BCC/CEF) + Comparison-Secure-Comparison-Protocol (CSCP). Each validator holds exactly one poly-vector Shamir share of `s1`; signing aggregates only masked `z`-partials; the hint is recovered from the **public** `w' = A·z − c·t1·2^d` and `w1`. No process forms `s1`, the seed, `sk`, `c·s2`, `c·t0`, `r0`, or full `w`. Output verifies under unmodified FIPS 204 ML-DSA (`mldsa{65,87}.Verify`). | Base `main` @ `v0.4.0` (commit `b652893`). The sole production path. |
| **v0.4.x — `harden/malicious-security`** | **THIS BRANCH (in review, NOT merged)** | Hardens v0.4 from semi-honest/no-leak toward **malicious** security: nonce single-use **safe by construction** (per-share registry, default-path enforced; `w1`-only dedup closes cross-committee reuse), **authenticated-PartyID blame** (forged victim-slot partials dropped before attribution; blame gated on identity-signature validity — an attacker cannot frame/exclude an honest victim), identifiable-abort plumbing (duplicate-PartyID rejection, invalid/malformed blame, per-party commitment binding), GATE-2 reachability **+ indirection lint**, CI invariant against `legacy_trusted_dealer` in the prod build. | Branch off `origin/main`; **a RED agent re-verifies before any merge.** See "Malicious-hardening status" below for implemented-vs-residual. |

## Keygen / nonce-gen track (separate from the sign path)

The no-reconstruct property above is a **SIGN-time** property. Key and nonce
*generation* are a distinct axis with its own honest scope:

| Track | Status | Notes |
|---|---|---|
| **Trusted-dealer bootstrap** (`DealAlgShares`) | **TEST/BOOTSTRAP ONLY — quarantined** | Expands the seed once and Shamir-shares `s1`, then wipes. Confined to `bootstrap_dealer_test.go` (a `_test.go` file → **uncompilable into any production binary**). It seeds the no-reconstruct SIGNING tests; it is **not** a production keygen. |
| **Legacy GF(q) seed-share committee** (`large_*.go`, `largeshamir.go`) | **QUARANTINED behind `//go:build legacy_trusted_dealer`** | `LargeCombine` reconstructs the master seed at sign time (the H-1 footgun). **Absent from the default build.** Item-4 CI invariant asserts the production build never ships this tag. |
| **Pedersen-VSS dealerless exploration** | **SEPARATE BRANCH** `feat/v02-pedersen-vss-no-reconstruct` | The dealerless-keygen research track. Not on `main`; not part of the v0.4 production claim. |
| **Dealerless byte-FIPS-204 KEY DKG** | **PROVEN UNREACHABLE (parameter obstruction)** | `naive_additive_seta_obstruction.go` → `ErrDealerlessByteFIPSUnreachable`: a dealerless sum of `S_η` shares has `‖·‖∞ ≤ N·η > η`, breaking BCC and FIPS-204 byte equality. Permissionless safety is carried by the dealerless **Corona** leg of the Quasar AND-mode cert, not by this keygen. |
| **NonceMPC (leak-free distributed nonce)** | **STAND-IN today** (`DealNonceMPCDebug`) | The production sign path consumes a `NonceCert` (only `w1` public). The stand-in dealer-models the nonce and exposes `DebugW` to the **test harness only** (never on the wire) — the **PULSAR-V13-W-LEAK** residual. The leak-free distributed nonce (HighBits-over-shares MPC / exact-ℓ∞ boundary ZK) is fail-closed behind the same wall as `rangeproof.go`. |

## Malicious-hardening status (this branch — honest implemented-vs-residual)

**Implemented, with a passing gate:**
- **Nonce single-use / anti-replay — SAFE BY CONSTRUCTION** (`nonce_ledger.go`). The
  single-use store is resolved from a **process-global registry keyed by SHARE
  IDENTITY** (`shareIdentityKey`), so EVERY signer instance over the same key-share
  shares ONE ledger by DEFAULT — there is **no opt-in and no per-instance
  empty-ledger fail-open**. The dedup key is the nonce commitment **`w1` ALONE**
  (committee-independent), so reuse is refused even when relabeled under a new
  `nonceID` AND when the same joint nonce is presented across two committees that
  share a victim. `Round2` reserves before emitting the secret `z`-partial.
  - GATE A `TestRED_NonceReuse_RecoversS1` (key-recovery math is real + injected-
    ledger guard), `TestRED_PoC_DefaultLedger_NonceReuse_Refused` (the **DEFAULT**
    API — fresh signer per message, **no** `SetNonceLedger` — refuses the second
    partial + relabel), `TestRED_LOW_CrossCommittee_SameNonce_Deduped` (same nonce
    across committees deduped).
- **Authenticated PartyID → blame gated on signature validity** (RED MEDIUM,
  `distributed_bcc.go` / `protocol_auth.go`). Each `Partial` carries `Author +
  AuthSig` (the producer's identity-key signature over slot ‖ content);
  `AggregateBCCWithBlame` AUTHENTICATES each partial (valid signature **and**
  `Author == quorum[PartyID]`) BEFORE attribution, dropping forged/wrong-slot
  partials with **no blame against the slot's honest owner**, before the
  first-per-PartyID/duplicate logic. Blame is **never** emitted off a raw
  unauthenticated PartyID (with no verifier wired, no blame is produced at all).
  - GATE B (duplicate / invalid-proof / malformed all attributed to the SIGNING
    deviator) + `TestRED_PoC_MEDIUM_CannotFrameOrExcludeHonestVictim` (a forged
    victim-slot partial cannot blame or exclude the victim; the verifier is shown
    load-bearing).
- **Per-party DKG/nonce commitment binding** — `AggregateBCC` populates and verifies
  the commitments the sigma proof is bound to (non-transferability).
- **GATE-2 → reachability + indirection lint** (`gate2_reachability_test.go`) — a
  stdlib AST name call-graph proves the reconstruct primitives (`KeyFromSeed`,
  `deriveKeyMaterial`, `bccSign`, `shamirReconstruct*`, `LargeCombine`) are
  **unreachable from the committee sign entrypoints via direct calls** (GATE C
  catches a `deriveKeyMaterial`+`bccSign` bypass), **paired** with a companion lint
  that forbids taking any banned primitive as a non-call **value** or aliasing it
  via `//go:linkname`. The graph is complete for DIRECT calls; the lint closes
  function-value / closure / linkname indirection — the pair (not either half) is
  complete for the banned set.
- **CI invariant** — the production (default-tag) build never carries
  `legacy_trusted_dealer`.

**Designed + scaffolded + FLAGGED (gated residuals — NOT done):**
- **Sound valid-sigma wrong-`z` blame** needs a hiding lattice commitment
  (BDLOP/Ajtai) to the dealt share + an extended linear-sigma proof of opening.
  A homomorphic `A·s1_i` / `A·y_i` commitment is **rejected** because it reopens
  PULSAR-V13-W-LEAK / HINT-LEAK. Until then, a valid-sigma wrong-`z` is a
  **liveness fault (unattributed abort), never a forgery or leak**.
- **Persistent nonce ledger (crash-restart safety).** The in-process default is
  safe NOW (registry, above); the persistent per-share ledger that survives a
  restart is the residual — install one at startup via `SetNonceLedger` (writes the
  same per-share registry slot, first-writer-wins).
- **Networked / authenticated transport.** The partial→producer crypto binding is
  in place (above); the networked channel that authenticates message DELIVERY is
  owned by the consensus layer and remains a flagged residual.
- **Malicious-secure CSCP**, **networked MPC transcript**, **leak-free NonceMPC**,
  **last-mover-bias controls**. See `BLOCKERS.md` Residual A and the branch report.

## The honest one-line scope (canonical)

> Dealerless committee key/nonce gen **(target track; trusted-dealer bootstrap is
> test-only, leak-free NonceMPC is a residual)** + CEF/CSCP **no-reconstruct
> signing** + **standard-ML-DSA-verifier output**, **semi-honest / no-leak
> today**; **malicious-CSCP + networked-MPC are gated residuals**.

**NEVER claimed:** FIPS/NIST-certified threshold ML-DSA · fully-malicious-secure-proven · global-1000-validator DKG.
