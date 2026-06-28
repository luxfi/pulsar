# Pulsar `pkg/pulsar` — version & track ledger (claim hygiene)

> One file, one truth about what each version of the committee threshold
> ML-DSA path IS and is NOT. Read alongside the repo-root `PROOF-CLAIMS.md`
> (the gate-read assurance vocabulary) and `BLOCKERS.md` (open findings).

## Signing-path versions

| Version | Status | What it is | Why it is gone / current |
|---|---|---|---|
| **v0.3 — algebraic broadcast** | **REMOVED** | The `AlgebraicAggregate` path broadcast per-party `c·s2` / `c·t0` residual shares and reconstructed the leaking `MakeHint` residual at the aggregator. | Closed as **PULSAR-V13-HINT-LEAK** — broadcasting those shares leaks the long-term key. Ripped out (commit `b185533`); **no backward-compatible re-entry**. |
| **v0.4 — BCC/CSCP no-reconstruct** | **CURRENT (production sign path)** | Boundary-Cleared Carry-elimination (BCC/CEF) + Comparison-Secure-Comparison-Protocol (CSCP). Each validator holds exactly one poly-vector Shamir share of `s1`; signing aggregates only masked `z`-partials; the hint is recovered from the **public** `w' = A·z − c·t1·2^d` and `w1`. No process forms `s1`, the seed, `sk`, `c·s2`, `c·t0`, `r0`, or full `w`. Output verifies under unmodified FIPS 204 ML-DSA (`mldsa{65,87}.Verify`). | Base `main` @ `v0.4.0` (commit `b652893`). The sole production path. |
| **v0.4.x — `harden/malicious-security`** | **THIS BRANCH (in review, NOT merged)** | Hardens v0.4 from semi-honest/no-leak toward **malicious** security: nonce single-use / anti-replay ledger (closes the nonce-reuse key-recovery vector), identifiable-abort plumbing (duplicate-PartyID rejection, invalid-proof blame attribution, per-party commitment binding), GATE-2 hardened to call-graph reachability, CI invariant against `legacy_trusted_dealer` in the prod build. | Branch off `origin/main`; **a RED agent re-verifies before any merge.** See "Malicious-hardening status" below for implemented-vs-residual. |

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
- **Nonce single-use / anti-replay** (`nonce_ledger.go`) — per-signer ledger keyed on
  the nonce commitment `(committeeID ‖ w1)`; `Round2` reserves before emitting the
  secret `z`-partial; reuse (even relabeled under a new `nonceID`) is rejected
  fail-closed. GATE A (`TestRED_NonceReuse_RecoversS1`) demonstrates the
  key-recovery math is real **and** that the guard blocks obtaining the second
  partial.
- **Duplicate-PartyID rejection** + **invalid/malformed-proof blame attribution** in
  `AggregateBCC` — a deviating partial is attributed to its `PartyID` (structured
  `AbortEvidence`), not silently dropped. GATE B covers these.
- **Per-party DKG/nonce commitment binding** — `AggregateBCC` populates and verifies
  the commitments the sigma proof is bound to (non-transferability).
- **GATE-2 → reachability** (`gate2_reachability_test.go`) — stdlib AST call-graph;
  the reconstruct primitives (`KeyFromSeed`, `deriveKeyMaterial`, `bccSign`,
  `shamirReconstruct*`, `LargeCombine`) must be **unreachable** from the committee
  sign entrypoints. GATE C catches the `deriveKeyMaterial`+`bccSign` bypass.
- **CI invariant** — the production (default-tag) build never carries
  `legacy_trusted_dealer`.

**Designed + scaffolded + FLAGGED (gated residuals — NOT done):**
- **Sound valid-sigma wrong-`z` blame** needs a hiding lattice commitment
  (BDLOP/Ajtai) to the dealt share + an extended linear-sigma proof of opening.
  A homomorphic `A·s1_i` / `A·y_i` commitment is **rejected** because it reopens
  PULSAR-V13-W-LEAK / HINT-LEAK. Until then, a valid-sigma wrong-`z` is a
  **liveness fault (unattributed abort), never a forgery or leak**.
- **Malicious-secure CSCP**, **networked MPC transcript**, **authenticated /
  signed protocol channels**, **leak-free NonceMPC**, **persistent nonce ledger**
  (crash-restart safety), **last-mover-bias controls**. See `BLOCKERS.md`
  Residual A and the branch report.

## The honest one-line scope (canonical)

> Dealerless committee key/nonce gen **(target track; trusted-dealer bootstrap is
> test-only, leak-free NonceMPC is a residual)** + CEF/CSCP **no-reconstruct
> signing** + **standard-ML-DSA-verifier output**, **semi-honest / no-leak
> today**; **malicious-CSCP + networked-MPC are gated residuals**.

**NEVER claimed:** FIPS/NIST-certified threshold ML-DSA · fully-malicious-secure-proven · global-1000-validator DKG.
