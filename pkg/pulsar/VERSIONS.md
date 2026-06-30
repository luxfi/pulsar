# Pulsar `pkg/pulsar` — version & track ledger (claim hygiene)

> One file, one truth about what each version of the committee threshold
> ML-DSA path IS and is NOT. Read alongside the repo-root `PROOF-CLAIMS.md`
> (the gate-read assurance vocabulary) and `BLOCKERS.md` (open findings).

## Signing-path versions

| Version | Status | What it is | Why it is gone / current |
|---|---|---|---|
| **v0.3 — algebraic broadcast** | **REMOVED** | The `AlgebraicAggregate` path broadcast per-party `c·s2` / `c·t0` residual shares and reconstructed the leaking `MakeHint` residual at the aggregator. | Closed as **PULSAR-V13-HINT-LEAK** — broadcasting those shares leaks the long-term key. Ripped out (commit `b185533`); **no backward-compatible re-entry**. |
| **v0.4 — BCC/CSCP no-reconstruct** | **CURRENT (production sign path)** | Boundary-Cleared Carry-elimination (BCC/CEF) + Comparison-Secure-Comparison-Protocol (CSCP). Each validator holds exactly one poly-vector Shamir share of `s1`; signing aggregates only masked `z`-partials; the hint is recovered from the **public** `w' = A·z − c·t1·2^d` and `w1`. No process forms `s1`, the seed, `sk`, `c·s2`, `c·t0`, `r0`, or full `w`. Output verifies under unmodified FIPS 204 ML-DSA (`mldsa{65,87}.Verify`). | Base `main` @ `v0.4.0` (commit `b652893`). The sole production path. |
| **v0.5.0 — malicious-hardening** | **MERGED (`main` @ `53ed1c2`, RED-verified 0 crit/high)** | Hardens v0.4 from semi-honest/no-leak toward **malicious** security: nonce single-use **safe by construction** (per-share registry, default-path enforced; `w1`-only dedup closes cross-committee reuse), **authenticated-PartyID blame** (forged victim-slot partials dropped before attribution; blame gated on identity-signature validity — an attacker cannot frame/exclude an honest victim), identifiable-abort plumbing (duplicate-PartyID rejection, invalid/malformed blame, per-party commitment binding), GATE-2 reachability **+ indirection lint**, CI invariant sealing the prod build against the reconstruct-at-sign quarantine. | Merged off `harden/malicious-security`. Still **malicious-HARDENED, not fully-malicious-secure-PROVEN** (see scope). |
| **v0.5.1 — post-merge hardening** | **MERGED (`main`)** | Closes 3 RED post-merge nits (all liveness/availability, no forgery/leak): **(1) origin-auth SAFE-BY-DEFAULT** — `AggregateBCC{,WithBlame}` now REFUSE FAIL-CLOSED (`ErrOriginAuthRequired`) when no verifier is wired, instead of silently aggregating unauthenticated partials; the unauthenticated path is reachable ONLY via the explicit `UnauthenticatedAggregation` opt-out (trusted-channel/test). **(2) epoch-pruned nonce ledger** — `(*InMemoryNonceLedger).PruneBefore` + registry sweep `PruneShareLedgers` bound the single-use map to a sliding retained-epoch window, never reopening reuse inside the live window. **(3) CI no-asm/no-cgo assertion** — `TestCI_NoAssemblyOrCgoFiles` seals GATE-C's blind spot (the AST gates cannot model `.s`/`.c`/cgo) by proving the package is pure Go. | Same honest scope as v0.5.0 — no new "proven" claim. |
| **v0.6.0 — dealerless RSS keygen** | **MERGED (`main`) — the dealer is dead at keygen** | Mithril short replicated-secret-sharing committee keygen (`mithril_rss.go`); see the keygen track below. Completes the dealerless story: SIGNING no-reconstruct (v0.4/v0.5) + KEYGEN dealerless (RSS). | Standard-verifier-compatible; distribution-equivalence is a labeled residual. |
| **HYPERBALL — Mithril 3-round no-reconstruct signer** | **MERGED (`main`, gates 5/6)** | `mithril_rss_hyperball.go` `SignHyperball`: 3-round no-reconstruct threshold signer over the RSS key — `z_j = y_j + c·s1_(j)`, no party/coordinator forms `s1`/`s2`/`y`/`w0`/`sk`; the secret mask `y` is never serialised onto the wire. Verifies under stock circl (`TestHyperballStockCirclVerify`); structural no-reconstruct proven by AST (`TestHyperballNoReconstructStructural`); fail-closed (GATE-6). | The Mithril-native signer complementing the RSS keygen; same standard-verifier boundary. |
| **v0.6.1 / v0.6.2 — mlwe de-dup** | **MERGED (`main`, byte-preserving)** | Pulsar routed transcript→`mlwe/transcript`, Shamir→`mlwe/share`, samplers→`mlwe/sample/shake`, ring→`mlwe/ring/mldsa` (deleted duplicate zeta tables + samplers). Golden KAT vectors UNCHANGED; one-and-one-way DRY with Corona. | No wire/modulus/vector change; signing math untouched. |
| **v0.6.3 — RSS overflow fix** | **CURRENT (`main`)** | `accumulateSubset` reduces mod q per-subset in RSS keygen — fixes the uint32 overflow at `C(N,M) ≥ ⌊2³²/q⌋ = 512` that produced unsignable wall keys for large committees (n=16,t=14, C=560). modQ is an additive homomorphism → bit-identical for small committees (n≤8). | Single-file keygen-correctness fix; golden KATs unchanged. |

## Keygen / nonce-gen track (separate from the sign path)

The no-reconstruct property above is a **SIGN-time** property. **As of v0.6.0,
committee KEY generation is ALSO dealerless** (Mithril RSS, below) — so the
trusted dealer is dead at both ends. Nonce *generation* remains a distinct axis
(leak-free NonceMPC is still a residual):

| Track | Status | Notes |
|---|---|---|
| **Dealerless RSS committee KEYGEN (Mithril)** | **CURRENT (`main` @ v0.6.0+) — the dealer is dead at keygen** | `mithril_rss.go` `MithrilRSSKeygen`: dealerless committee key generation via Mithril short replicated secret sharing (no dealer, no centralized reconstruction). Each committee's RSS-generated group key signs under **stock unmodified** `mldsa65.Verify` — gold-proof verified at (t=8,n=8), (t=16,n=16), and all small committees `T=2..N, N=2..6` via real per-party rejection sampling (`TestMithrilRSSStockCirclVerify`, `TestMithrilRSS_LargeN_StockCircl`). v0.6.3 `accumulateSubset` per-subset mod-q reduction unblocks large committees (n=16,t=14, C(16,3)=560 — the uint32 overflow at C≥512). **Scope:** standard-verifier-compatible (PROVEN). Full FIPS-204 KeyGen-distribution-equivalence (simulation/hiding-vs-<t/abort-bias) remains a labeled residual (R1). |
| **NAIVE additive S_η dealerless keygen** | **UNSOUND (parameter obstruction — naive construction ONLY)** | `naive_additive_seta_obstruction.go` → `ErrDealerlessByteFIPSUnreachable`: a NAIVE Pedersen/Gennaro sum of `S_η` shares has `‖·‖∞ ≤ N·η > η`, breaking BCC and FIPS-204 byte equality. This is the naive lift ONLY — **NOT a class impossibility**: Mithril short-replicated-shares (above) is the published escape and is now the production dealerless keygen. The old `feat/v02-pedersen-vss-no-reconstruct` branch was the exploration; RSS superseded it. |
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
  - **EPOCH-PRUNED (v0.5.1)** so the in-memory map cannot grow unbounded over a
    validator's lifetime: `(*InMemoryNonceLedger).PruneBefore(minEpoch)` drops
    reservations older than `minEpoch`, and `PruneShareLedgers(minEpoch)` sweeps
    the whole per-share registry. Pruning NEVER reopens reuse inside the retained
    window `[minEpoch, ∞)` (caller picks `minEpoch ≥ finality/reorg depth`).
  - GATE A `TestRED_NonceReuse_RecoversS1` (key-recovery math is real + injected-
    ledger guard), `TestRED_PoC_DefaultLedger_NonceReuse_Refused` (the **DEFAULT**
    API — fresh signer per message, **no** `SetNonceLedger` — refuses the second
    partial + relabel), `TestRED_LOW_CrossCommittee_SameNonce_Deduped` (same nonce
    across committees deduped), `TestNonceLedger_EpochPruneFreesOldRetainsWindow`
    + `TestNonceLedger_PruneShareLedgers_SweepsRegistry` (pruning frees old entries;
    retained-window reuse still `ErrNonceReused`).
- **Authenticated PartyID → blame gated on signature validity** (RED MEDIUM,
  `distributed_bcc.go` / `protocol_auth.go`). Each `Partial` carries `Author +
  AuthSig` (the producer's identity-key signature over slot ‖ content);
  `AggregateBCCWithBlame` AUTHENTICATES each partial (valid signature **and**
  `Author == quorum[PartyID]`) BEFORE attribution, dropping forged/wrong-slot
  partials with **no blame against the slot's honest owner**, before the
  first-per-PartyID/duplicate logic. Blame is **never** emitted off a raw
  unauthenticated PartyID.
  - **SAFE BY DEFAULT (v0.5.1):** a **nil** verifier is now REFUSED FAIL-CLOSED
    (`ErrOriginAuthRequired`) — a caller that FORGOT to wire the verifier can no
    longer silently revert to the exclude-honest-victim footgun (matches the nonce
    ledger's no-fail-open posture). The unauthenticated path (no origin check, no
    blame) is reachable ONLY via the EXPLICIT `UnauthenticatedAggregation` opt-out
    (trusted-channel / test); `DistributedBCCSigner.FinalizeWithBlame` forwards
    `idVerify`, so a signer with no `SetIdentity` fails closed too.
  - GATE B (duplicate / invalid-proof / malformed all attributed to the SIGNING
    deviator) + `TestRED_PoC_MEDIUM_CannotFrameOrExcludeHonestVictim` (a forged
    victim-slot partial cannot blame or exclude the victim; the verifier is shown
    load-bearing) + `TestGATE_OriginAuth_FreeFn_DefaultRefuses` /
    `TestGATE_OriginAuth_Signer_DefaultRefuses` (the default, no-verifier path
    refuses; opt-out and a real verifier both aggregate to a FIPS-valid signature).
- **Per-party DKG/nonce commitment binding** — `AggregateBCC` populates and verifies
  the commitments the sigma proof is bound to (non-transferability).
- **GATE-2 → reachability + indirection lint** (`gate2_reachability_test.go`) — a
  stdlib AST name call-graph proves the reconstruct primitives (`KeyFromSeed`,
  `deriveKeyMaterial`, `bccSign`, `shamirReconstruct*`) are
  **unreachable from the committee sign entrypoints via direct calls** (GATE C
  catches a `deriveKeyMaterial`+`bccSign` bypass), **paired** with a companion lint
  that forbids taking any banned primitive as a non-call **value** or aliasing it
  via `//go:linkname`. The graph is complete for DIRECT calls; the lint closes
  function-value / closure / linkname indirection — the pair (not either half) is
  complete for the banned set.
- **CI invariant** — the reconstruct-at-sign combiner, the trusted-dealer keygen,
  and their quarantine tag are DELETED, and every `.go` file is scanned so they can
  never reappear (`TestCI_ReconstructAndDealerRipIsComplete`),
  and (v0.5.1) the package is **pure Go** — no `.s` / `.c` / cgo unit
  (`TestCI_NoAssemblyOrCgoFiles`), sealing GATE-C's blind spot: the AST
  reachability + indirection gates cannot model assembly/C, so the no-reconstruct
  soundness claim requires (and now asserts) there is none.

**Designed + scaffolded + FLAGGED (gated residuals — NOT done):**
- **Sound valid-sigma wrong-`z` blame** needs a hiding lattice commitment
  (BDLOP/Ajtai) to the dealt share + an extended linear-sigma proof of opening.
  A homomorphic `A·s1_i` / `A·y_i` commitment is **rejected** because it reopens
  PULSAR-V13-W-LEAK / HINT-LEAK. Until then, a valid-sigma wrong-`z` is a
  **liveness fault (unattributed abort), never a forgery or leak**.
- **Persistent nonce ledger (crash-restart safety).** The in-process default is
  safe NOW (registry, above) and its lifetime memory is now BOUNDED by epoch
  pruning (`PruneShareLedgers`, v0.5.1); the persistent per-share ledger that
  survives a **restart** is the remaining residual — install one at startup via
  `SetNonceLedger` (writes the same per-share registry slot, first-writer-wins).
  The pruning retained-window MUST stay ≥ the finality/reorg depth.
- **Networked / authenticated transport.** The partial→producer crypto binding is
  in place (above); the networked channel that authenticates message DELIVERY is
  owned by the consensus layer and remains a flagged residual.
- **Malicious-secure CSCP**, **networked MPC transcript**, **leak-free NonceMPC**,
  **last-mover-bias controls**. See `BLOCKERS.md` Residual A and the branch report.

## The honest one-line scope (canonical)

> Dealerless committee KEYGEN **(DONE — Mithril RSS; leak-free NonceMPC is the
> remaining gen-side residual)** + CEF/CSCP **no-reconstruct signing** +
> **standard-ML-DSA-verifier output**, **semi-honest / no-leak today**;
> **malicious-CSCP + networked-MPC are gated residuals**.

**NEVER claimed:** FIPS/NIST-certified threshold ML-DSA · fully-malicious-secure-proven · global-1000-validator DKG.
