# PULSAR — Dealerless Committee-Threshold ML-DSA Certificate Layer

> **Status.** Architecture specification, current to **v0.6.3** (`git log`
> → `0650729`, `origin/main`). This document defines the *certificate layer* of
> Pulsar: how **dealerless** committee-threshold ML-DSA is organized into epochs,
> committees, signing sessions, and on-chain-verifiable certificates so that it
> scales to a permissionless validator set of N > 1000 by **sampling many small
> committees and accumulating confidence by repetition** (Avalanche-native), not
> by pushing one giant Shamir/FROST sharing across all N. It is the
> consensus-integration companion to the algorithm-level NIST-MPTC submission
> spec (`spec/pulsar.tex`, `spec/parameters.tex`, `spec/system-model.tex`) and
> the proofs under `~/work/lux/proofs/pulsar/`.
>
> **SPEC + grounded reality.** Sections labelled *implemented today* cite the
> real reference implementation under `ref/go/pkg/pulsar/` at v0.6.3; sections
> labelled *consensus target* are the integration surface to build. No code is
> changed by this document.

---

## 0. Claim discipline (read first)

This layer makes **two distinct claims that must never be conflated**. Most
flawed "threshold post-quantum" marketing collapses them; Pulsar keeps them
apart on purpose.

- **Claim (A) — FIPS-204 verification *compatibility* — PROVEN.** The verifier
  boundary is **standard, unmodified** FIPS-204 ML-DSA verification:

  ```
  Verify_MLDSA(GroupPK, digest, sig) ∈ {accept, reject}
  ```

  The threshold-produced `(c̃, z, h)` is byte-for-byte a FIPS-204 signature; a
  stock verifier (`cloudflare/circl` `mldsa65.Verify` / `mldsa87.Verify`,
  BoringSSL/AWS-LC FIPS ML-DSA, OpenSSL 3.x PQ provider) accepts it with **no
  Pulsar code in the verify path**. This is proven today for:
  - the no-reconstruct BCC/CEF signer over a single group key
    (`ref/go/pkg/pulsar/bcc_sign_test.go:86`, `TestBCCSignRoundTripVerifiesCIRCL`);
  - the **dealerless RSS** group key, signed and verified under stock circl for
    every viable committee N ≤ 6 and the T = N committees n=8,t=8 / n=16,t=16
    (`mithril_rss_test.go:38`, `mithril_rss_n8_test.go:16`);
  - the **no-reconstruct hyperball** signer over the dealerless RSS key
    (`mithril_rss_hyperball_test.go:41`, `TestHyperballStockCirclVerify`).

- **Claim (B) — DKG/threshold *construction* soundness — Lux-authored, SCOPED.**
  The dealerless key generation (RSS / Mithril) and the threshold signing
  protocols (BCC/CEF/CSCP + hyperball) are a **Lux-authored construction**. Its
  security is argued by reduction to ML-DSA EUF-CMA under Module-LWE /
  Module-SIS, *plus* the protocol-level privacy/abort properties argued in
  `~/work/lux/proofs/pulsar/`. This is **our** theorem, not NIST's, and parts of
  it are **scoped residuals** (§18) — labelled, fail-closed, never silently
  weakened.

**What we never say.** There is no such thing as "FIPS-certified threshold
ML-DSA" or "NIST-certified threshold ML-DSA." FIPS 204 standardizes
*single-party* ML-DSA KeyGen/Sign/Verify. We never claim
fully-malicious-secure-*proven* (mechanized) or a global-1000-validator DKG.
Conformance language is always one of: "verifies under unmodified FIPS-204"
(Claim A), or "Lux-authored threshold construction, reduction in
`proofs/pulsar/`" (Claim B).

**The honest one-line scope (canonical).** *Dealerless committee key generation
(RSS / Mithril) + no-reconstruct signing (BCC/CSCP, and the Mithril hyperball
3-round signer) + standard-FIPS-204-verifier output, malicious-hardened; the
full FIPS-204 KeyGen-distribution-equivalence proof and the malicious-secure
CSCP/identifiable-abort layer are labelled residuals.*

---

## 1. Why a committee certificate layer, and why not Shamir/FROST end-to-end

ML-DSA is not Schnorr. Four features break Schnorr-style threshold composition:

1. **Small secrets.** `s1, s2` are sampled uniformly from
   `S_η = {p ∈ R_q : ‖p‖∞ ≤ η}` (η = 4 for ML-DSA-65, η = 2 for ML-DSA-87). The
   *entire* parameter set is calibrated to this bound.
2. **Rejection sampling.** Signing loops until `‖z‖∞ < γ1 − β` and
   `‖r0‖∞ < γ2 − β`; the accepted distribution is not a simple linear image of
   the inputs.
3. **Decompose / rounding.** `w1 = HighBits(A·y)` and `r0 = LowBits(w − c·s2)`
   are non-linear; there is no homomorphic commitment to `w1` over additive
   nonce shares — this is precisely why naive FROST-style additive-nonce
   threshold ML-DSA is impossible.
4. **Hints.** The signature carries `h = MakeHint(...)`; recovering it from
   shares without leaking the key residual `c·t0 − c·s2` is the delicate part.

Consequence for the *key* layer — the naive-additive obstruction:

- **Naive Lagrange/additive DKG blows the norm.** A dealerless joint secret
  formed as a *sum / Lagrange combination* of N ≥ 2 independent `S_η`
  contributions has `‖s2_joint‖∞ ≤ N·η`, hence `‖c·s2_joint‖∞ ≤ N·β`. This
  violates both the BCC boundary-clearance hypothesis (`‖c·s2‖∞ ≤ β`) and
  ML-DSA's `S_η`-calibrated EUF-CMA. This **naive-additive obstruction is
  computed, not asserted**, in
  `ref/go/pkg/pulsar/naive_additive_seta_obstruction.go:196`
  (`assessDealerlessFIPS`: `JointS2Linf = N·η`, `JointCS2Linf = N·β`) and is the
  reason the *naive* dealerless entry point fails closed
  (`ErrDealerlessByteFIPSUnreachable`, `naive_additive_seta_obstruction.go:152`).
  **It is the naive *lift* only — it does *not* prove a general impossibility**;
  the file's own header (`:84`–`:107`) lists the escape: a sharing whose
  reconstruction stays in `S_η` *by construction*.

**That escape is now built (v0.6.0+): Mithril short Replicated Secret Sharing
(RSS).** The key is the *plain sum of `C(N, N−T+1)` fresh short `χ_η` subset
secrets*, so `‖s2‖∞ ≤ C·η` stays genuinely small (§4). RSS does **not** form an
N-way additive blow-up — it sidesteps the obstruction the obstruction file
itself names. The dealer is dead **at keygen too**, not just at signing.

So Pulsar does **not** push one global Shamir/FROST sharing across all N
validators, and it does **not** rely on a trusted dealer. Instead it **scales by
sampling many small dealerless committees** and treats the *certificate* (an
epoch/committee-bound, stock-FIPS-204-verifiable ML-DSA signature) as the unit
of composition (§5, §12).

---

## 2. What exists today (grounded in `ref/go/pkg/pulsar/` @ v0.6.3)

| Concern | Implemented today (file:line) |
|---|---|
| (A) Threshold output verifies under **unmodified FIPS-204** | **DONE** — `bcc_sign_test.go:86` checks a no-leak BCC/CEF signature byte-for-byte under independent `circl` `mldsa65/87.Verify` (+ tamper / wrong-msg / wrong-ctx negatives). |
| **Dealerless** committee keygen | **DONE (RSS / Mithril)** — `mithril_rss.go:133` `MithrilRSSKeygen`: no trusted dealer; each subset's short secret is sampled by that subset's leader and replicated; no party holds the whole `(s1,s2)`. Stock-circl-verifiable: `mithril_rss_test.go:38` (all 15 committees N ≤ 6), `mithril_rss_n8_test.go:16` (T=N at n=8, n=16). |
| Large-committee keygen (arithmetic) | **DONE (v0.6.3)** — per-subset reduction `accumulateSubset` (`mithril_rss.go:122`) fixes a uint32 overflow that wrapped the key once `C(N,N−T+1) ≥ 512`; unblocks the owner-default large committees (e.g. n=16,t=14, `C(16,3)=560`). |
| No-reconstruct online signing (single group key) | **DONE** — `distributed_bcc.go:645` partial `z_i = λ_i·y_i + c·λ_i·s1_i`; `AggregateBCCWithBlame` (`:875`) sums to `z = ȳ + c·s1` **without ever forming `s1`** (let alone the seed); hint from public `w' = A·z − c·t1·2^d`. |
| **No-reconstruct signing over the dealerless RSS key** | **DONE (hyperball, gates 5/6)** — `mithril_rss_hyperball.go:780` `SignHyperball`: the Mithril 3-round protocol; each party emits only `z_j = y_j + c·s1_(j)`; **no party or coordinator forms** the full `s1`, any `s2`, `t0`, the mask `y`, the commitment `w`, `w0`, or any `sk`. |
| Malicious hardening | **DONE (v0.5)** — nonce single-use safe-by-construction (`nonce_ledger.go`), authenticated-PartyID blame / identifiable abort (`blame.go`, `protocol_auth.go`), origin-auth safe-by-default (`ErrOriginAuthRequired`, `distributed_bcc.go:813`), GATE-2 call-graph reachability (`gate2_reachability_test.go`). |
| Offline preprocessing / ticket factory (TALUS) | **BUILT (semi-honest)** — TALUS `talus.go`, CEF `talus_cef.go`, CSCP secure-comparison `talus_cscp.go` (W-LEAK closed semi-honest, simulation-proven). |
| Shared lattice base | **DONE (v0.6.1/.2)** — transcript, Shamir, SHAKE samplers, and the ML-DSA ring core routed onto `github.com/luxfi/mlwe` (byte-preserving); Pulsar and Corona share one Module-LWE base. |
| Committee/epoch object model + on-chain registry | **Consensus target** — the sampled-certificate finality layer (§12) lives in `luxfi/consensus`; the pulsar repo supplies the per-committee keygen + signing primitive each committee runs. |

The load-bearing fact, restated for v0.6.3: **dealerless keygen and
no-reconstruct signing are both built and stock-FIPS-204-verifiable.** The open
work (B) is the *full KeyGen-distribution-equivalence proof* and the
*malicious-secure CSCP / identifiable-abort* layer (§18), not the existence of a
dealerless committee key.

---

## 3. Version lineage (the certificate kernel's own ledger)

> Read alongside `ref/go/pkg/pulsar/VERSIONS.md` (the gate-read track ledger) and
> `PROOF-CLAIMS.md` (the assurance vocabulary). Package-version scheme (distinct
> from the repo's `vX` module tags).

| Version | What it is | Status |
|---|---|---|
| **v0.3 — algebraic broadcast** | The `AlgebraicAggregate` path broadcast per-party `c·s2`/`c·t0` residual shares and reconstructed the `MakeHint` residual at the aggregator. | **REMOVED** — leaked the long-term key (PULSAR-V13-HINT-LEAK). Ripped out forward-only; no backward-compatible re-entry. |
| **v0.4 — BCC/CSCP no-reconstruct** | Boundary-Clearance-Condition (BCC) + Carry-Elimination (CEF) + CarryCompare secure-comparison (CSCP). Each member holds one poly-vector Shamir share of `s1`; signing aggregates only masked `z`-partials; the hint comes from the public `w' = A·z − c·t1·2^d`. No process forms `s1`, the seed, `sk`, `c·s2`, `c·t0`, `r0`, or full `w`. | **Production sign path.** |
| **v0.5 — malicious hardening** | Nonce single-use *safe by construction* (`w1`-only dedup, per-share registry); authenticated-PartyID blame (forged victim-slot partials dropped before attribution); origin-auth *safe by default* (`ErrOriginAuthRequired`); identifiable-abort plumbing; GATE-2 reachability + indirection lint; CI pure-Go / no-`legacy_trusted_dealer` invariants. | **Merged, RED-verified 0 crit/high.** Malicious-**hardened**, not fully-malicious-secure-*proven*. |
| **v0.6.0 — dealerless RSS keygen** | *The dealer is dead at keygen too.* Mithril short Replicated Secret Sharing (`ia.cr/2026/013`): the key is the sum of `C(N,N−T+1)` fresh `χ_η` subset secrets (`‖s2‖∞ ≤ C·η`, genuinely small), sampled leaderwise and replicated; no party holds all subsets. Signs byte-for-byte under stock circl. | **Built.** `mithril_rss.go`. |
| **v0.6.1 / v0.6.2 — mlwe de-dup** | Route transcript → `mlwe/transcript`, Shamir → `mlwe/share`, SHAKE samplers → `mlwe/sample/shake`, ML-DSA ring core → `mlwe/ring/mldsa`. Byte-preserving (all KATs replay identically). Pulsar + Corona on one Module-LWE base. | **Built.** |
| **v0.6.3 — RSS overflow fix** | `accumulateSubset` reduces mod q *per subset*; without it, summing all `C(N,M)` `χ_η` coefficients (each stored ≈ q ≈ 2²³) overflows uint32 once `C ≥ ⌊2³²/q⌋ = 512`, wrapping the key into an unsignable large-secret wall key. Mod-q is additively homomorphic ⇒ small committees (n ≤ 8) are byte-unchanged. | **Built (current `main`).** `mithril_rss.go:110`–`127`. |
| **+ HYPERBALL signer** | The Mithril 3-round no-reconstruct threshold signer for the RSS key: each party reveals only `z_j = y_j + c·s1_(j)` under a leak-free Excess gate; the summed `z` is a standard FIPS-204 response. Gates 5 (verifies under stock circl, no reconstruction) and 6 (fail-closed). | **Built.** `mithril_rss_hyperball.go`. Lands on the dealerless RSS keygen (commits `645b5c5`→`0faa086`). |

---

## 4. Dealerless RSS keygen — the dealer is dead at keygen

`MithrilRSSKeygen(mode, t, n, partySeeds)` (`mithril_rss.go:133`) runs the
dealerless Mithril RSS DKG for an `(T, N)` committee, driven by one contributed
32-byte seed per party. There is **no trusted dealer**.

**Construction.** For every `M`-subset `S` of the committee (`M = N − T + 1`),
that subset's **leader** (lowest-indexed member) derives a 64-byte sampling seed
from its own contributed entropy (`mithrilSubsetSeed`, `:84`, domain-separated
`"pulsar.mithril.rss.subset.v1"`), samples a short secret
`(s1^(S), s2^(S)) ∈ S_η` from it, and replicates it to the subset's members and
to no one else (`:169`–`182`). The composite key is the plain sum
`s1 = Σ_S s1^(S)`, `s2 = Σ_S s2^(S)`; the public key `t = A·s1 + s2` is
Power2Round-split into `(t0, t1)` exactly as `deriveKeyMaterial` / circl does
(`computePublicKey`, `:192`), so the published `t1` is **byte-identical to what
circl derives** from `(rho, s1, s2)`.

**Why it beats the pick-2 wall (the obstruction's named escape).** The
vss/large-blinding dealerless DKG yields `t = A·s1 + B·u` with `‖B·u‖∞ ≈ q/2` —
far outside `S_η` — so `FindHint` never fits a ±1 hint of weight ≤ ω and **no**
byte-stock-FIPS-204 signature exists. RSS keeps every share short:
`‖s2‖∞ ≤ C(N,N−T+1)·η`, genuinely small. The BCC signer recovers the hint from
the **public** `w' = A·z − c·t1·2^d` exactly as the verifier does, so the small
`s2` only lowers the per-nonce acceptance rate — it never breaks verifiability
(`mithril_rss.go:12`–`23`).

**Dealerless guarantee (structural).** No single party is a member of every
subset (T ≥ 2), so no party ever holds the whole `(s1, s2)`; any T parties cover
all subsets and reconstruct via the balanced partition; fewer than T are
disjoint from at least one whole subset whose fresh short secret masks the key.
Proven for the entire viability range by `TestMithrilRSSDealerless`
(`mithril_rss_test.go:91`): no party holds all subsets, and no `(T−1)`-coalition
covers all subsets.

**Admission (the per-(N,T) norm bound, not a flat cap).** A committee is
admitted iff `2 ≤ T ≤ N ≤ 63` **and** `τ·C(N,N−T+1)·η < γ2` (`luxfi/dkg`
`rss.ValidateCommittee`). The second condition is load-bearing: the signer's
hint term `‖c·s2‖∞ ≤ τ·C·η` must stay inside one γ2 rounding bucket. Worked
numerically (dkg v0.3.5): **admitted** n=8,t=7 (`τCη = 5 488`, 48× margin),
n=8,t=8 (1 568), n=16,t=14 (109 760, 2.4× margin — tight but viable);
**rejected** n=16,t=12 (856 128 > γ2, hint budget blown). The empirical
reconstructed norms at n=16,t=14 are `‖s1‖∞, ‖s2‖∞ ≈ 185–230` — far below the
worst-case `C·η = 2240` and far below γ2 = 261 888 (so the key is genuinely
signable). `MaxParties = 6` is only the small-committee fast-path / iteration
cap, **not** the admissible ceiling.

**The v0.6.3 overflow fix (why large committees were blocked).** Every `χ_η`
coefficient is stored in pulsar's `[q−η, q+η]` representation (≈ q ≈ 2²³), and
`poly.add` is a raw uint32 add. Summing all `C(N,M)` subset secrets without
intermediate reduction overflows the accumulator once `C ≥ ⌊2³²/q⌋ = 512` —
exactly the owner-default n=16,t=14 with `C(16,3) = 560` — wrapping the
coefficient into an unsignable large-secret wall key. `accumulateSubset`
(`mithril_rss.go:122`) reduces **mod q per subset**; because reduction mod q is
an additive homomorphism, the result is the *identical* short `Σ_S` secret a
single final reduction would give for a small committee (so n ≤ 8 is
byte-unchanged), while every intermediate accumulator stays below 2q ≪ 2³².

**Signing the RSS key — two paths.**
- *Quorum-reconstruct* (`MithrilKey.Sign`, `mithril_rss.go:266`): rebuilds the
  key material from any T parties' holdings (`ReconstructKeyMaterial`, `:223`,
  balanced partition `rss.RSSRecover`), BCC-signs, and **fail-closed
  self-verifies** under the FIPS-204 verifier before returning. This rebuilds
  the secret at the signing coordinator — fine for a single trusted signer, but
  it is *reconstruct-at-sign*.
- *No-reconstruct* (`MithrilKey.SignHyperball`, §5): never rebuilds the key.

---

## 5. No-reconstruct hyperball signer — the Mithril 3-round protocol

`SignHyperball(active, message, ctx, rng, maxRounds)`
(`mithril_rss_hyperball.go:780`) produces a byte-stock-FIPS-204 ML-DSA signature
under the dealerless RSS group key from any T active parties **without ever
reconstructing the key**. No party and no coordinator ever forms the full `s1`,
any `s2`, `t0`, the mask `y`, the commitment `w`, `w0 = LowBits(w)`, or any `sk`.

**The kernel idea.** Each active party holds only its balanced-partition share
`s1_(j)` (the sum of the subset secrets the partition assigns to it, taken from
*this party's own holdings* — `partyShareS1`, `:870`, never summed across
parties). The party emits only its partial response `z_j = y_j + c·s1_(j)`. The
sum `z = Σ_j z_j = y + c·s1` is the standard FIPS-204 response; the hint is
recovered from the **public** `w' = A·z − c·t1·2^d`. `s2` is never touched
during signing.

**Three rounds** (`mithril_rss_hyperball.go`):
1. **Commit** (`round1`, `:294`). Each party samples `K = kReps` ephemeral masks
   `y_{j,k}` uniformly inside a hyperball `B(0, r1)` (`sampleHyperballInBall`,
   `:895`), computes `w_{j,k} = A·y_{j,k}`, and broadcasts binding commitment
   hashes `CommitW` (and a blame-only `CommitT` to `T_j = A·s1_(j)`,
   `hyperballCommitT`, `:1019`).
2. **Reveal + aggregate** (`round2` `:321`; coordinator `aggregateCommitments`
   `:430`). Parties reveal `w_{j,k}`; the coordinator verifies each against the
   Round-1 commitment (equivocation gate, `:466`), sums `w_k = Σ_j w_{j,k}`, and
   derives the challenge `c_k` for every **boundary-clear** slot (`BoundaryClear`,
   `boundary.go:103`). A non-clear slot gets `c = nil` (dead — no party responds,
   no secret consulted).
3. **Respond** (`round3`, `:333`). For each live slot the party computes
   `z_{j,k} = y_{j,k} + c_k·s1_(j)` and applies a **leak-free Excess gate**
   (`hyperballExcess`, `:966`): if the continuous response leaves `B(0, r)` the
   partial is **rejected and never revealed**. The coordinator `finalize`
   (`:518`) requires every active party to have accepted a slot, sums
   `z_k = Σ_j z_{j,k}`, runs the FIPS-204 reject bound + `FindHint`
   (`boundary.go:154`) on the public `w'`, and emits `(c̃, z, h)`. A **mandatory
   fail-closed release gate** runs stock `VerifyCtx` before returning — a biased
   or malformed partial makes `w'` miss `w1`, so that slot is skipped, never a
   bad signature emitted.

**Why it is stock-verifiable (Claim A).** Verifiability is *independent of the
hyperball parameters*: the produced `(c̃, z, h)` clears the FIPS-204 verifier iff
the summed `z, w` clear the central BCC checks — identical to what `bccSign`
checks on a single reconstructed key, only here `y` and `z` are formed
additively. So the signature verifies byte-for-byte under unmodified
`circl mldsa65.Verify`.

**Why the partials are leak-free (Claim B argument).** Conditioned on the Excess
gate's acceptance, the revealed `z_j` is (almost) uniform on `B(0, r)`,
independent of the secret shift `c·s1_(j)`; the residual dependence is bounded by
Rényi divergence ≤ 1/(1 − 2⁻⁶⁴) per signature via the leak-free gap
`Δ = r1 − r` (`deriveHyperballParams`, `:106`; κ = 64 conservative;
`docs/hyperball-mldsa65-params.md`). The mask `y_j` is **never serialised** — the
wire carries only `w_{j,k} = A·y_{j,k}` (recovering `y` is Module-SIS) and the
public `z_{j,k}`.

**Gate evidence (proven today):**
- **GATE 5(a)** — `TestHyperballStockCirclVerify` (`mithril_rss_hyperball_test.go:41`):
  the hyperball signature verifies under unmodified `circl mldsa65.Verify` for
  every committee N ≤ 6 and for n=8,t=8; tamper / wrong-message / wrong-context
  rejected (verifier non-vacuous).
- **GATE 5(b)** — `TestHyperballNoReconstructStructural` (`:100`): a `go/ast` scan
  proves the signing path **never calls `ReconstructKeyMaterial`**; a source byte
  scan proves no secret share/mask is ever packed to the wire; a runtime
  transcript oracle proves no party's share `s1_(j)` nor the full reconstructed
  `s1`/`s2` bytes appear in `publicBytes()`; and no `(T−1)`-coalition even covers
  all subsets.
- **GATE 6** — fail-closed: `TestHyperballSubThresholdFailsClosed` (`:298`,
  below-threshold/malformed active sets refused before signing),
  `TestHyperballBiasedPartialCaughtAndBlamed` (`:329`, the release gate rejects a
  biased partial and `blameSlot` pinpoints the culprit *without forming
  Σ_j T_j = t − s2* — leak-free blame), `TestHyperballEquivocationCaught` (`:404`,
  a rushing party that changes `w` between rounds is rejected by the binding
  check).
- **Mask never on wire** — `TestHyperballMaskNeverOnWire` (`:529`, commit
  `0faa086`): no party's mask `y` (nor its share) bytes appear in the Round-2 /
  Round-3 wire data.

**Honest blame residual (`mithril_rss_hyperball.go:633`–`637`).** A party that
uses a share inconsistent with keygen but self-consistent with its *own*
(equivocated-at-keygen) `T_j` passes the per-party blame check; it is still
caught by the fail-closed release gate (no bad signature ever emitted) but is not
pinpointed there. This is the same identifiable-abort residual as the
malicious-CSCP layer (§18) — flagged, not faked.

---

## 6. Parameter sets

Pulsar is defined for the BCC-proven scope only: **ML-DSA-65** and
**ML-DSA-87**. ML-DSA-44 has **no** Pulsar suite.

Common FIPS-204 modulus `q = 8380417 = 2²³ − 2¹³ + 1`, ring
`R_q = Z_q[X]/(X²⁵⁶ + 1)`, Power2Round `d = 13`.

| Symbol | ML-DSA-65 | ML-DSA-87 | Meaning |
|---|---|---|---|
| Category | NIST 3 (production target) | NIST 5 | |
| `(K, L)` | `(6, 5)` | `(8, 7)` | matrix `A ∈ R_q^{K×L}` |
| `η` | `4` | `2` | secret bound, `s1,s2 ∈ S_η` |
| `τ` | `49` | `60` | challenge weight |
| `β = τ·η` | `196` | `120` | key-shift bound `‖c·s2‖∞ ≤ β` |
| `γ2` | `261888 = (q−1)/32` | `261888` | HighBits bucket half-width |
| `ω` | `55` | `75` | hint weight bound |
| `\|c̃\|` | `48 B` | `64 B` | challenge-hash length |

**BCC clearance** (`boundary.go`): a nonce is accepted only if its commitment
clears a fixed boundary so `HighBits(w − c·s2) = HighBits(w)`; the hint is then
**public-computable** and the key residual never appears in the transcript.

**Why ML-DSA-44 is excluded.** BCC requires `‖c·t0‖∞ ≤ τ·2^(d−1) < γ2`. For
ML-DSA-44, `39·4096 = 159744 > γ2 = 95232` — the hint cannot be kept
public-computable. `bccParams` returns `ok = false` (`boundary.go:40`,
`:38`–`:39`); both the BCC signer and `deriveHyperballParams` (`ErrHyperballScope`,
`mithril_rss_hyperball.go:72`) refuse ML-DSA-44.

---

## 7. Avalanche-native committee math — sample many, accumulate by repetition

This is the load-bearing scaling idea, and it is **not** "one big BFT committee."
Lux consensus is Avalanche-family: safety on the chain itself comes from
*repeated small-sample sub-sampling*. Pulsar mirrors that for the post-quantum
*certificate*: **do not make one small committee the finality root — sample MANY
small dealerless RSS committees over the same finalized digest and accumulate
confidence by repetition.**

**Setup.** A permissionless validator set of `N ≥ 1000` with a Byzantine
fraction `f ≤ 1/3`. Per epoch, sample `m` independent committees, each of size
`n` with signing threshold `t`; require `r` of the `m` committees to produce a
valid certificate over the same digest.

**One-committee capture probability.** A single committee of `n` stake-weighted
members is *captured* (the adversary controls ≥ t of it, hence could forge that
committee's leg) with probability
```
p  =  Pr[X ≥ t],   X ~ Binomial(n, f).
```

**r-of-m failure probability.** Treating committee captures as independent
(unbiased sampling, §8), the certificate forges only if **at least r** of the
`m` committees are captured:
```
P_fail  ≈  Σ_{j ≥ r}  C(m, j) · p^j · (1 − p)^{m − j}     (exact binomial tail)
```
The special case `r = m` (require *all* sampled committees) collapses to
`P_fail ≈ p^r`. The general `r`-of-`m` tail is what the default uses, because it
tolerates up to `m − r` offline/stalled committees for liveness while keeping
the forgery budget astronomically small.

**Default profile — `Pulsar-HYBRID-PQ-v1`: n = 8, t = 7, m = 12, r = 8.**
- One-committee capture `p = Pr[X ≥ 7], X ~ Binomial(8, 1/3) = 17/6561 ≈ 2⁻⁸·⁶`.
- 8-of-12 tail `P_fail ≈ 2⁻⁵⁹·⁸` (the dominant `j = 8` term
  `C(12,8)·p⁸·(1−p)⁴` dominates; computed with exact `math/big` on the consensus
  side).
- This is **NOT** `n = 64 / t = 5` or any single large committee. Small, high
  threshold (t close to n) maximizes per-committee `p`-resistance; repetition
  (`r`-of-`m`) does the security amplification.

Why small-and-high-`t` committees, specifically: the dealerless RSS keygen is
norm-viable exactly in the small/high-`t` regime (§4: n=8,t=7 has 48× margin;
n=16,t=14 is 2.4×; n=16,t=12 is rejected). The Avalanche sampled-cert model wants
exactly those committees — so the cryptographic feasibility envelope and the
consensus security model **coincide**. We never need the research-open
large-committee dealerless DKG, because we never use a large committee.

**`PulsarSampledCert` shape.** `r` standard ML-DSA signatures (one per
contributing committee, each a `(c̃, z, h)` under that committee's RSS `GroupPK`),
plus the committee plan binding (§8). Storage and verify cost are `O(r)`,
independent of `N` — each leg is verified by an **unmodified** FIPS-204 verifier.

---

## 8. Unbiasable committee selection

The independence assumption behind §7's `P_fail` requires that the adversary
**cannot grind committee membership**.

- **Stake-weighted VRF sortition.** Each committee's members are drawn by
  stake-weighted VRF from the snapshotted validator set, seeded by an
  **unbiasable** beacon.
- **The seed is the previous *finalized* block**, not a proposer-chosen value —
  it is **not proposer-grindable**. An adversary cannot re-roll the sortition to
  land ≥ t members in a committee.
- **`committeePlanHash` is bound into the Quasar subject `M`.** The full plan
  (epoch, the `m` committees' member sets, thresholds, the seed) is hashed and
  folded into the message the committees sign, so a certificate is valid only for
  the exact plan it was sampled under — a captured committee from one plan cannot
  be replayed into another.

This is what lets §7 treat the `m` committee captures as (near-)independent
Bernoulli trials, and what makes the `r`-of-`m` tail meaningful rather than
grindable down to one lucky committee.

---

## 9. Three finality tiers

Pulsar's sampled certificate is the **default PQ finality**, sitting between a
fast classical path and a maximal large-quorum PQ root.

| Tier | Cert | Use | PQ posture |
|---|---|---|---|
| **FAST** | **Beam-only** (classical BLS/consensus finality) | low-latency, non-adversarial-PQ lanes | classical only |
| **HYBRID_PQ** | **Beam + Pulsar sampled-cert** (§7 default `n=8,t=7,m=12,r=8`) | **default finality** | classical safety + compact PQ certs (`P_fail ≈ 2⁻⁵⁹·⁸`) |
| **PQ_ROOT** | **P3Q large-quorum** — a ≥ ⅔-weighted ML-DSA quorum over the validator set | recovery / checkpoint / maximal-assurance root of trust | full PQ super-majority |

**Division of labour.** Avalanche sub-sampling carries *chain safety*; Pulsar
produces *compact post-quantum certificates over consensus-finalized digests*.
The sampled-cert tier (HYBRID_PQ) is not re-deriving consensus — it is attaching
a small, independently-verifiable PQ proof to a digest consensus already
finalized. PQ_ROOT (P3Q) is the heavyweight fallback when a maximal,
non-sampled, super-majority PQ attestation is required.

---

## 10. System, adversary, and synchrony model

**Parties.** `N` permissionless validators (target `N > 1000`), each with stake
and a registered long-term identity key; the epoch validator set is committed by
`validator_set_root` (§11). Per epoch, `m` committees of size `n` are sampled by
stake-weighted VRF (§8). A per-session **coordinator** is a committee member with
**no special trust** — it routes/aggregates public data, and the fail-closed
release gate makes coordinator misbehavior detectable (liveness-only).

**Adversary.** Byzantine, Module-LWE/Module-SIS-bounded, SHA3/SHAKE modeled as a
RO for domain-separated input. Per committee, up to `t − 1` corruptions for
unforgeability and `(t−1)`-privacy (the standard threshold bound). The *certificate*
forgery budget is the `r`-of-`m` product across committees (§7), not a single
committee. Static corruption is the submission posture. The hyperball signer's
malicious-deviation containment is **fail-closed/liveness-only**: a biased
partial cannot forge or leak (§5); identifiable-abort against an
equivocated-at-keygen share is a labelled residual (§18).

**Synchrony.** *Keygen* (RSS) and *preprocessing*: partially synchronous with a
bounded complaint/blame round. *Online signing*: 3 rounds (hyperball) or 1 round
(BCC over an offline ticket) under partial synchrony; liveness is provided by
sampling `m > r` committees so a stalled committee does not stall finality.
*On-chain verification*: deterministic, no synchrony assumption.

---

## 11. Object model

All objects are content-addressed by a SHAKE256 hash over their canonical
encoding with a domain tag (§14). On-chain we store **commitments**, not raw
material.

### PulsarEpoch
```
epoch_id            uint64        monotonic epoch counter
validator_set_root  [32]byte      Merkle root over (validator_id, stake, ltk) leaves
randomness_seed     [32]byte      UNBIASABLE beacon (prev finalized block) → committee sampling (§8)
policy_id           uint32        selects (n, t, m, r) profile + suite (§7, §9)
activation_height   uint64        first block at which this epoch's committees may sign
expiry_height       uint64        last block; certs under this epoch invalid after it
```

### PulsarCommittee
```
epoch_id            uint64
committee_id        uint32        index within the epoch (0..m-1)
members             []ValidatorID stake/VRF-sampled, size n
stake_weights       []uint64      aligned with members
threshold_t         uint16        RSS signing threshold (§4 viability bound)
scheme              uint8         ML-DSA-65 | ML-DSA-87
group_public_key    []byte        FIPS-204 pk bytes — the RSS GroupPK a verifier uses
keygen_root         [32]byte      commitment to the RSS keygen transcript (DKG-PROOF-BOUNDARY.md)
status              uint8         Proposed | Active | Expired | Slashed
```

### PulsarSampledCert
```
epoch_id              uint64
policy_id             uint32      the (n,t,m,r) profile (§7)
message_kind          uint16      finality | bridge | upgrade | warp | emergency
message_digest        [32]byte    domain-separated digest the committees signed (§14)
committee_plan_hash   [32]byte    bound into the signed digest (§8) — anti-grinding
legs                  []Leg       r entries, each { committee_id, signature (c̃,z,h), group_public_key_ref }
```
Each `Leg.signature` is a **standard FIPS-204** signature under that committee's
RSS `GroupPK`. `O(r)` storage; `r` independent stock-verifier checks (§13).

---

## 12. Per-epoch lifecycle

1. **Epoch start** → snapshot the validator set; commit `validator_set_root`.
2. **Beacon** → `randomness_seed` (prev finalized block, §8) seeds the
   stake-weighted VRF sortition of `m` committees.
3. **Dealerless committee DKG** (off-chain / p2p) → each committee runs
   `MithrilRSSKeygen` (§4): **no dealer**, no party holds the full key, the
   public `GroupPK` is a genuine FIPS-204 key. The keygen transcript root is
   committed.
4. **Commit** → the chain accepts each committee's `GroupPK` iff the keygen
   transcript is well-formed and the committee is admissible (§4 norm bound).
   Faulty members → blame set → slashing input.
5. **Per certificate:** for a consensus-finalized digest, each sampled committee
   runs the **no-reconstruct** signer (hyperball, §5 — or the 1-round BCC signer
   over an offline ticket) and emits its leg; the chain assembles a
   `PulsarSampledCert` once `r` legs land.
6. **Verify** (any relying party / chain) → §13.
7. **Rotation** → at `expiry_height` the epoch's committees expire; membership
   changes take effect at the **next** epoch's fresh DKG (key expiry, not key
   mutation — a live committee key is never mutated per join/leave).

**Never all-N-sign.** A certificate is signed by `r` small committees of `n`
members each, never by all `N` validators. Cost is `O(r·n)`, independent of `N`.

---

## 13. On-chain verification

Verification is **cheap and stateless w.r.t. DKG** — no threshold or DKG math
runs per signature. Given a `PulsarSampledCert` and the on-chain committee
registry, check, in order, fail-closed:

1. **Epoch active.** `epoch_id` resolves to an epoch whose
   `[activation_height, expiry_height]` brackets the current height, and whose
   `policy_id` admits `message_kind`.
2. **Plan binding.** Recompute `committee_plan_hash` from the registered epoch
   sortition and confirm it equals the value bound into `message_digest` (§8).
3. **Quorum of legs.** Exactly `r` distinct committees' legs are present, each
   resolving to an `Active` committee of this epoch.
4. **Each leg: GroupPK matches registry** (`group_public_key_ref == hash(registry
   GroupPK)`), then **standard verify**:
   `MLDSA.Verify(GroupPK, message_digest, leg.signature)` with an **unmodified**
   FIPS-204 verifier (Claim A). This is the only crypto op, run `r` times.
5. **Not replayed.** `(epoch_id, message_digest)` has not been accepted before.

The `r`-of-`m` policy (§7) is enforced by step 3 + the per-leg checks; the forgery
budget is `P_fail` (§7). This is the **HYBRID_PQ** tier verifier; **PQ_ROOT** (P3Q)
runs the analogous large-quorum check over a ≥ ⅔-weighted ML-DSA set.

---

## 14. Domain separation tags

All hashing uses SHAKE256 / cSHAKE256 (SP 800-185) with a version-pinned tag;
one tag per purpose, never reused. The *implemented* DSTs (grounded in
`transcript.go` and the RSS/hyperball files) include:

| Tag | Purpose | Site |
|---|---|---|
| `Pulsar` (cSHAKE function-name `N`) | all cSHAKE calls | `transcript.go:73` |
| `PULSAR-DKG-COMMIT-V1` | seed-share DKG Round-2 digest + committeeRoot | `transcript.go:40` |
| `PULSAR-SEED-SHARE-V1` | Shamir coeff stream + master-seed mix | `transcript.go:66` |
| `pulsar.mithril.rss.rho.v1` | RSS joint public seed `rho` | `mithril_rss.go:101` |
| `pulsar.mithril.rss.subset.v1` | RSS per-subset sampling seed | `mithril_rss.go:86` |
| `pulsar.mithril.hyperball.nonce.v1` | hyperball per-round nonce seed | `mithril_rss_hyperball.go:993` |
| `pulsar.mithril.hyperball.commitW.v1` | hyperball `w`-commitment binding | `mithril_rss_hyperball.go:1006` |
| `pulsar.mithril.hyperball.commitT.v1` | hyperball `T_j` (blame-only) commitment | `mithril_rss_hyperball.go:1021` |
| `pulsar.mithril.hyperball.sid.v1` | hyperball session id | `mithril_rss_hyperball.go:1032` |
| `PULSAR/nonce-single-use/v1` | nonce dedup key (`w1` alone) | `nonce_ledger.go:395` |
| `PULSAR-BCC-CEF/joint-pk-id/v1` | stable group-PK id | `distributed_bcc.go` |
| `PULSAR/protocol-msg/v1` | authenticated-protocol-message TBS | `protocol_auth.go:61` |

The certificate-layer namespace (`pulsar:v1:<kind>` for `message_digest`) is the
*consensus target* binding `epoch / committee-plan / policy / chain_id /
message_kind` (§8, §13); it is kept distinct from the implemented kernel DSTs
above on purpose.

---

## 15. Abort, blame, and slashing

- **DKG abort.** A member that fails to deliver/open a subset secret, or
  equivocates, is placed in the blame set; the committee re-runs without it (if
  `n − |blame| ≥ t`) or the epoch resamples. Blame is on-chain → slashing input.
- **Signing abort (liveness, not safety).** A biased `z_j` or a bad aggregate is
  caught by the **mandatory fail-closed release gate** (`finalize` runs stock
  FIPS-204 verify before emit, `mithril_rss_hyperball.go:610`–`616`; the BCC path's
  `TalusReleaseGate`): the slot is skipped/aborted. A deviating party is bounded
  to **liveness** — never a forgery or leak. `blameSlot` (`:638`) attributes the
  culprit leak-free (never forming `Σ_j T_j = t − s2`).
- **Nonce-reuse.** The hyperball protocol derives fresh per-round nonces (`round1`
  is keyed on fresh round entropy); `TestHyperballNonceReuseFatal` (`:419`)
  demonstrates why reuse would be catastrophic (`z1 − z2 = (c1 − c2)·s1_(j)`
  recovers the share) and that the derivation prevents it. The BCC path enforces
  `w1`-keyed single-use (`ErrNonceReused`, `nonce_ledger.go:80`).

---

## 16. Build note — packaging & shared base

Pulsar's lattice primitives are routed onto **`github.com/luxfi/mlwe`** (v0.6.1 /
v0.6.2): transcript → `mlwe/transcript`, Shamir → `mlwe/share`, SHAKE samplers →
`mlwe/sample/shake`, ML-DSA ring core → `mlwe/ring/mldsa`, all byte-preserving.
The dealerless committee combinatorics (subset enumeration, the `(n,t)` viability
bound, the balanced reconstruction partition) come from
**`github.com/luxfi/dkg/rss`**. Pulsar and Corona share the one Module-LWE base,
so a change to the shared arithmetic is made in one place — and the two **legs of
the Quasar dual-PQ cert build and version independently** (a Module-LWE issue in
one must not block the other).

---

## 17. Security summary

- **(A) Verification compatibility — PROVEN today.** The no-reconstruct BCC/CEF
  signer (`bcc_sign_test.go:86`), the dealerless RSS key
  (`mithril_rss_test.go:38`, `mithril_rss_n8_test.go:16`), and the no-reconstruct
  hyperball signer (`mithril_rss_hyperball_test.go:41`) all produce `(c̃, z, h)`
  accepted by **unmodified** `circl mldsa{65,87}.Verify`, with
  tamper/wrong-message/wrong-context negatives.
- **(B) Construction — Lux-authored, partly residual.** Dealerless RSS keygen
  (no dealer, no party holds the whole key) + no-reconstruct signing (BCC/CSCP +
  hyperball) reduce to ML-DSA EUF-CMA under Module-LWE / Module-SIS for the
  *output bytes*. The **scoped residuals** (§18) are the full FIPS-204
  KeyGen-distribution-equivalence proof and the malicious-secure
  CSCP/identifiable-abort layer.
- **Certificate-level safety — sampling, not one committee.** A `PulsarSampledCert`
  forges only if `r` of `m` independent, unbiasably-sampled committees are
  captured: `P_fail ≈ 2⁻⁵⁹·⁸` for the default `n=8,t=7,m=12,r=8` (§7).
- **Dual-PQ defence in depth.** Pulsar is the FIPS-204-standard, Module-LWE leg of
  the Quasar AND-mode dual-PQ cert; **Corona** (natively dealerless Module-LWE
  Raccoon/Ringtail line — a *non*-FIPS verifier) is the assumption-diverse
  companion leg. A forgery requires breaking both legs.

---

## 18. Residuals (labelled, fail-closed, never silently weakened)

| # | Residual | Status |
|---|---|---|
| **R1** | **Full FIPS-204 KeyGen-distribution-equivalence** for the dealerless RSS keygen — that `GroupPK` is distributed identically to a single honest `KeyGen`, with (i) an unbiased composite secret, (ii) hiding against `< t` corruptions, (iii) abort-bias resistance. Standard-verifier compatibility (A) is **proven**; this distributional (B) equivalence needs a simulation/hiding/abort-bias proof. | **open-research** (Claim B). The structural facts (no party holds the key, `‖s2‖∞ ≤ C·η`, stock-circl-verifiable) are proven; the distributional proof is not. |
| **R2** | **Malicious-secure CSCP + identifiable-abort.** A valid-sigma but wrong-`z` partial (BCC), or an equivocated-at-keygen share (hyperball `blameSlot`), is bounded to a **liveness fault** (never forgery/leak — the release gate catches it) but is **not yet attributed**. Needs BDLOP/Ajtai hiding share-commitments + an extended linear-sigma. | **fail-closed-pending-review** (`share_commit.go:73` `ErrIdentifiableAbortResidual`; `mithril_rss_hyperball.go:633`). |
| **R3** | **Leak-free distributed NonceMPC** (BCC offline ticket factory). The production sign path consumes a `NonceCert` (only `w1` public); the stand-in dealer-models the nonce and exposes `DebugW` to tests only (PULSAR-V13-W-LEAK). | **fail-closed-pending-review.** The hyperball signer does **not** use this path (it forms `w` additively from per-party commitments, no nonce dealer). |
| **R4** | **Networked, non-simulation MPC + persistent (crash-restart) nonce ledger.** The crypto binding is in place; the authenticated transport and a restart-surviving per-share ledger are consensus-layer residuals. | **flagged.** |

**Never claimed.** FIPS/NIST-certified threshold ML-DSA · fully-malicious-secure-
*proven* (mechanized) · global-1000-validator DKG. (RSS keygen is per-committee
and small; the global scale is achieved by *sampling* small committees, §7.)

---

## 19. References

- **TALUS** — J. Kao, "TALUS: Threshold ML-DSA with One-Round Online Signing via
  Boundary Clearance and Carry Elimination," `arXiv:2603.22109`. *(BCC = Boundary
  Clearance Condition; CEF = Carry Elimination Framework; reduces to ML-DSA
  EUF-CMA; offline ticket factory + one-round online signing.)*
- **Mithril** — Celi, del Pino, Espitau, Niot, Prest, "Mithril: Threshold ML-DSA
  from Short Replicated Secret Sharing," `ia.cr/2026/013`, USENIX Security 2026.
  *(Short replicated sharing — the dealerless RSS keygen; the 3-round hyperball
  no-reconstruct signer; standard-verifier-compatible; practical for small,
  high-threshold committees.)*
- **Threshold Raccoon** — del Pino, Katsumata, Prest, Rossi, EUROCRYPT 2024.
  *(Noise-flooded lattice signatures — a non-FIPS verifier; the Corona/Raccoon
  line, why Corona is the assumption-diverse dealerless leg.)*
- **Corona** — Boschini et al., Module-LWE threshold signatures (`luxfi/corona`),
  the dealerless companion leg of the dual-PQ Quasar cert.
- **Avalanche** — Team Rocket, "Scalable and Probabilistic Leaderless BFT
  Consensus through Metastability." *(The repeated-small-sample sub-sampling whose
  `Pr[capture]^r`-style amplification the sampled-cert model mirrors for PQ
  certificates.)*
- **FIPS 204** — NIST, Module-Lattice-Based Digital Signature Standard (ML-DSA).
  *(The single-party standard whose **verifier** accepts Pulsar output — Claim A.
  NIST does not standardize threshold ML-DSA.)*

### Companion artifacts
- DKG/threshold proof boundary: `DKG-PROOF-BOUNDARY.md` +
  `vectors/dkg-proof-boundary.json`.
- Assurance vocabulary / gate-read: `PROOF-CLAIMS.md`; track ledger:
  `ref/go/pkg/pulsar/VERSIONS.md`; open findings: `BLOCKERS.md`.
- Algorithm-level spec: `spec/pulsar.tex`, `spec/parameters.tex`,
  `spec/system-model.tex`, `spec/security-games.tex`.
- Proofs: `~/work/lux/proofs/pulsar/` (LaTeX) + `~/work/lux/proofs/lean/Crypto/Pulsar/`.
- Reference implementation: `ref/go/pkg/pulsar/` (BCC/CEF kernel, TALUS, the
  dealerless RSS keygen `mithril_rss.go`, the hyperball signer
  `mithril_rss_hyperball.go`, the computed naive-additive obstruction).
