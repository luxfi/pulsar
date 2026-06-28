# Mithril hyperball parameters for ML‑DSA‑65 (one‑sided BCC, no‑reconstruct)

This document derives the hyperball rejection‑sampling parameters for the
**no‑reconstruct** threshold signing path on the dealerless RSS ML‑DSA‑65 key
(`mithril_rss.go`). It is the parameter companion to `mithril_rss_hyperball.go`.

The reference scheme is **Mithril** (Celi–del Pino–Espitau–Niot–Prest,
*Efficient Threshold ML‑DSA from Short Secret Sharing*, USENIX Security 2026,
ePrint 2026/013), whose reference implementation
(`github.com/lattice-safe/threshold-ml-dsa`) is parameterised for **ML‑DSA‑44**.
We derive the corresponding **ML‑DSA‑65** parameters and adapt the geometry to
pulsar's **one‑sided Boundary‑Cleared / Carry‑Elimination (BCC)** signer.

---

## 1. Where the hyperball sits in the protocol

The no‑reconstruct signature is the standard FIPS‑204 ML‑DSA signature

```
z = y + c·s1 ,    h = hint recovered from public w' = A·z − c·t1·2^d
```

formed **additively** across the active signers: party `j` holds only its
balanced‑partition share `s1_(j)` of `s1` (`Σ_j s1_(j) = s1`, all reconstruction
coefficients 0/1 — the RSS property), samples its own mask `y_j`, and emits only

```
z_j = y_j + c·s1_(j)         (Round 3)
```

so that `z = Σ_j z_j = y + c·s1` forms with **no party ever holding `y`, `s1`,
the full key, or any low‑bits/`w0` quantity**. The hint comes from the public
`w'` exactly as in `bcc_sign.go` (`BoundaryClear` + `FindHint`), so **`s2` is
never touched during signing**.

Crucially, **verifiability does not depend on the hyperball parameters at all.**
The signature verifies under unmodified `circl mldsa65.Verify` iff the *summed*
`z` clears the central BCC checks:

* `BoundaryClear(w)` on the aggregated commitment `w = Σ_j A·y_j` (public),
* `‖z‖∞ < γ1 − β` on the aggregated `z`,
* `FindHint(w', w1)` succeeds with weight `≤ ω`.

The hyperball is **not** a correctness device. It is the device that makes each
*revealed* partial `z_j` **leak‑free** with respect to the secret share `s1_(j)`,
and the K‑repetition machinery is what keeps the joint acceptance probability
across `T` parties from collapsing. This separation is what makes the
no‑reconstruct path provably stock‑verifiable independent of the parameter
derivation below.

---

## 2. Why a ball, not a box (the leakage problem)

If each party did the standard FIPS‑204 **L∞ (hypercube)** rejection on `z_j`
independently, the per‑party accept probability would be
`((γ1−β)/γ1)^(L·N)` and the joint probability over `T` parties would be

```
p_cube = ((γ1−β)/γ1)^(T·L·N)
```

which decays **exponentially in `T·L·N`** — infeasible already at `T = 2`,
`L·N = 1280`. Replacing the `L·N` independent per‑coordinate constraints with a
**single L2 (hyperball) constraint** turns the decay from `(·)^(L·N)` into the
concentration of one chi‑like statistic, restoring feasibility. This is the core
Mithril observation (ePrint 2026/013, §2.7).

The ball also makes the leak‑freeness argument a clean **bounded‑rejection**
statement: a nonce drawn uniformly from a ball, accepted iff the shifted
response stays in a slightly smaller ball, yields an accepted response whose
distribution is (almost) independent of the shift `c·s1_(j)`.

### One‑sided adaptation

The Mithril reference is **two‑sided**: it commits `w = A·y + e`, responds with
`(z1, z2) = (c·s1 + y, c·s2 + e)`, and rejects on an **ellipsoid** that weights
the first `L·N` (s1‑side) coordinates by `1/ν²` and the last `K·N` (s2‑side)
coordinates by `1` (`Excess: Σ_{i<L·N} z_i²/ν² + Σ_{i≥L·N} z_i² > r²`, ν = 3).
The `ν` balances the differing magnitudes of the `s1` and `s2` responses.

Pulsar's BCC signer is **one‑sided**: `s2` is never used in signing (the hint is
recovered from the public `w'`), so there is no `s2`‑side, no `e`, and the
ellipsoid degenerates to a **plain L2 ball over the `L·N` mask coordinates**
(`ν = 1`). The commitment is `w_j = A·y_j` (exactly FIPS‑204's `w`, no `e`);
revealing it is sound because, given the to‑be‑revealed `z_j` and the public
`A·s1_(j)`, `w_j = A·z_j − c·A·s1_(j)` carries no extra information, and for
*rejected* slots only `w_j = A·y_j` is on the wire, which hides `y_j` under
Module‑SIS (the same assumption ML‑DSA's unforgeability already rests on).

We keep `ν` as a configurable field for fidelity to the reference, defaulting to
`ν = 1` (plain ball) in the one‑sided path.

---

## 3. The leak‑free radius gap `Δ = r1 − r`

Sample the nonce `y_j` uniformly on the ball `B(0, r1) ⊂ R^n`, `n = L·N`.
Accept the response `z_j = y_j + sh`, `sh = c·s1_(j)`, iff `z_j ∈ B(0, r)` with
`r < r1`. Conditioned on acceptance, `z_j` is uniform on the **lens**
`B(0, r) ∩ B(sh, r1)`. Because both distributions are uniform‑on‑a‑set, the
Rényi divergence of every order `α` between the accepted distribution `P_sh` and
the ideal shift‑independent `U = Uniform(B(0,r))` is the **volume ratio**

```
R_α(P_sh ‖ U) = Vol(B(0,r)) / Vol(B(0,r) ∩ B(sh,r1)) = 1 / (1 − p_cap)
```

where `p_cap` is the fraction of `B(0,r)` farther than `r1` from `sh` (the
missing spherical cap). Over `Q` signatures the divergence multiplies,
`R_α(P^Q ‖ U^Q) = (1 − p_cap)^(−Q)`, and Rényi probability preservation gives no
security loss as long as

```
(1 − p_cap)^(−Q) ≤ 2     ⟺     p_cap ≤ ln2 / Q ≈ 2^(−64.5)   for Q = 2^64.
```

so we target **`p_cap ≤ 2^(−κ)` with `κ = 64`**.

### High‑dimensional cap concentration

Most mass of `B(0,r)` is near the boundary sphere. For a point on the sphere of
radius `r`, with `sh` along an axis and `‖sh‖ = δ`, `‖z − sh‖ > r1` becomes
`z_1 < t` for `t = (r² + δ² − r1²)/(2δ)`. For `r ≫ δ` (always true here) and
`Δ = r1 − r`, `t ≈ −r·Δ/δ`, i.e. the cap is `{z_1/r < −Δ/δ}`. The sphere
marginal of `z_1/r` in dimension `n` has density `∝ (1−u²)^((n−3)/2)`, so

```
p_cap ≈ (1 − (Δ/δ)²)^(n/2).
```

Setting `p_cap = 2^(−κ)` and using `(Δ/δ)² ≪ 1`:

```
              ┌─────────────────────────────┐
   Δ / δ  =   │  √( 2·κ·ln2 / n )            │      (leak‑free gap ratio)
              └─────────────────────────────┘
```

independent of `r` (hence of the norm budget). This is the load‑bearing
formula. We use the order‑`∞` (volume‑ratio) bound, which is the **conservative**
choice — it over‑estimates `Δ` relative to a tighter finite‑`α` Rényi analysis,
buying *more* leak protection at the cost of more rejection.

### Validation against the ML‑DSA‑44 reference table

For the **two‑sided** reference, `n = (K+L)·N = 2048`, and the single‑subset
shift (one χ_η=2 secret, τ=39) has `δ ≈ 400` (mean) over the 2048 coords. The
formula predicts `Δ/δ = √(2·64·ln2/2048) = 0.208`, i.e. `Δ ≈ 0.208·400 ≈ 56` —
matching the reference table's diagonal (T=N, single‑subset shares):

| (T,N) | r       | r1      | r1−r |
|-------|---------|---------|------|
| (2,2) | 252778  | 252833  | 55   |
| (3,3) | 246490  | 246546  | 56   |
| (4,4) | 243463  | 243519  | 56   |
| (5,5) | 239924  | 239981  | 57   |
| (6,6) | 219245  | 219301  | 56   |

The reference's effective `κ` is slightly smaller (≈ 29, a tighter finite‑`α`
bound); our `κ = 64` `α=∞` choice yields `Δ` larger by ≈ 1.5×, i.e. **strictly
more** leak protection. The off‑diagonal reference entries scale as
`Δ ≈ 56·√(maxSubsetsPerParty)`, confirming the quadrature scaling below.

---

## 4. ML‑DSA‑65 parameters (one‑sided, `n = L·N = 1280`)

FIPS‑204 ML‑DSA‑65 constants: `N=256, K=6, L=5, η=4, τ=49, ω=55, q=8380417,
d=13, γ1=2^19=524288, γ2=261888, β=τ·η=196, γ1−β=524092`.

**Single‑subset shift L2 norm.** `s1^(S)` has `L·N = 1280` coefficients drawn
uniformly from `[−η,η] = [−4,4]` (FIPS‑204 RejBoundedPoly), variance
`((2η+1)²−1)/12 = 80/12 = 6.667`. The shift coefficient
`(c·s1^(S))_i` is a sum of `τ = 49` signed copies, variance `τ·6.667 = 326.7`,
so `E‖sh‖² = 1280·326.7 = 418133`, `E‖sh‖ = 646.6`, and a 6σ upper bound is

```
δ_single ≈ √(418133 + 6·√(2·1280)·326.7) ≈ √517307 ≈ 720.
```

**Leak‑free gap ratio** (`n = 1280`, `κ = 64`):

```
Δ/δ = √(2·64·ln2 / 1280) = 0.2633 .
```

**Base gap** (single subset, `T = N`): `Δ_base = ⌈0.2633·720⌉ = 190`.

**Per‑committee gap.** A party's share `s1_(j)` is the sum of
`m = maxSubsetsPerParty(T,N)` independent χ_η secrets, so `‖sh_(j)‖ ≈ √m·δ_single`
(quadrature). Hence

```
Δ(T,N) = Δ_base · √( maxSubsetsPerParty(T,N) )           (= 190·√m)
```

where `maxSubsetsPerParty` is the largest block of the balanced partition
`rss.RSSRecover` (`= 1` for `T = N`).

**Nonce radius.** `r1` is set from the L∞ norm budget so the *summed* `z` stays
under `γ1 − β`. With `y_j` per‑coordinate ≈ `N(0, r1²/n)` and `T` independent
parties, the summed per‑coordinate std is `r1·√(T/n)`; a safety tail of `6.4`
keeps the worst of `L·N` coordinates ≈ `1.7×` under budget:

```
r1(T,N) = (γ1−β)·√(L·N) / (6.4·√T)  =  2,929,687 / √T ,     r = r1 − Δ(T,N).
```

This holds the summed‑`z` per‑coordinate std at a constant ≈ 81 800 (independent
of `T`), worst‑coordinate ≈ 309 000 `< γ1−β = 524 092`.

### Worked values (`Δ_base = 190`, `ν = 1`)

| (T,N) | m | Δ=190√m | r1=2929687/√T | r=r1−Δ | p_party=(r/r1)^1280 |
|-------|---|---------|---------------|--------|---------------------|
| (2,2) | 1 |    190  |   2 071 600   | 2 071 410 | 0.886 |
| (3,3) | 1 |    190  |   1 691 460   | 1 691 270 | 0.861 |
| (4,4) | 1 |    190  |   1 464 840   | 1 464 650 | 0.848 |
| (5,5) | 1 |    190  |   1 310 020   | 1 309 830 | 0.832 |
| (6,6) | 1 |    190  |   1 196 000   | 1 195 810 | 0.817 |
| (8,8) | 1 |    190  |   1 035 800   | 1 035 610 | 0.791 |
| (4,6) | 5 |    425  |   1 196 000   | 1 195 575 | 0.634 |
| (3,5) | 4 |    380  |   1 310 020   | 1 309 640 | 0.690 |

`p_party` is the per‑party ball‑acceptance; the joint per‑slot success is
`p_party^T · p_boundary` with the central `BoundaryClear` yield
`p_boundary ≈ 0.09` for ML‑DSA‑65. K‑repetition (and protocol re‑runs) amortise
this; e.g. `(8,8)`: per‑slot ≈ `0.791^8·0.09 ≈ 0.013`, so ≈ 350 slot‑attempts
clear 99 %, spread over `K` parallel slots and `maxRounds` re‑runs.

### Recommended K (parallel slots per round)

```
K(T,N) = clamp( ⌈ 3 / (p_party^T · p_boundary) ⌉ , 8 , 256 )
```

a slot budget giving `≈ 95 %` success per round; the driver re‑runs the 3 rounds
with fresh nonces up to `maxRounds` if a round produces no usable slot. Sample:
`(2,2)→8`, `(3,3)→8`, `(6,6)→18`, `(8,8)→34`, `(4,6)→200`.

---

## 5. Security summary

* **Verifiability** (stock `circl mldsa65.Verify`): independent of all
  hyperball parameters; guaranteed by the central BCC checks on the *summed*
  `z`, `w`. Proven by round‑trip test across `n=8,t=8` and all `N≤6` committees.
* **Leak‑freeness** (per‑party `z_j`): bounded by Rényi divergence
  `R_α ≤ 1/(1 − 2^(−64))` per signature, `≤ 2` over `Q = 2^64` signatures, by
  the `Δ/δ = √(2κln2/n)` gap. The α=∞ choice is conservative.
* **Structural no‑leak**: no party forms `s1, s2, y, w, w0, sk`; the coordinator
  forms only the *public* aggregates `w = Σ A·y_j`, `w1 = HighBits(w)`,
  `w' = A·z − c·t1·2^d`, and the hint — never `w0 = LowBits(w)`, never any share.
* **Assumption**: Module‑LWE / Module‑SIS over `R_q = Z_q[X]/(X^256+1)` (the same
  assumption ML‑DSA‑65 / FIPS‑204 already rests on) — the one‑sided commitment
  `w_j = A·y_j` hides `y_j` under Module‑SIS. EUF‑CMA of the produced signature
  is exactly FIPS‑204's.

## 6. References

* del Pino, Celi, Espitau, Niot, Prest. *Mithril: Efficient Threshold ML‑DSA
  from Short Secret Sharing.* USENIX Security 2026, ePrint 2026/013.
* Reference implementation: `github.com/lattice-safe/threshold-ml-dsa`
  (`src/fvec.rs` SampleHyperball + Excess, `src/params.rs` Figure 8/9 table,
  `src/sign.rs` 3‑round protocol).
* FIPS 204, *Module‑Lattice‑Based Digital Signature Standard* (ML‑DSA).
* Bai, Lepoint, Roux‑Langlois, Sakzad, Stehlé, Steinfeld. *Improved Security
  Proofs in Lattice‑Based Cryptography: Using the Rényi Divergence.* J.
  Cryptology 2018 (the Rényi‑divergence probability‑preservation lemma).
