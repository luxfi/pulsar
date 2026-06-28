# Pulsar v0.2 Pedersen-VSS DKG — spec → Go mapping (and the FIPS-204 wall)

Scope: maps the v0.2 Pedersen-VSS DKG of `spec/pulsar.tex`
(§"Distributed key generation", Construction `con:pedersen`,
Rounds 1/1.5/2) onto the Go reference (`ref/go/pkg/pulsar`), and records
the precise, **computed + empirically-demonstrated** obstruction that
stops the no-reconstruct construction from producing byte-FIPS-204
signatures. This is the honest Part-2 deliverable: the sound, no-leak
**dealing** layer is real; the FIPS-204 **key-formation** step
fails closed at a structural wall, exactly as the package's existing
`naive_additive_seta_obstruction.go` does for the naive additive lift.

---

## 1. Symbol → Go mapping

| Spec symbol | Meaning | Go (reused unless "NEW") |
|---|---|---|
| `q = 8380417` | ML-DSA prime | `mldsaQ`, `shamirPrimeQ` |
| `R_q = Z_q[X]/(X^256+1)` | base ring | `poly [256]uint32`, `polyVec` |
| `(k, ℓ, η, τ, β, γ1, γ2, ω, d)` | FIPS-204 params | `modeShape`, `modeTauOmega`, `bccParams`, `bccD` |
| `A = ExpandA(ρ) ∈ R_q^{k×ℓ}` | public matrix, NTT domain | `km.a` via `polyDeriveUniform(&p,&rho,nonce)` |
| `B ∈ R_q^{k×ℓ}` uniform, `ρ_B = cSHAKE(…,'PULSAR-EXPANDB-V1')` | hiding matrix | **NEW** `expandB(mode)` (`pedersen_vss.go`) |
| `Comm_{A,B}(c;r) = A·c + B·r ∈ R_q^k` | module-Pedersen commit | **NEW** `modulePedersenCommit` |
| `c_{i,0} ← χ_η^ℓ` | party `i`'s contribution to `s1` | sampled via `polyDeriveUniformLeqEta` |
| `r_{i,k} ← χ_η^ℓ` | blinding coeffs | sampled via `polyDeriveUniformLeqEta` |
| `f_i(X), g_i(X)` deg `t−1` over `R_q^ℓ` | Shamir + blinding polys | **NEW** `vssDealPolyVec` (Shamir over GF(q), per-coeff) |
| `C_{i,k} = A·c_{i,k} + B·r_{i,k}` | commits broadcast in R1 | `modulePedersenCommit` |
| share `(f_i(j), g_i(j))` to party `j` | **share only**, no full `c_i` | **NEW** `VSSShare{S1Share,BlindShare}` |
| `H_i = cSHAKE(…,'PULSAR-DKG-COMMIT-V1' ‖ enc(C_{i,·}))` | R1.5 equivocation digest | reuses `cshake256` / `transcriptHash32` |
| `A·f_i(j)+B·g_i(j) =? Σ_k j^k C_{i,k}` | R2 Pedersen identity check | **NEW** `VerifyVSSShare` |
| `s_j = Σ_i f_i(j)`, `u_j = Σ_i g_i(j)` | aggregated `s1`/`u` shares | **NEW** `AggregateVSSShares` → `AlgShare.S1Share` |
| `t = Σ_i C_{i,0} = A·s1 + B·u` | aggregated public commit | **NEW** `AggregateVSSCommits` |
| `(t1, t0) = Power2Round(t, d)`; `pk = (ρ, t1)` | FIPS-204 pk | `poly.power2Round`; `AlgSetup{Pub,rho,a,t1}` |
| signer consuming the output | TALUS / BCC | `AlgSetup`, `AlgShare`, `DistributedBCCSigner`, `AggregateBCC` (UNCHANGED) |

**Signer interface the DKG must emit** (`distributed_bcc.go`): public
`AlgSetup{Mode,Pub,rho,tr,a,t1}` and per-party
`AlgShare{NodeID,EvalPoint,S1Share,Mode}`. Crucially the BCC/CEF signer
consumes **`S1Share` only** — never `s2`, `t0`, the seed, or the full
`t` — because it recovers the FIPS hint from the **public**
`w' = A·z − c·t1·2^d` via `FindHint`. So a no-reconstruct DKG need only
produce `s1`-shares + public `t1`. That is the good news, and it is why
the dealing layer below is sound. The bad news is how `t1` (hence the
implied `s2`) is formed.

## 2. Rounds (what is sound, what is new)

- **Round 1 (commit + deal)** — SOUND, no-leak. Each dealer samples
  `f_i, g_i` (deg `t−1`, coeffs `← χ_η^ℓ`), broadcasts Pedersen commits
  `C_{i,k}`, and sends each party `j` **only** the Shamir pair
  `(f_i(j), g_i(j))`. No party ever sees another's full `c_{i,0}`. This
  is the decisive improvement over v0.1 `dkg.go`, whose envelope reveals
  the full 32-byte contribution `c_i` to every recipient
  (`dkg.go:366` — "every committee member learns the master secret").
- **Round 1.5 (equivocation gate)** — reuse the existing CR-6/7/8
  cSHAKE256 commit-digest machinery (`abort.go`, `computeRound2Digest`).
- **Round 2 (verify + aggregate)** — SOUND. `VerifyVSSShare` checks the
  Pedersen identity `A·f_i(j)+B·g_i(j) = Σ_k j^k C_{i,k}`; failure →
  `ComplaintBadDelivery` (identifiable abort, binding under MSIS over
  `[A|B]`). Aggregate `s_j = Σ_i f_i(j)` → `AlgShare.S1Share`,
  `t = Σ_i C_{i,0}`.
- **Round 3 (form FIPS-204 key)** — **FAILS CLOSED.** See §3. No seed,
  no `s1`, no `sk` is ever formed (structural no-reconstruct invariant
  holds); but `t = A·s1 + B·u` does not yield a signable FIPS-204 key.

## 3. The obstruction (computed + empirically demonstrated)

The v0.2 key sets the second secret component to **`s2 = B·u`**, with
`u = Σ_i r_{i,0}` small (`χ_η`) and **`B` uniform** (spec
`con:pedersen`; the hiding theorem `thm:pedersen-hiding` *requires* `B`
uniform — it reduces hiding to M-LWE on `B`).

Any FIPS-204 verifier accepts a signature on `pk = (ρ, t1)`,
`t1 = HighBits(A·s1 + s2)`, **only if** for the per-signature nonce
commitment `w = A·y`:

```
HighBits(w − c·s2) = HighBits(w)        ⟺   ‖c·s2‖∞ ≤ β = τ·η
```

(FIPS-204 / Dilithium correctness lemma; the BCC path makes it explicit
via `BoundaryClear` + `FindHint`, the standard path via the `r0`/`MakeHint`
rejection — both need `‖c·s2‖∞ ≤ β`). The package's own `bcc_sign.go`
states the identity `w' = A·z − c·t1·2^d = w + (c·t0 − c·s2)`.

But the **same** M-LWE statement that gives hiding (`thm:outind` proof:
"`B·u` is computationally indistinguishable from a **uniform** `w ∈ R_q^k`")
makes `s2 = B·u` **pseudo-uniform**:

```
‖s2‖∞ = ‖B·u‖∞ ≈ q/2     ⇒     ‖c·s2‖∞ ≫ γ2 ≫ β.
```

Hence `HighBits(w − c·s2) ≠ HighBits(w)` for ~every coefficient, no
weight-`≤ω` hint bridges `w'` to `w1`, `FindHint` returns `ok=false`
(`ErrNoFIPSHint`), and **no FIPS-204-verifiable signature exists** for
the v0.2 key. Empirically (`pedersen_vss_obstruction_test.go`): the
real `bccSign` returns `ErrBCCExhausted` on a `s2 = B·u` key while
succeeding **and circl-verifying** on a small-`s2` key built from the
**same `s1`** — isolating `s2 = B·u` as the sole cause.

### Why no choice of B rescues it
- `B` uniform (spec) ⇒ `s2 ≈ uniform` (worst case).
- `B` small ⇒ ring-convolution blowup `‖B·u‖∞ ≥ ℓ·n·‖B‖∞·‖u‖∞ ≫ η`
  (ML-DSA-65: `≥ 5·256·1·η`), and the `B·r` term degenerates to a small
  perturbation — hiding then rests on M-LWE in `A`, and `s2` collapses to
  `≈ u ∈ S_{Nη}`, i.e. the **naive-additive wall**
  (`assessDealerlessFIPS`: `‖c·s2‖∞ ≤ N·β > β` for every `N ≥ 2`).
- `B = 0` ⇒ `s2 = 0`, a degenerate/insecure key, no hiding from `B`.

### What `thm:outind` actually proves
PUBLIC-KEY indistinguishability: `Power2Round(A·s1+B·u)` and
`Power2Round(A·s1+s2_FIPS)` are both ≈ uniform over the `Power` image, so
the two pks are indistinguishable. True and useful — but **not signature
correctness**. The σ-half of `thm:outind` invokes `thm:sign-correct` as a
hypothesis, and `thm:sign-correct` does **not** hold for `s2 = B·u`
(uniform `B`). "indistinguishable from a fresh `χ_η^k` sample" would be the
opposite claim (small), and is not what the proof establishes.

### Relationship to the existing record
This is the package's documented **Residual B** (`BLOCKERS.md`;
`naive_additive_seta_obstruction.go` / `assessDealerlessFIPS`),
specialized to the Pedersen `B·u` case — which is strictly worse than the
naive `S_{Nη}` sum. Hiding (DKG-PRIV, needs `B` uniform ⇒ `s2` large) and
signing correctness (needs `s2` small) are irreconcilable at the FIPS-204
parameters.

## 4. The real path forward (not Pedersen-VSS Shamir)
Dealerless / no-reconstruct **byte-FIPS-204** keygen is achieved by
**short replicated secret sharing + local rejection** (Mithril,
Celi–del Pino–Espitau–Niot–Prest, ia.cr/2026/013, USENIX Security 2026) —
replicated (not Shamir/Lagrange, whose coefficient-norm blowup breaks
ML-DSA's short-vector requirement), at small `N`. It is already named in
`naive_additive_seta_obstruction.go` as the adoption target. Until then,
KEYGEN stays trusted-dealer (`DealAlgShares`, no-reconstruct at **sign**
time) and permissionless safety rests on the genuinely-dealerless
**Corona** leg in the AND-mode dual-PQ Quasar cert.
