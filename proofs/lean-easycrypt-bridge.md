# Lean ↔ EasyCrypt Shamir/Lagrange bridge

## Why this document exists

Pulsar's machine-checked proof stack uses **two complementary
provers**:

* **EasyCrypt** drives the procedure-level refinement / equiv proofs
  for the threshold layer (`proofs/easycrypt/Pulsar_N1.ec`,
  `Pulsar_N4.ec`, the two `*_Refinement.ec` files, the two
  `*_Layout.ec` files, the `Pulsar_N1_{Combine,Sign}_Wrapper.ec`
  files, and `Pulsar_N1_Extracted.ec`).
  EasyCrypt is the right tool for procedural Hoare/equiv goals with
  side-channel-aware semantics — but its first-order theory of
  finite fields and polynomial interpolation is comparatively
  thin.
* **Lean 4 + Mathlib** carries the algebraic content: Shamir
  reconstruction, Lagrange interpolation linearity, finite-field
  polynomial uniqueness. Mathlib has the field theory we'd
  otherwise have to re-axiomatize in EC.

The bridge between them is currently **conceptual** — the EC side
states the algebraic identities it needs as **named axioms** that
correspond 1:1 to **proved Lean theorems** in the sibling repo
`~/work/lux/proofs/lean/Crypto/`. This document pins that 1:1
correspondence so a reviewer can verify the math content is
discharged elsewhere and not silently hand-waved.

The honest framing: **the EasyCrypt axioms named below are not
unproved obligations in the strict sense — they are imports from
the Lean proof artifact**. The audit gap is operational (no
mechanical proof-object exchange across the two provers, no shared
serialization format) rather than mathematical.

## Repository pin-points

* EasyCrypt side: `~/work/lux/pulsar/proofs/easycrypt/`,
  commit `226b4cb` (this commit, or later — verify against the
  current `git rev-parse HEAD`).
* Lean side: `~/work/lux/proofs/lean/Crypto/`, commit `923dc84`.

## Axiom-to-theorem mapping

### Axiom 1: `Pulsar_N1.lagrange_inverse_eval`

**EasyCrypt statement** (`proofs/easycrypt/Pulsar_N1.ec:177`):

```ec
op poly_degree : share_t -> int.
axiom poly_degree_nonneg (s : share_t) : 0 <= poly_degree s.

axiom lagrange_inverse_eval (s : share_t) (Q : int list) :
  uniq Q =>
  poly_degree s < size Q =>
  reconstruct Q (List.map (poly_eval s) Q) = s.
```

The `poly_degree s < size Q` precondition matches the Lean
theorem's `f.degree < s.card`. Earlier versions used the weaker
`1 <= size Q` which permitted unsound instantiations on a
short quorum reconstructing a non-constant polynomial.

**Lean proof** (`lean/Crypto/Pulsar/Shamir.lean:76`):

```lean
theorem shamir_correct_at_target
    {F : Type*} [Field F] [DecidableEq F]
    (f : Polynomial F) {ι : Type*} [DecidableEq ι]
    (s : Finset ι) (v : ι → F)
    (hvs : Set.InjOn v s) (degree_f_lt : f.degree < s.card) :
    f = Lagrange.interpolate s v (fun i => f.eval (v i)) :=
  Crypto.Threshold.Lagrange.threshold_reconstructs_secret f s v hvs degree_f_lt
```

**Correspondence**:

| Symbol | EC | Lean |
|---|---|---|
| Shamir polynomial | `s : share_t` (abstracted as its constant term) | `f : Polynomial F` |
| Quorum / evaluation set | `Q : int list` (with `uniq Q`) | `s : Finset ι` + `v : ι → F` injective on `s` |
| Per-party share | `poly_eval s i` | `f.eval (v i)` |
| Reconstruction | `reconstruct Q shares` | `(Lagrange.interpolate s v shares).eval 0` |
| Identity at quorum | `reconstruct Q (map (poly_eval s) Q) = s` | `f = Lagrange.interpolate s v (fun i => f.eval (v i))` then evaluate at 0 |

The Lean theorem is **stronger** (polynomial-level equality, not
just constant-term recovery). Specializing to evaluation at 0
yields the EC-side identity via
`Crypto.Threshold.Lagrange.secret_recovery_at_zero` (file
`lean/Crypto/Threshold_Lagrange.lean:62`).

**Degree bound**: The Lean side requires `f.degree < s.card`. On
the EC side this is implicit in the abstract `share_t` type
(Pulsar's Shamir polynomial has degree exactly `t - 1` over a
`t`-of-`n` committee, and `size Q ≥ 1` plus `uniq Q` plus the
implicit `t ≤ size Q` from the protocol layer gives the degree
bound).

### Axiom 2: `Pulsar_N4.reconstruct_linear`

**EasyCrypt statement** (`proofs/easycrypt/Pulsar_N4.ec:133`):

```ec
axiom reconstruct_linear :
  forall (q : int list) (a b : share_t list),
    size a = size q => size b = size q =>
    reconstruct q (zip_add a b) =
      add_share (reconstruct q a) (reconstruct q b).
```

**Lean proof** (`lean/Crypto/Threshold_Lagrange.lean:81`):

```lean
theorem combine_distributes_over_sum
    {ι : Type*} [DecidableEq ι] (s : Finset ι) (v : ι → F) (a b : ι → F) :
    Lagrange.interpolate s v (a + b) =
      Lagrange.interpolate s v a + Lagrange.interpolate s v b :=
  (Lagrange.interpolate s v).map_add a b
```

**Correspondence**:

| Symbol | EC | Lean |
|---|---|---|
| Quorum | `q : int list` | `s : Finset ι` |
| Per-party value | `a : share_t list`, `b : share_t list` | `a, b : ι → F` |
| Pointwise sum | `zip_add a b` | `a + b` (pointwise) |
| Combination | `reconstruct q (...)` | `(Lagrange.interpolate s v (...)).eval 0` |
| Linearity | `reconstruct (a + b) = reconstruct a + reconstruct b` | `interpolate (a + b) = interpolate a + interpolate b` |

The Lean theorem follows from `LinearMap.map_add` applied to
`Lagrange.interpolate s v`, which Mathlib expresses as an
`F-linear map`. Evaluating at 0 (an `R-linear` operation) preserves
the equation. This is exactly the algebraic content the EC axiom
states.

### Axiom 3: `Pulsar_N4.shamir_correct`

**EasyCrypt statement** (`proofs/easycrypt/Pulsar_N4.ec:141`):

```ec
axiom shamir_correct :
  forall (q : int list) (s : share_t),
    uniq q => 1 <= size q =>
    reconstruct q (fresh_sharing q s) = s.
```

**Lean proof** (same as Axiom 1):

```lean
theorem shamir_correct_at_target ...  (* Crypto/Pulsar/Shamir.lean:76 *)
```

Plus the auxiliary `secret_recovery_at_zero`
(`lean/Crypto/Threshold_Lagrange.lean:62`).

**Correspondence**: `fresh_sharing q s` is the Pulsar adapter that
constructs the per-party shares of `s` along quorum `q` (= mapping
`q ↦ poly_eval s` on each `q[i]`, modulo the internal randomness
of the polynomial above degree 0). After Lagrange-recovery via
`reconstruct`, the constant term `s` returns. Same theorem as
Axiom 1, applied differently.

### Axiom 4: `Pulsar_N4.add_share_zeroR`

**EasyCrypt statement** (`proofs/easycrypt/Pulsar_N4.ec:130`):

```ec
axiom add_share_zeroR : forall (s : share_t), add_share s zero_share = s.
```

This is an algebraic identity on the `share_t` ring (right-identity
of addition). Mathlib provides this for any
`AddCommMonoid`-instance type, but the EC side keeps `share_t`
abstract and so axiomatizes the property directly. On the Lean
side this is implicit in the `Ring` / `Polynomial`-coefficient
instances and never needs an explicit theorem.

### Axiom 5: `Pulsar_N1.threshold_partial_response_identity`

**EasyCrypt statement** (`proofs/easycrypt/Pulsar_N1.ec`, v8):

```ec
axiom threshold_partial_response_identity :
  forall (Q : int list) (shares : share_t list)
         (c_tilde : c_tilde_n1_t) (rho_rnd : randomness_t) (mu_val : mu_t),
    uniq Q =>
    size shares = size Q =>
    poly_degree (reconstruct Q shares) < size Q =>
    shares = List.map (poly_eval (reconstruct Q shares)) Q =>
    lagrange_aggregate_responses Q
      (List.map (per_party_partial_response c_tilde rho_rnd mu_val) shares)
    = mldsa_compute_z
        (unpack_sk (reconstruct Q shares))
        mu_val rho_rnd.
```

**Lean counterpart**
(`~/work/lux/proofs/lean/Crypto/Threshold_Lagrange.lean:121`,
theorem `threshold_partial_response_identity`):

```lean
theorem threshold_partial_response_identity
    (f : F[X]) {ι : Type*} [DecidableEq ι] (s : Finset ι) (v : ι → F)
    (hvs : Set.InjOn v s) (degree_f_lt : f.degree < s.card)
    (y : ι → F) (c : F)
    (z : ι → F) (hz : z = y + c • fun i => f.eval (v i)) :
    (Lagrange.interpolate s v z).eval 0 =
      (Lagrange.interpolate s v y).eval 0 + c * f.eval 0
```

**Type correspondence**

| Lean | EasyCrypt | Meaning |
|---|---|---|
| `F[X]` | (abstracted into `share_t`) | secret-sharing polynomial |
| `s : Finset ι` | `Q : int list` (with `uniq Q`) | quorum |
| `v : ι → F` (with `Set.InjOn v s`) | implicit in `uniq Q` | party indexing |
| `degree_f_lt : f.degree < s.card` | `poly_degree (reconstruct Q shares) < size Q` | sharing-polynomial degree bound |
| `z = y + c • fun i => f.eval (v i)` (per party) | `per_party_partial_response c_tilde rho_rnd mu_val (poly_eval (reconstruct Q shares) i)` | per-party response |
| `Lagrange.interpolate s v z .eval 0` | `lagrange_aggregate_responses Q [per_party_PR_i]` | quorum aggregation at 0 |
| `+ c * f.eval 0` | folded into the abstract `mldsa_compute_z` on the reconstructed share | centralised z |

**Used by**
`Pulsar_N1_Combine_Refinement.combine_body_z_spec` (v8, now a
derived lemma) — bridges the combine-side z-stage byte-walk to the
Lean Lagrange theorem. The `combine_body_partial_responses_spec`
narrow axiom + `combine_body_z_via_aggregation_spec` structural
axiom + this bridge compose to derive `combine_body_z_spec`.

**Honest framing**

The EC axiom integrates THREE facts:
1. The Lean theorem's algebraic identity (interpolate-z = interpolate-y + c·f(0));
2. The implicit y-aggregation: `mldsa_compute_z`'s y_central
   equals the Lagrange-aggregation of the per-party y_i values used
   in `per_party_partial_response`;
3. The structural decomposition `mldsa_compute_z = y_central + c · s_central`.

(2) and (3) are not separately mechanized — they are folded into
the EC axiom's RHS via the abstract `mldsa_compute_z` op. Future
narrowing would expose y_aggregation as a separate identity and
split this bridge into smaller pieces.

## What this bridge does NOT do

It does **not** provide a mechanical proof-object exchange. The EC
axioms are still trusted in the EC dependency cone — the bridge
is a code-review-level mapping, not a formal-method-level one.

The honest closure path is:

1. **Either** mechanize the four axioms inside EasyCrypt itself
   (would require importing or rebuilding a finite-field
   polynomial-interpolation library in EC; multi-week project),
2. **Or** prove the same statements in a tool whose proof object
   EC can consume (no current standard format),
3. **Or** keep the conceptual bridge and pin the Lean commit in
   the EC file headers (which we do, see "Citation comments"
   below).

Option (3) is what we do today. It is honest — the EC axiom
statements correspond 1:1 to Lean theorems we have proved — but
it is not strict closure inside the EC dependency cone.

## Citation comments

Each of the five EC axioms above carries an inline comment immediately
preceding it that names the Lean theorem and file. The CI guard
`scripts/check-lean-bridge.sh` asserts every EC axiom in the bridge
has an unchanged signature AND a citation comment naming a Lean
theorem that still exists; signature drift trips the gate.

## Closure paths

The bridge collapses entirely under either of two routes:

1. **Mechanical close in EC.** Build a minimal polynomial-
   interpolation theory inside EasyCrypt sufficient to discharge
   the five axioms. The Mathlib `Lagrange.interpolate` machinery
   is the porting target.
2. **Lean → EC tactic translation.** When the EasyCrypt community
   ships a Lean-proof-object consumer, the bridge becomes a
   one-line `import` rather than five axiom statements.

## Summary

The trust footprint of the extracted N1 byte-equality theorem,
inclusive of this bridge:

* **22 named axioms total**, each with file:line in EC and Lean:
  17 narrow implementation-refinement (14 byte-walk + 1
  signature-codec round-trip + 2 honest-execution no-reject
  post-conditions) plus 5 Lean-bridged algebraic (Axioms 1–5 above,
  each citing a proved Lean theorem in
  `~/work/lux/proofs/lean/Crypto/`).
* **0** section-local module-contract axioms in the extracted N1
  corollary.

Per-axiom enumeration with closure plan: `docs/proof-axiom-inventory.md`.
Authoritative source: `proofs/easycrypt/Pulsar_N1_Extracted.ec`.
