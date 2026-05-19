# `sign_body_compute_sig_spec` byte-walk roadmap

## Status

`sign_body_compute_sig_spec` is the **last remaining
implementation-refinement axiom** on the sign side (the
separation axiom became a lemma in `c4148a0`). It states:

```ec
axiom sign_body_compute_sig_spec :
  forall mem_pre ptrs full,
    Pulsar_N1_Sign_Layout.layout_sign_args
      mem_pre ptrs (wire_sign_args_of_full full) =>
    refine_sig_to_n1_sign (sign_body_compute_sig mem_pre ptrs)
    = sign_abs_op full.
```

where `sign_abs_op full` unfolds (by definition) to:

```ec
Pulsar_N1.mldsa_sign_op
  full.`sgn_sk_n1 full.`sgn_m_n1
  full.`sgn_ctx_n1 full.`sgn_rnd_n1
```

i.e., the centralised FIPS 204 ML-DSA-65 signature on the four
protocol-level ghost fields. Tracked under #3.

**Ghost contract**: ctx and rho_rnd are NOT direct libjade
parameters. The wrapper carries them as ghost fields; the
obligation includes the claim that the wrapper's mu derivation
(`SHAKE256(0x00 || ctxlen || ctx || M)` per FIPS 204 §5.4.1
ExternalMu) and K-derived randomness correspond to FIPS 204
`Sign_internal` on the four-tuple. See the named ghost contract
in `Pulsar_N1_Sign_Refinement.ec` and `lean-easycrypt-bridge.md`.

## Why the sign-side proof is harder than combine

The combine-side proof (see `combine-byte-walk-roadmap.md`) gets
to skip the rejection-sampling loop: combine is invoked AFTER
each party has already computed and revealed their Round-2
contribution; the aggregator's job is just polynomial sum-
reconstruct + rejection-condition recheck + pack.

The sign-side proof has to cover the FULL FIPS 204 §6.2 flow:

* sk unpacking
* mu computation
* the kappa rejection-sampling loop
* polynomial pack

The kappa loop is the rough part — it's a `while` whose
termination invariant is "eventually FIPS 204 §6.1 rejection
conditions are satisfied". Proving termination + correctness
of an unbounded rejection loop in EC is significantly harder
than proving a fixed-length aggregation.

## Extracted procedure shape

`M.sign` lives in `sign.ec:3603-3641`. Its signature:

```ec
proc sign (ptr_signature : W64.t, ptr_m : W64.t,
           m_len : W64.t, ptr_sk : W64.t) : W32.t
```

The body is thin: it reads 4000 bytes of secret-key bytes from
`ptr_sk`, delegates to `sign_inner` for the actual signature
computation, and writes 3293 bytes of packed signature at
`ptr_signature`.

The real work is in `sign_inner` (`sign.ec:3469`). The kappa
rejection loop, the SHAKE-based mu computation, the
expandA + expandMask + matrix-vector multiplication + decompose
+ rejection-check + pack flow — all of it lives in `sign_inner`.

## Stage map (high-level)

| Stage | Extracted location | Functional op | Sub-claim |
|---|---|---|---|
| 1. Read sk bytes from input pointer | `sign.ec:3625-3630` | `decode_sk` (Sign_Layout) | **(S1)** sk loaded matches `read_sk(mem, ptr_sk)` = `full.sgn_wire.sk_abs` |
| 2. sign_inner: sk unpacking | `sign_inner` body, decode rho, K, tr, s1, s2, t0 from sk bytes per FIPS 204 §3.5.4 | `MLDSA65_Functional.unpack_sk` (to be defined; mirror of `pack_sk`) | **(S2)** (rho, K, tr, s1, s2, t0) decoded matches FIPS 204 §3.5.4 unpacking of full.sgn_sk_n1 |
| 3. sign_inner: mu = SHAKE256(tr ‖ M) | `sign_inner`, SHAKE call | `shake256` op in MLDSA65_Functional | **(S3)** mu_computed = SHAKE256(tr ‖ msg ‖ ctx-encoded prehash) (ghost contract: ctx already folded into mu by the wrapper convention) |
| 4. sign_inner: rho_prime derivation | deterministic: SHAKE256(K ‖ mu); hedged: SHAKE256(K ‖ rho_rnd ‖ mu) | `MLDSA65_Functional.shake256` | **(S4)** rho_prime equals FIPS 204 §6.2 derivation under the ghost-contract integration of full.sgn_rnd_n1 |
| 5. sign_inner: kappa rejection loop | the WHILE loop in sign_inner — main body of `M.sign_inner` | composition: expand_mask, mat_vec_mul, decompose, sample_in_ball, mul, sub, make_hint, rejection checks | **(S5)** the loop terminates with kappa = some k* such that all R1-R4 conditions hold; the resulting (c_tilde*, z*, h*) match FIPS 204 §6.2 outputs at that kappa |
| 6. sign_inner: pack_signature(c_tilde*, z*, h*) | `pack_signature` call in `sign_inner` | `MLDSA65_Functional.pack_signature` | **(S6)** sig_packed matches FIPS 204 §3.5.5 pack of (c_tilde*, z*, h*) |
| 7. M.sign: write sig_packed at ptr_signature | `sign.ec:3634-3640` | `write_sig_sign` (Sign_Layout) | **(S7)** Sign_Layout.read_sig_sign (memory after the write loop) ptr_signature = decode_signature(sig_packed) |

## How the sub-claims compose

```
S1 ∧ S2 ∧ S3 ∧ S4 ∧ S5 ∧ S6 ∧ S7
       ⇒ sign_body_compute_sig_spec
```

S7 is mechanical (same shape as combine's S10). S6 mirrors
combine's S9. S2 is structural (FIPS 204 §3.5.4 packing
specified by Mathlib-equivalent byte layouts). S3, S4 are
SHAKE256 calls — abstract op in MLDSA65_Functional that should
be discharged via circl's SHAKE256 spec (already imported in
the EC layout side). S1 is a layout-lemma corollary.

**S5 is the hard one**. Bounding the kappa loop in EC requires:
* a non-decreasing termination metric (e.g., expected iteration
  count under the rejection-conditions probability — but a
  termination proof in EC needs an explicit upper bound, not an
  expected one),
* an inductive invariant carrying the per-iteration randomness
  derivation,
* showing that the loop's exit state matches FIPS 204 §6.2's
  selected (c_tilde, z, h) tuple.

In practice, FIPS 204 §6.2 is universally implemented as the
"first-passing kappa" loop, and circl/libjade both bound it by a
hard `kappa_max = 256` (or similar). For an EC proof, the
worst-case-bounded-loop form is the right shape.

## Suggested attack order

1. **S7 first** (signature memory write). Mechanical mirror of
   combine's S10. Estimated: 1-2 days.

2. **S6 second** (pack_signature). The same extracted
   `pack_signature` proc as combine's S9 (libjade reuses it).
   Estimated: 3-5 days (shared with combine S9 work).

3. **S2** (sk unpacking). Structural; FIPS 204 §3.5.4 byte
   layout. Needs `unpack_sk` op in MLDSA65_Functional (not yet
   present — write it). Estimated: 1 week.

4. **S3, S4** (mu and rho_prime derivation). Each is a SHAKE256
   call. Needs concrete `shake256` op in MLDSA65_Functional
   bridged to circl's `cshake256` (already a Pulsar primitive).
   The ghost-contract integration for ctx-into-mu and rho_rnd-
   into-K-derivation is the named obligation; this work decides
   whether to expose it as a separate axiom (per the bridge doc
   § "future-refactor path") or keep it folded into S3 + S4.
   Estimated: 1-2 weeks.

5. **S1** (sk read from memory). Direct layout corollary.
   Estimated: 1 day.

6. **S5** (kappa rejection loop). The substantial work — needs
   a bounded-loop termination + invariant. Estimated:
   3-4 weeks.

**Total honest estimate**: 6-9 weeks (similar to combine,
dominated by the kappa loop).

## Cross-references

* The wider trust accounting: `proofs/easycrypt/Pulsar_N1_Extracted.ec`
  (composition theorem) and the per-file `ACCOUNTING` blocks at the
  end of each refinement / wrapper / layout file. See
  `proofs/easycrypt/README.md` for the per-file dashboard.
* Algebraic bridge: `proofs/lean-easycrypt-bridge.md`.
* Combine-side counterpart: `proofs/easycrypt/extraction/combine-byte-walk-roadmap.md`.
* Ghost contract: named block in `proofs/easycrypt/Pulsar_N1_Sign_Refinement.ec`.
* Linear-issue tracker: #3.
* Libjade jasmin-ct dependency: `ct/jasmin-ct-libjade.md` (separately
  blocking issue #2).
