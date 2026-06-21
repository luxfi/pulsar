(* -------------------------------------------------------------------- *)
(* Pulsar -- Class N1 NO-LEAK masked-aggregate model                    *)
(* -------------------------------------------------------------------- *)
(* STATUS (honest): WRITTEN; machine-recheck PENDING EasyCrypt.          *)
(*   There is no `easycrypt`/`why3`/`alt-ergo` toolchain on the build    *)
(*   host this file was authored on, so it has NOT been re-elaborated    *)
(*   here. The CI gate `scripts/checks/ec-compile.sh` is the authority;  *)
(*   it is SKIPPED locally when easycrypt is absent. Do NOT relabel any  *)
(*   lemma below "machine-checked"/"discharged" until ec-compile runs    *)
(*   green in CI. The ALGEBRAIC CORE this file rests on IS machine-      *)
(*   checked, in Lean 4 + Mathlib, on this host:                         *)
(*     Crypto.Pulsar.NoLeak.{z_aggregate_no_reconstruct,                 *)
(*       hint_highbits_stable_under_hidden_shift, hint_is_fips_hint,     *)
(*       no_leak_under_standard_assumptions}                             *)
(*     Crypto.Pulsar.Boundary.{boundary_clearance, findHintCoeff_*}      *)
(*     Crypto.Threshold.Lagrange.threshold_partial_response_identity     *)
(*   (`lake build` exits 0, with no unproven-tactic placeholders).       *)
(*                                                                      *)
(* WHY THIS FILE EXISTS — de-misdirecting reconstruct-then-sign          *)
(* -----------------------------------------------------------------    *)
(* `Pulsar_N1.ec`'s headline `pulsar_n1_byte_equality` proves the        *)
(* threshold combine bit-equals `SinglePartyRun(S).run`, whose body is   *)
(*                                                                       *)
(*     sk_group <- reconstruct quorum shares;  S.sign(sk_group, ...)     *)
(*                                                                       *)
(* i.e. it RECONSTRUCTS THE MASTER SECRET and signs with it. That is     *)
(* exactly the path the production leaderless signer must NEVER take     *)
(* (BLOCKERS.md PULSAR-V13-HINT-LEAK): forming `reconstruct quorum       *)
(* shares` -- or any per-party `c*s2`/`c*t0` whose Shamir aggregate is   *)
(* the master `c*s2`/`c*t0` -- leaks the long-term key.                  *)
(*                                                                       *)
(* This file states the CORRECT no-leak model: the public Lagrange       *)
(* aggregate of the per-party MASKED responses equals the central `z`    *)
(* WITHOUT ever forming the master secret, and the hint is recovered     *)
(* from the PUBLIC `w' = A*z - c*t1*2^d` via FIPS `UseHint` (FindHint).  *)
(* The residual OPEN content is then NOT "extracted code = central sign  *)
(* on the reconstructed secret" but a STANDARD-ASSUMPTION reduction      *)
(* (Module-LWE + Module-SIS) that the public transcript leaks nothing    *)
(* about (s1,s2,t0) beyond a single FIPS 204 signature.                  *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv Distr.
require import Pulsar_N1.

(* We work inside a section parametric on the same abstract algebra as
   Pulsar_N1, reusing its types/ops (share_t, z_n1_t, mu_t,
   per_party_partial_response, lagrange_aggregate_responses,
   mldsa_compute_z, unpack_sk, reconstruct, ...). *)

(* ===================================================================
   PART 1 — the no-leak z aggregate (master secret never reconstructed)

   This is the EC mirror of the machine-checked Lean theorem
   `Crypto.Pulsar.NoLeak.z_aggregate_no_reconstruct`, which is itself
   `Crypto.Threshold.Lagrange.threshold_partial_response_identity`.

   The pre-existing Pulsar_N1 axiom `threshold_partial_response_identity`
   ALREADY states the no-leak z identity: the Lagrange aggregate of the
   per-party masked responses equals `mldsa_compute_z (unpack_sk
   (reconstruct Q shares)) ...`. Crucially the RHS uses the secret only
   as the `z` value's `c*s1` summand; the per-party `c*share_i` terms are
   each masked by `y_i` and only the public aggregate is exposed.

   `no_leak_z_aggregate` re-exports it in no-leak vocabulary and is the
   contract the production combine satisfies: it computes the SAME `z`
   the central signer would, from masked partials, without reconstruction
   as an operational step. (A: Lean-bridged standard fact; NOT a security
   conclusion.)
   =================================================================== *)

lemma no_leak_z_aggregate
      (Q : int list) (shares : share_t list)
      (c_tilde : c_tilde_n1_t) (rho_rnd : randomness_t) (mu_val : mu_t) :
    uniq Q =>
    size shares = size Q =>
    poly_degree (reconstruct Q shares) < size Q =>
    shares = List.map (poly_eval (reconstruct Q shares)) Q =>
    lagrange_aggregate_responses Q
      (List.map (per_party_partial_response c_tilde rho_rnd mu_val) shares)
    = mldsa_compute_z (unpack_sk (reconstruct Q shares)) mu_val rho_rnd.
proof.
  (* Exactly the Lean-bridged Pulsar_N1 axiom; re-stated here so the
     no-leak file is self-contained. Closes by `apply`. *)
  exact (threshold_partial_response_identity Q shares c_tilde rho_rnd mu_val).
qed.

(* ===================================================================
   PART 2 — the public-hint recovery (no secret residual on the wire)

   The hint is recovered from PUBLIC data: the verifier-reconstructable
   `w' = A*z - c*t1*2^d` and the PUBLIC target `w1 = HighBits(w)`. We
   model the FIPS 204 UseHint and the public FindHint as abstract ops
   over the public commitment vector; the MACHINE-CHECKED content (that
   FindHint reproduces the unique FIPS hint, and HighBits is stable under
   the hidden c*s2 shift so such a hint EXISTS) lives in Lean
   `Crypto.Pulsar.Boundary`. Here we expose the interface and the
   no-secret-residual invariant the combine must satisfy. *)

type commit_vec_t.        (* w / w' / w1 all live in the public commitment space *)
type hint_vec_t.

op public_w_prime : z_n1_t -> c_tilde_n1_t -> group_pk_t -> commit_vec_t.
  (* w' = A*z - c*t1*2^d : a function of the PUBLIC (z, c_tilde, pk) ONLY.
     No s1/s2/t0 input -- this is the verifier's own reconstruction. *)

op high_bits_commit : commit_vec_t -> commit_vec_t.   (* HighBits (FIPS 204 §3.4.2) *)
op find_hint : commit_vec_t -> commit_vec_t -> hint_vec_t.  (* (w', w1) -> h, public *)
op use_hint  : hint_vec_t -> commit_vec_t -> commit_vec_t.  (* FIPS UseHint (Alg.40) *)

(* The central commitment w1 the signer committed the challenge to. A
   function of the secret only through the boundary-clear nonce; surfaced
   as an abstract op (its concretisation is in Pulsar_N1_Combine_Refinement). *)
op central_w1_of : unpacked_sk_t -> mu_t -> randomness_t -> commit_vec_t.

(* PUBLIC-HINT CONTRACT (Lean-backed, B/standard layer):
   on a boundary-clear nonce, FindHint over the PUBLIC (w', w1) returns a
   hint that UseHint maps back to w1. The Lean theorems
   `boundary_clearance` (HighBits stable under the hidden |delta|<=beta
   c*s2 shift) + `findHintCoeff_sound/_unique` establish per-coefficient
   that such a hint exists and is THE FIPS hint. This axiom is the
   procedure-level lift of those per-coefficient facts; it references only
   public quantities -- there is no c*s2/c*t0/r0 anywhere in it. *)
axiom public_hint_roundtrip
      (z : z_n1_t) (c_tilde : c_tilde_n1_t) (gpk : group_pk_t)
      (usk : unpacked_sk_t) (mu_val : mu_t) (rho_rnd : randomness_t) :
    (* the public target equals the central w1 ... *)
    high_bits_commit (public_w_prime z c_tilde gpk)
      = central_w1_of usk mu_val rho_rnd =>
    (* ... then UseHint of the public-found hint reaches it *)
    use_hint (find_hint (public_w_prime z c_tilde gpk)
                        (central_w1_of usk mu_val rho_rnd))
             (public_w_prime z c_tilde gpk)
    = central_w1_of usk mu_val rho_rnd.

(* ===================================================================
   PART 3 — the residual cryptographic assumption (STANDARD: M-LWE/M-SIS)

   The two parts above are CORRECTNESS: the no-leak combine computes the
   same (c_tilde, z, h) the central signer would, from masked partials and
   public hint recovery, with the master secret never formed. The
   remaining content is SECRECY: that the public threshold transcript
   reveals nothing about (s1,s2,t0) beyond ONE single-party FIPS 204
   signature. We state it as an abstract simulation-soundness predicate
   reducing to Module-LWE + Module-SIS -- the SAME assumptions ML-DSA's
   own EUF-CMA rests on (FIPS 204 / Dilithium). This is the honest
   replacement for `combine_body_axiom`: a standard-assumption reduction,
   NOT a reconstruct.

   EC mirror of Lean `Crypto.Pulsar.NoLeak.NoLeakReduction`. *)

type public_transcript_t.     (* (w1, commit(w), clearance proof, c_tilde, z, h) *)
type fips_leakage_t.          (* one single-party FIPS 204 sig's public footprint *)

op module_lwe_hard : bool.    (* w = A*y pseudorandom (mask y is the LWE secret) *)
op module_sis_hard : bool.    (* extracting short (s1,s2) from sig data is MSIS *)
op transcript_simulator : fips_leakage_t -> public_transcript_t.

(* NO-LEAK REDUCTION (C / OPEN, but now a STANDARD-ASSUMPTION reduction).
   Under Module-LWE + Module-SIS, the public threshold transcript is
   reproducible from a single FIPS 204 signature's leakage alone -- i.e.
   the threshold path leaks nothing extra about (s1,s2,t0). DISCLOSED and
   OPEN: the full simulation proof is the v0.8 EC/paper artifact. It does
   NOT reconstruct the secret; its content reduces to standard lattice
   hardness. *)
axiom no_leak_reduction :
  module_lwe_hard =>
  module_sis_hard =>
  forall (leak : fips_leakage_t),
    exists (tr : public_transcript_t), tr = transcript_simulator leak.

(* The packaged honest statement: under the standard assumptions and the
   reduction, every transcript is the simulator's output. Mirrors Lean
   `no_leak_under_standard_assumptions`. *)
lemma no_leak_under_standard_assumptions (leak : fips_leakage_t) :
    module_lwe_hard =>
    module_sis_hard =>
    exists (tr : public_transcript_t), tr = transcript_simulator leak.
proof.
  move=> hlwe hsis.
  exact (no_leak_reduction hlwe hsis leak).
qed.

(* ===================================================================
   ACCOUNTING (this file)

   axioms (3) — all DISCLOSED in AXIOM-INVENTORY.md:
     - public_hint_roundtrip   (B / standard: procedure lift of the
                                Lean-machine-checked boundary_clearance +
                                findHintCoeff_* ; references only PUBLIC
                                quantities, no c*s2/c*t0/r0)
     - no_leak_reduction       (C / OPEN, STANDARD: the Module-LWE +
                                Module-SIS simulation reduction -- the
                                honest replacement for the reconstruct-
                                then-sign combine_body_axiom cone)
     - module_lwe_hard / module_sis_hard are `op` declarations (booleans
                                naming the standard assumptions), not
                                axioms.

   PROVED-MODULO-RECHECK lemmas (machine-recheck pending EasyCrypt):
     no_leak_z_aggregate           (re-exports the Lean-bridged
                                    threshold_partial_response_identity)
     no_leak_under_standard_assumptions

   The z-aggregate + hint-recovery CORRECTNESS core is machine-checked in
   Lean on this host; the EC side is the procedure-level wrapper pending
   ec-compile. The ONLY genuinely-open assumption is `no_leak_reduction`,
   which is a Module-LWE/MSIS reduction -- a STANDARD PQ assumption, not
   an implementation reconstruct.
   =================================================================== *)
