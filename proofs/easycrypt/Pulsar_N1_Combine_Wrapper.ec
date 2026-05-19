(* -------------------------------------------------------------------- *)
(* Pulsar — Class N1 combine wrapper                                   *)
(* -------------------------------------------------------------------- *)
(* Decomplected from Pulsar_N1_Wrapper_Bridge.ec.                       *)
(*                                                                      *)
(* This file owns ONE thing: the combine-side wrapper machinery that    *)
(* lifts the extracted M.pulsar_combine byte-walk into a procedure-     *)
(* level equiv against Pulsar_N1.CombineAbs.combine. Specifically:      *)
(*                                                                      *)
(*   - derive_*_wire        — protocol → wire-type projectors           *)
(*   - n1_inputs_to_combine_full — builds combine_full_args_t           *)
(*   - encode_combine_args  — composes adapter + Layout encoder         *)
(*   - combine_wrapper_bridge — the byte-level wrapper-bridge lemma     *)
(*   - CombineExtractedWrapper — module satisfying Pulsar_Threshold     *)
(*   - combine_wrapper_equiv_CombineAbs — procedure-level equiv         *)
(*                                                                      *)
(* The sign-side mirror lives in Pulsar_N1_Sign_Wrapper.ec. The         *)
(* composition into pulsar_n1_byte_equality_extracted lives in          *)
(* Pulsar_N1_Extracted.ec.                                              *)
(*                                                                      *)
(* Previously these three concerns lived in one ~500-line file          *)
(* (Pulsar_N1_Wrapper_Bridge.ec). Splitting clarifies which file owns   *)
(* combine machinery, which owns sign machinery, and which composes     *)
(* both into the final theorem. The sign side no longer transitively    *)
(* depends on combine-wrapper definitions.                              *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv Distr DBool DInterval SmtMap.

(* Combine-side refinement: gives us combine_full_args_t, the
   `wire_args_of_full` projection, `refine_sig_to_n1`, the proven
   `combine_body_spec` lemma + `combine_abs_op` definition. *)
require import Pulsar_N1_Combine_Refinement.

(* Concrete combine layout: the encoder + the proved
   `encode_combine_args_layout` aggregate. *)
require import Pulsar_N1_Combine_Layout.

(* Pulsar_N1: protocol types + module types (Pulsar_Threshold,
   CombineAbs, FIPS204Sign, the reconstruct / lagrange ops). *)
require import Pulsar_N1.

(* ===================================================================
   Wire derivation ops.

   The combine ABI's wire-level inputs (c_tilde, t0, r2_msgs)
   are derived from the protocol-level inputs:
     - c_tilde  = SHAKE digest of the Round-1 commit transcript
     - t0       = read from the group public key
     - r2_msgs  = projection of Pulsar_N1.round2_t onto the
                  wire-level r2_msg_t record

   These are abstract ops; their concrete bodies live in the FIPS
   204 / Pulsar protocol spec.
   =================================================================== *)

op derive_c_tilde_wire :
  Pulsar_N1.group_pk_t -> Pulsar_N1.message_t -> Pulsar_N1.ctx_t ->
  Pulsar_N1.round1_t list -> Pulsar_N1_Combine_Layout.c_tilde_t.

op derive_t0_wire :
  Pulsar_N1.group_pk_t -> Pulsar_N1_Combine_Layout.t0_vec_t.

op derive_r2_msgs_wire :
  Pulsar_N1.round2_t list -> Pulsar_N1_Combine_Layout.r2_msg_t list.

(* ===================================================================
   Bundle adapter + concrete encoder.
   =================================================================== *)

op n1_inputs_to_combine_full
   (gpk : Pulsar_N1.group_pk_t) (m : Pulsar_N1.message_t)
   (ctx : Pulsar_N1.ctx_t) (quorum : int list)
   (shares : Pulsar_N1.share_t list) (rho_rnd : Pulsar_N1.randomness_t)
   (r1s : Pulsar_N1.round1_t list) (r2s : Pulsar_N1.round2_t list)
   : combine_full_args_t =
  {| full_wire =
        {| c_tilde_abs = derive_c_tilde_wire gpk m ctx r1s;
           t0_abs      = derive_t0_wire gpk;
           r2s_abs     = derive_r2_msgs_wire r2s; |};
     full_gpk     = gpk;
     full_m       = m;
     full_ctx     = ctx;
     full_quorum  = quorum;
     full_shares  = shares;
     full_rho_rnd = rho_rnd;
     full_r1s     = r1s; |}.

op encode_combine_args
   (gpk : Pulsar_N1.group_pk_t) (m : Pulsar_N1.message_t)
   (ctx : Pulsar_N1.ctx_t) (quorum : int list)
   (shares : Pulsar_N1.share_t list) (rho_rnd : Pulsar_N1.randomness_t)
   (r1s : Pulsar_N1.round1_t list) (r2s : Pulsar_N1.round2_t list)
   : Pulsar_N1_Memory.mem_t *
     Pulsar_N1_Combine_Layout.combine_ptrs_t *
     combine_full_args_t =
  let full = n1_inputs_to_combine_full gpk m ctx quorum shares
                                       rho_rnd r1s r2s in
  let (mem, ptrs) =
    Pulsar_N1_Combine_Layout.encode_combine_args (wire_args_of_full full) in
  (mem, ptrs, full).

(* ===================================================================
   Combine wrapper bridge — PROVED.

   Composes encode_combine_args_layout + combine_body_spec, then
   unfolds combine_abs_op (definitionally equal to
   mldsa_sign_op ∘ reconstruct).
   =================================================================== *)

(* The wrapper bridge now requires an HONEST gpk: it must be the
   derived public key of the reconstructed share. This precondition
   discharges the protocol_consistency predicate the byte-walk axiom
   now asks for (Agent 1 HIGH-1 closure). Without this, an
   adversarial caller passing an arbitrary gpk could claim
   byte-equality with mldsa_sign_op on the reconstructed share —
   independent of whether their claimed gpk matches. *)
lemma combine_wrapper_bridge :
  forall (gpk : Pulsar_N1.group_pk_t)
         (m : Pulsar_N1.message_t)
         (ctx : Pulsar_N1.ctx_t)
         (quorum : int list)
         (shares : Pulsar_N1.share_t list)
         (rho_rnd : Pulsar_N1.randomness_t)
         (r1s : Pulsar_N1.round1_t list)
         (r2s : Pulsar_N1.round2_t list),
    gpk = Pulsar_N1.derive_pk (Pulsar_N1.reconstruct quorum shares) =>
    Pulsar_N1.accept_signing_attempt
      (Pulsar_N1.reconstruct quorum shares) m ctx rho_rnd =>
    (* v8: threshold interpolation well-formedness bundle. The four
       conjuncts mirror the Lean Lagrange theorem's preconditions and
       are required to discharge the `threshold_partial_response_identity`
       bridge in the z-stage derivation:
         1. uniq quorum                         (distinct party indices)
         2. size shares = size quorum           (shape match)
         3. poly_degree < size quorum           (degree bound)
         4. shares = poly_eval reconstruction   (honest sharing)
       Conjuncts (1) and (2) are conventional threshold-protocol
       preconditions present in the wrapper context since earlier
       commits; conjuncts (3) and (4) are new in v8 and propagate up
       to the top-level `pulsar_n1_byte_equality`. A future v9 may
       refactor these four into a single `threshold_interpolation_wf`
       predicate; for v8 they remain expanded to minimise proof churn.
       *)
    uniq quorum =>
    size shares = size quorum =>
    Pulsar_N1.poly_degree (Pulsar_N1.reconstruct quorum shares) < size quorum =>
    shares = List.map (Pulsar_N1.poly_eval (Pulsar_N1.reconstruct quorum shares)) quorum =>
    let (mem, ptrs, full) =
      encode_combine_args gpk m ctx quorum shares rho_rnd r1s r2s in
    refine_sig_to_n1
      (Pulsar_N1_Combine_Layout.read_signature_at
         (combine_body_fn mem ptrs)
         ptrs.`Pulsar_N1_Combine_Layout.sig_out_ptr)
    = Pulsar_N1.mldsa_sign_op
        (Pulsar_N1.reconstruct quorum shares) m ctx rho_rnd.
proof.
  move=> gpk m ctx quorum shares rho_rnd r1s r2s Hgpk Haccept Huniq Hsize Hdeg Hhonest /=.
  rewrite /encode_combine_args /=.
  have Hlay :
    Pulsar_N1_Combine_Layout.layout_combine_args
      (Pulsar_N1_Combine_Layout.encode_combine_args
         (wire_args_of_full
            (n1_inputs_to_combine_full gpk m ctx quorum shares
                                       rho_rnd r1s r2s))).`1
      (Pulsar_N1_Combine_Layout.encode_combine_args
         (wire_args_of_full
            (n1_inputs_to_combine_full gpk m ctx quorum shares
                                       rho_rnd r1s r2s))).`2
      (wire_args_of_full
         (n1_inputs_to_combine_full gpk m ctx quorum shares
                                    rho_rnd r1s r2s)).
  - by apply Pulsar_N1_Combine_Layout.encode_combine_args_layout.
  have Hconsist : protocol_consistency
                    (n1_inputs_to_combine_full gpk m ctx quorum shares
                                               rho_rnd r1s r2s).
  - by rewrite /protocol_consistency /n1_inputs_to_combine_full /=.
  have Hthresh : threshold_protocol_invariants
                   (n1_inputs_to_combine_full gpk m ctx quorum shares
                                              rho_rnd r1s r2s).
  - rewrite /threshold_protocol_invariants /n1_inputs_to_combine_full /=.
    by smt().
  have Hacc :
    Pulsar_N1.accept_signing_attempt
      (Pulsar_N1.reconstruct
         (n1_inputs_to_combine_full gpk m ctx quorum shares
                                    rho_rnd r1s r2s).`full_quorum
         (n1_inputs_to_combine_full gpk m ctx quorum shares
                                    rho_rnd r1s r2s).`full_shares)
      (n1_inputs_to_combine_full gpk m ctx quorum shares
                                 rho_rnd r1s r2s).`full_m
      (n1_inputs_to_combine_full gpk m ctx quorum shares
                                 rho_rnd r1s r2s).`full_ctx
      (n1_inputs_to_combine_full gpk m ctx quorum shares
                                 rho_rnd r1s r2s).`full_rho_rnd.
  - by rewrite /n1_inputs_to_combine_full /=.
  have Hspec :=
    combine_body_spec
      (Pulsar_N1_Combine_Layout.encode_combine_args
         (wire_args_of_full
            (n1_inputs_to_combine_full gpk m ctx quorum shares
                                       rho_rnd r1s r2s))).`1
      (Pulsar_N1_Combine_Layout.encode_combine_args
         (wire_args_of_full
            (n1_inputs_to_combine_full gpk m ctx quorum shares
                                       rho_rnd r1s r2s))).`2
      (n1_inputs_to_combine_full gpk m ctx quorum shares
                                 rho_rnd r1s r2s)
      Hlay Hconsist Hthresh Hacc.
  rewrite Hspec /combine_abs_op /n1_inputs_to_combine_full /=.
  done.
qed.

(* ===================================================================
   Concrete extracted-wrapper module.

   `round1`/`round2` are placeholders returning witness — the
   N1 byte-equality theorem only consumes `combine`. They satisfy
   the Pulsar_Threshold module-type signature without claiming any
   meaningful behavior (which is correct: the extracted M.pulsar_*
   round procs are separate proof obligations covered by their own
   refinement files when those land).
   =================================================================== *)

module CombineExtractedWrapper : Pulsar_N1.Pulsar_Threshold = {
  proc round1(sess : Pulsar_N1.session_t,
              share : Pulsar_N1.share_t,
              rho_rnd : Pulsar_N1.randomness_t)
       : Pulsar_N1.round1_t = {
    return witness;
  }

  proc round2(sess : Pulsar_N1.session_t,
              share : Pulsar_N1.share_t,
              round1_aggregate : Pulsar_N1.round1_t list,
              c_tilde : Pulsar_N1.message_t)
       : Pulsar_N1.round2_t = {
    return witness;
  }

  proc combine(group_pk : Pulsar_N1.group_pk_t,
               m : Pulsar_N1.message_t,
               ctx : Pulsar_N1.ctx_t,
               quorum : int list,
               shares : Pulsar_N1.share_t list,
               rho_rnd : Pulsar_N1.randomness_t,
               r1s : Pulsar_N1.round1_t list,
               r2s : Pulsar_N1.round2_t list)
       : Pulsar_N1.signature_t = {
    var enc : Pulsar_N1_Memory.mem_t *
              Pulsar_N1_Combine_Layout.combine_ptrs_t *
              combine_full_args_t;
    var mem_post : Pulsar_N1_Memory.mem_t;
    var sig : Pulsar_N1.signature_t;
    enc <- encode_combine_args group_pk m ctx quorum shares
                               rho_rnd r1s r2s;
    mem_post <- combine_body_fn enc.`1 enc.`2;
    sig <- refine_sig_to_n1
             (Pulsar_N1_Combine_Layout.read_signature_at
                mem_post enc.`2.`Pulsar_N1_Combine_Layout.sig_out_ptr);
    return sig;
  }
}.

(* ===================================================================
   Procedure-level equiv against the abstract CombineAbs.
   =================================================================== *)

(* Procedure-level equiv against CombineAbs — explicit proof.

   Earlier version closed via `smt(combine_wrapper_bridge)`. Per
   the cryptographer review (HIGH-6): SMT close hid whether the
   let-destructured tuple from `encode_combine_args` actually
   unified with `combine_wrapper_bridge`'s universally-quantified
   shape. Replaced with an explicit witness chain: introduce both
   sides' arguments, apply `combine_wrapper_bridge` at the exact
   shape produced by encode_combine_args, and close by rewriting
   the wrapper's three-step body via the bridge identity. *)
lemma combine_wrapper_equiv_CombineAbs :
  equiv [ CombineExtractedWrapper.combine ~ Pulsar_N1.CombineAbs.combine :
            ={arg}
            /\ group_pk{1} = Pulsar_N1.derive_pk
                              (Pulsar_N1.reconstruct quorum{1} shares{1})
            /\ Pulsar_N1.accept_signing_attempt
                 (Pulsar_N1.reconstruct quorum{1} shares{1})
                 m{1} ctx{1} rho_rnd{1}
            /\ uniq quorum{1}
            /\ size shares{1} = size quorum{1}
            /\ Pulsar_N1.poly_degree
                 (Pulsar_N1.reconstruct quorum{1} shares{1}) < size quorum{1}
            /\ shares{1} = List.map
                  (Pulsar_N1.poly_eval
                     (Pulsar_N1.reconstruct quorum{1} shares{1}))
                  quorum{1}
        ==> ={res} ].
proof.
  proc.
  inline Pulsar_N1.CombineAbs.combine Pulsar_N1.FIPS204Sign.sign.
  wp; skip => /> &1 Haccept Huniq Hsize Hdeg Hhonest.
  (* After `=> />` the equational `={...}` and gpk-consistency
     conjuncts are consumed (eq_refl on gpk). The remaining
     hypotheses (accept-path + 4 threshold invariants) are passed
     to combine_wrapper_bridge to discharge the Lean Lagrange
     bridge preconditions in the z-stage derivation. *)
  exact: (combine_wrapper_bridge
            (Pulsar_N1.derive_pk (Pulsar_N1.reconstruct quorum{1} shares{1}))
            m{1} ctx{1} quorum{1}
            shares{1} rho_rnd{1} r1s{1} r2s{1}
            (eq_refl _) Haccept Huniq Hsize Hdeg Hhonest).
qed.

(* ===================================================================
   ACCOUNTING

   axioms (0 — combine_wrapper_bridge is a lemma):
     (none)

   ops:
     derive_c_tilde_wire, derive_t0_wire, derive_r2_msgs_wire
       (abstract wire-type projectors)
     n1_inputs_to_combine_full   (record builder)
     encode_combine_args         (3-tuple — composes adapter +
                                  Layout encoder)

   modules:
     CombineExtractedWrapper : Pulsar_N1.Pulsar_Threshold

   PROVED lemmas:
     combine_wrapper_bridge
     combine_wrapper_equiv_CombineAbs
   =================================================================== *)
