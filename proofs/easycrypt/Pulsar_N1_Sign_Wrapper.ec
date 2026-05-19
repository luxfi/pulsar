(* -------------------------------------------------------------------- *)
(* Pulsar — Class N1 sign wrapper                                      *)
(* -------------------------------------------------------------------- *)
(* Decomplected from Pulsar_N1_Wrapper_Bridge.ec.                       *)
(*                                                                      *)
(* This file owns ONE thing: the sign-side wrapper machinery that lifts *)
(* the extracted libjade M.sign byte-walk into a procedure-level equiv  *)
(* against Pulsar_N1.FIPS204Sign.sign. Specifically:                    *)
(*                                                                      *)
(*   - n1_share_to_layout_sign, n1_msg_to_layout_sign — adapters        *)
(*   - n1_inputs_to_sign_full   — builds sign_full_args_t               *)
(*   - encode_sign_args         — composes adapter + Layout encoder     *)
(*   - sign_wrapper_bridge      — the byte-level wrapper-bridge lemma   *)
(*   - SignExtractedWrapper     — module satisfying MLDSA65_Sign        *)
(*   - sign_wrapper_equiv_FIPS204Sign — procedure-level equiv           *)
(*                                                                      *)
(* The combine-side mirror is Pulsar_N1_Combine_Wrapper.ec. The         *)
(* composition into pulsar_n1_byte_equality_extracted lives in          *)
(* Pulsar_N1_Extracted.ec.                                              *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv Distr DBool DInterval SmtMap.

(* Sign-side refinement: sign_full_args_t, wire_sign_args_of_full,
   refine_sig_to_n1_sign, sign_body_fn, proven sign_body_spec
   lemma + sign_abs_op definition. *)
require import Pulsar_N1_Sign_Refinement.

(* Concrete sign layout: encode_sign_args + encode_sign_args_layout
   aggregate lemma + read_sig_sign. *)
require import Pulsar_N1_Sign_Layout.

(* Memory: shared mem_t used by both layouts. *)
require import Pulsar_N1_Memory.

(* Pulsar_N1: protocol types + MLDSA65_Sign module type +
   FIPS204Sign abstract module + mldsa_sign_op. *)
require import Pulsar_N1.

(* ===================================================================
   Wire derivation ops.

   Project the protocol-level Pulsar_N1 types onto the Sign_Layout
   file's LOCAL abstract wire types. These mirror the combine-side
   `derive_*_wire` ops.

   `n1_share_to_layout_sign` projects the abstract Pulsar_N1
   `share_t` onto the byte-encoded FIPS 204 §3.5.4 sk packing
   (rho || K || tr || s1 || s2 || t0). This is the secret-key
   adapter the threshold wrapper uses when calling libjade.

   `n1_msg_to_layout_sign` projects the abstract Pulsar_N1
   `message_t` onto the libjade-side message byte layout.

   `ctx` and `rho_rnd` do NOT have wire-layer counterparts —
   libjade's M.sign has no ctx/rnd parameters (the threshold
   wrapper handles them BEFORE calling libjade by folding ctx
   into mu and rho_rnd into K-derived randomness). They appear
   only as GHOST fields in `sign_full_args_t` (see the GHOST
   CONTRACT block in Pulsar_N1_Sign_Refinement.ec).
   =================================================================== *)

op n1_share_to_layout_sign :
  Pulsar_N1.share_t   -> Pulsar_N1_Sign_Layout.share_t.

op n1_msg_to_layout_sign :
  Pulsar_N1.message_t -> Pulsar_N1_Sign_Layout.message_t.

(* ===================================================================
   Bundle adapter + concrete encoder.
   =================================================================== *)

op n1_inputs_to_sign_full
   (sk : Pulsar_N1.share_t) (m : Pulsar_N1.message_t)
   (ctx : Pulsar_N1.ctx_t) (rho_rnd : Pulsar_N1.randomness_t)
   : sign_full_args_t =
  {| sgn_wire =
        {| sk_abs = n1_share_to_layout_sign sk;
           m_abs  = n1_msg_to_layout_sign  m; |};
     sgn_sk_n1   = sk;
     sgn_m_n1    = m;
     sgn_ctx_n1  = ctx;
     sgn_rnd_n1  = rho_rnd; |}.

op encode_sign_args
   (sk : Pulsar_N1.share_t) (m : Pulsar_N1.message_t)
   (ctx : Pulsar_N1.ctx_t) (rho_rnd : Pulsar_N1.randomness_t)
   : Pulsar_N1_Memory.mem_t *
     Pulsar_N1_Sign_Layout.sign_ptrs_t *
     sign_full_args_t =
  let full = n1_inputs_to_sign_full sk m ctx rho_rnd in
  let (mem, ptrs) =
    Pulsar_N1_Sign_Layout.encode_sign_args
      full.`sgn_wire.`sk_abs
      full.`sgn_wire.`m_abs
      (Pulsar_N1_Sign_Layout.msg_len full.`sgn_wire.`m_abs) in
  (mem, ptrs, full).

(* ===================================================================
   Sign wrapper bridge — PROVED.

   Mirrors the combine-side proof:
     - encode_sign_args_layout (PROVED in Sign_Layout)
     - sign_body_spec (lemma in Sign_Refinement, derived from
       sign_body_compute_sig_spec axiom)
     - sign_abs_op definition (folds the four ghost fields into
       mldsa_sign_op directly)
   =================================================================== *)

lemma sign_wrapper_bridge :
  forall (sk : Pulsar_N1.share_t)
         (m : Pulsar_N1.message_t)
         (ctx : Pulsar_N1.ctx_t)
         (rho_rnd : Pulsar_N1.randomness_t),
    Pulsar_N1.accept_signing_attempt sk m ctx rho_rnd =>
    let (mem, ptrs, full) = encode_sign_args sk m ctx rho_rnd in
    Pulsar_N1_Sign_Refinement.refine_sig_to_n1_sign
      (Pulsar_N1_Sign_Layout.read_sig_sign
         (Pulsar_N1_Sign_Refinement.sign_body_fn mem ptrs)
         ptrs.`Pulsar_N1_Sign_Layout.ptr_signature)
    = Pulsar_N1.mldsa_sign_op sk m ctx rho_rnd.
proof.
  move=> sk m ctx rho_rnd Haccept /=.
  rewrite /encode_sign_args /=.
  have Hlay :
    Pulsar_N1_Sign_Layout.layout_sign_args
      (Pulsar_N1_Sign_Layout.encode_sign_args
         (n1_share_to_layout_sign sk)
         (n1_msg_to_layout_sign  m)
         (Pulsar_N1_Sign_Layout.msg_len (n1_msg_to_layout_sign m))).`1
      (Pulsar_N1_Sign_Layout.encode_sign_args
         (n1_share_to_layout_sign sk)
         (n1_msg_to_layout_sign  m)
         (Pulsar_N1_Sign_Layout.msg_len (n1_msg_to_layout_sign m))).`2
      (wire_sign_args_of_full
         (n1_inputs_to_sign_full sk m ctx rho_rnd)).
  - rewrite /wire_sign_args_of_full /n1_inputs_to_sign_full /=.
    by apply Pulsar_N1_Sign_Layout.encode_sign_args_layout.
  have Hacc :
    Pulsar_N1.accept_signing_attempt
      (n1_inputs_to_sign_full sk m ctx rho_rnd).`sgn_sk_n1
      (n1_inputs_to_sign_full sk m ctx rho_rnd).`sgn_m_n1
      (n1_inputs_to_sign_full sk m ctx rho_rnd).`sgn_ctx_n1
      (n1_inputs_to_sign_full sk m ctx rho_rnd).`sgn_rnd_n1.
  - by rewrite /n1_inputs_to_sign_full /=.
  have Hspec :=
    Pulsar_N1_Sign_Refinement.sign_body_spec
      (Pulsar_N1_Sign_Layout.encode_sign_args
         (n1_share_to_layout_sign sk)
         (n1_msg_to_layout_sign  m)
         (Pulsar_N1_Sign_Layout.msg_len (n1_msg_to_layout_sign m))).`1
      (Pulsar_N1_Sign_Layout.encode_sign_args
         (n1_share_to_layout_sign sk)
         (n1_msg_to_layout_sign  m)
         (Pulsar_N1_Sign_Layout.msg_len (n1_msg_to_layout_sign m))).`2
      (n1_inputs_to_sign_full sk m ctx rho_rnd)
      Hlay Hacc.
  move: Hspec.
  rewrite /Pulsar_N1_Sign_Refinement.sign_abs_op
          /n1_inputs_to_sign_full /=.
  by rewrite /Pulsar_N1.mldsa_sign_op /=; move=> ->.
qed.

(* ===================================================================
   Concrete extracted-wrapper module.
   =================================================================== *)

module SignExtractedWrapper : Pulsar_N1.MLDSA65_Sign = {
  proc sign(sk : Pulsar_N1.share_t,
            m : Pulsar_N1.message_t,
            ctx : Pulsar_N1.ctx_t,
            rho_rnd : Pulsar_N1.randomness_t)
       : Pulsar_N1.signature_t = {
    var enc : Pulsar_N1_Memory.mem_t *
              Pulsar_N1_Sign_Layout.sign_ptrs_t *
              sign_full_args_t;
    var mem_post : Pulsar_N1_Memory.mem_t;
    var sig : Pulsar_N1.signature_t;
    enc <- encode_sign_args sk m ctx rho_rnd;
    mem_post <- Pulsar_N1_Sign_Refinement.sign_body_fn enc.`1 enc.`2;
    sig <- Pulsar_N1_Sign_Refinement.refine_sig_to_n1_sign
             (Pulsar_N1_Sign_Layout.read_sig_sign
                mem_post
                enc.`2.`Pulsar_N1_Sign_Layout.ptr_signature);
    return sig;
  }
}.

(* ===================================================================
   Procedure-level equiv against the abstract FIPS204Sign.
   =================================================================== *)

lemma sign_wrapper_equiv_FIPS204Sign :
  equiv [ SignExtractedWrapper.sign ~ Pulsar_N1.FIPS204Sign.sign :
            ={arg}
            /\ Pulsar_N1.accept_signing_attempt
                 sk{1} m{1} ctx{1} rho_rnd{1}
        ==> ={res} ].
proof.
  proc.
  inline Pulsar_N1.FIPS204Sign.sign.
  wp; skip => />.
  move=> &1 Haccept.
  exact: (sign_wrapper_bridge sk{1} m{1} ctx{1} rho_rnd{1} Haccept).
qed.

(* ===================================================================
   ACCOUNTING

   axioms (0 — sign_wrapper_bridge is a lemma):
     (none)

   ops:
     n1_share_to_layout_sign, n1_msg_to_layout_sign
       (abstract wire-type projectors)
     n1_inputs_to_sign_full   (record builder)
     encode_sign_args         (3-tuple — composes adapter +
                               Layout encoder)

   modules:
     SignExtractedWrapper : Pulsar_N1.MLDSA65_Sign

   PROVED lemmas:
     sign_wrapper_bridge
     sign_wrapper_equiv_FIPS204Sign
   =================================================================== *)
