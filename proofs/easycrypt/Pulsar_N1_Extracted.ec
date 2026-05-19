(* -------------------------------------------------------------------- *)
(* Pulsar — Class N1 extracted byte-equality corollary                 *)
(* -------------------------------------------------------------------- *)
(* Decomplected from Pulsar_N1_Wrapper_Bridge.ec.                       *)
(*                                                                      *)
(* This file owns ONE thing: the concrete extracted N1 byte-equality    *)
(* theorem. Composes the combine-side and sign-side wrapper modules     *)
(* (each defined in its own per-side wrapper file) and instantiates     *)
(* the generic `Pulsar_N1.pulsar_n1_byte_equality` theorem with the     *)
(* equivalence hypotheses from each side's wrapper-bridge lemma.        *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv Distr DBool DInterval SmtMap.

(* The two per-side wrapper files. Each provides its extracted-
   wrapper module + the procedure-level equiv against the
   corresponding abstract module (CombineAbs / FIPS204Sign). *)
require import Pulsar_N1_Combine_Wrapper.
require import Pulsar_N1_Sign_Wrapper.

(* Pulsar_N1 provides the generic byte-equality theorem
   `pulsar_n1_byte_equality` (proven inside `section ClassN1`,
   parametric on abstract T : Pulsar_Threshold + S : MLDSA65_Sign
   + the two declare-axiom equivalences combine_body_axiom /
   S_functional_spec). After section closure, it's exported as a
   universally-quantified lemma over (S, T, equiv-on-T.combine,
   equiv-on-S.sign). We supply concrete wrappers + bridge-lemma
   equivs here. *)
require import Pulsar_N1.

(* ===================================================================
   The concrete extracted N1 byte-equality corollary.

   Trust boundary of this corollary (v7):
     - 3 stage-level byte-walk axioms in the refinement files
       (combine z-stage moved to Lean bridge in v8):
         combine_body_h_spec  (MakeHint stage      — roadmap S7)
         sign_body_z_spec, sign_body_h_spec
     - 2 narrow combine z-stage axioms (v8):
         combine_body_z_via_aggregation_spec  (structural shape)
         combine_body_partial_responses_spec  (per-party byte-walk)
     - 2 c_tilde-stage sub-axioms (NARROW, w only — w1 sub-stage
       decomposed in v7 via HighBits structural split):
         combine_body_w_spec, sign_body_w_spec
       The w-stage axioms constrain the polynomial vector w BEFORE
       HighBits/decompose. Compose with the structural
       `high_bits_of_w` op (shared on both sides) to derive
       `*_body_w1_spec` lemmas, then with the derived `*_body_mu_spec`
       lemmas (v6) under the structural `shake_mu_w1` composition
       (v5) to derive `*_body_c_tilde_spec` lemmas.
     - 2 FIPS 204 §5.4.1 ExternalMu byte-layout axioms (v6, NARROW;
       classified under codec layouts, not byte-walks):
         combine_body_mu_input_spec, sign_body_mu_input_spec
       Each asserts the extracted SHAKE-input buffer matches the
       FIPS 204 byte layout for (m, ctx) — pure byte-layout claim,
       no SHAKE semantics. Compose via the structural
       `shake256_to_mu` op to give the derived `*_body_mu_spec`
       lemmas.
     - 1 codec roundtrip axiom in Pulsar_N1
         pack_unpack_n1_signature_roundtrip
       Slots into the FIPS 204 codec round-trip category.
       Pack-injectivity is a derived lemma
       (pack_n1_signature_injective), not an axiom.
     - 0 ABI bridge identity axioms in either wrapper file
       (both wrapper bridges are lemmas).
     - 0 module-contract axioms in scope here
       (combine_body_axiom / S_functional_spec are
        section-local inside Pulsar_N1; this corollary
        does NOT depend on them, instead using the
        wrapper-bridge equivs which are real lemmas).
     - 5 Lean-bridged algebraic axioms (Lagrange/Shamir +
       threshold_partial_response_identity (v8);
       see proofs/lean-easycrypt-bridge.md).

   Headline trust footprint:
     Was (v4): 6 stage-level byte-walks
     Was (v5): 4 stage-level + 4 c_tilde dep sub-stage (mu + w1)
     Was (v6): 4 stage-level + 2 c_tilde dep sub-stage (w1)
             + 2 codec layout (mu_input)
     Was (v7): 4 stage-level + 2 c_tilde dep sub-stage (w)
             + 2 codec layout
     Now (v8): 3 stage-level (sign z + combine/sign h)
             + 2 combine z extraction (v8 — aggregation shape + PR)
             + 2 c_tilde dep sub-stage (w only)
             + 2 codec layout (mu_input)
             + 5 Lean-bridged algebraic (+1 in v8)
     Continued axiom decomposition. `combine_body_z_spec` (v8),
     `*_body_w1_spec` (v7), `*_body_mu_spec` (v6), and
     `*_body_c_tilde_spec` (v5) are all derived lemmas now. The
     remaining axioms are narrower than what they replaced but
     remain axiomatic (NOT full mechanized closure).
   =================================================================== *)

lemma pulsar_n1_byte_equality_extracted :
  equiv [
    Pulsar_N1.ThresholdRun(CombineExtractedWrapper).run
    ~ Pulsar_N1.SinglePartyRun(SignExtractedWrapper).run :
        ={group_pk, shares, quorum, m, ctx, rho_rnd}
      /\ uniq quorum{1}
      /\ size shares{1} = size quorum{1}
      /\ group_pk{1} = Pulsar_N1.derive_pk
                        (Pulsar_N1.reconstruct quorum{1} shares{1})
      /\ Pulsar_N1.accept_signing_attempt
           (Pulsar_N1.reconstruct quorum{1} shares{1})
           m{1} ctx{1} rho_rnd{1}
      /\ Pulsar_N1.poly_degree
           (Pulsar_N1.reconstruct quorum{1} shares{1}) < size quorum{1}
      /\ shares{1} = List.map
           (Pulsar_N1.poly_eval
              (Pulsar_N1.reconstruct quorum{1} shares{1}))
           quorum{1}
    ==> ={res}
  ].
proof.
  apply (Pulsar_N1.pulsar_n1_byte_equality
           SignExtractedWrapper CombineExtractedWrapper
           combine_wrapper_equiv_CombineAbs
           sign_wrapper_equiv_FIPS204Sign).
qed.

(* ===================================================================
   ACCOUNTING

   axioms (0):
     (none)

   PROVED lemmas:
     pulsar_n1_byte_equality_extracted

   The two byte-walk obligations are owned by the refinement
   files. The four Lean-bridged algebraic axioms are owned by
   Pulsar_N1.ec (lagrange_inverse_eval) and Pulsar_N4.ec
   (add_share_zeroR, reconstruct_linear, shamir_correct).

   See proofs/lean-easycrypt-bridge.md for the algebraic-bridge
   correspondence and proofs/easycrypt/extraction/
   {combine,sign}-byte-walk-roadmap.md for the remaining byte-
   walk obligations.
   =================================================================== *)
