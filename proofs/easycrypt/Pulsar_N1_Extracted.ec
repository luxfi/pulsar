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

   Trust boundary of this corollary — 22 named axioms total
   (17 narrow implementation-refinement + 5 Lean-bridged algebraic),
   each with file:line. Authoritative enumeration:
   docs/proof-axiom-inventory.md.

   Implementation-refinement axioms (17):
     - 1 stage-level byte-walk
         sign_body_z_spec
       The h-stage on both sides and the combine z-stage are
       derived lemmas through `make_hint_of_w` and the Lean
       Lagrange bridge respectively.
     - 2 combine z-stage extraction sub-axioms (v8)
         combine_body_z_via_aggregation_spec  (structural shape)
         combine_body_partial_responses_spec  (per-party byte-walk)
     - 4 w-stage matrix_a / mask_y sub-axioms (v12)
         {combine,sign}_body_matrix_a_spec
         {combine,sign}_body_mask_y_spec
       `*_body_w_spec` are derived lemmas through `central_w`.
     - 2 w_low sub-axioms (h-stage; v10)
         {combine,sign}_body_w_low_spec
       `*_body_h_spec` are derived lemmas through `make_hint_of_w`.
     - 4 FIPS 204 §5.4.1 ExternalMu codec-layout axioms (v9)
         combine: 3 per-range sub-axioms over the protocol-witness
           buffer (`combine_body_mu_input_{prefix,ctx_bytes,m_bytes}_spec`)
         sign:    1 collapsed `sign_layout_m_buffer_external_mu`
                  (sign owns m_ptr / ctx_ptr in its layout)
       `*_body_mu_spec` are derived through `shake256_to_mu`.
     - 1 codec roundtrip axiom in Pulsar_N1
         pack_unpack_n1_signature_roundtrip
       Pack-injectivity is a derived lemma
       (pack_n1_signature_injective).
     - 2 honest-execution no-reject post-conditions
         {combine,sign}_no_reject_on_accepted_honest_layout
       Each conditions `status = 0` on the protocol-level
       `accept_signing_attempt` predicate; the kappa-loop
       probability bound `mldsa_accept_lower_bound` tracks the
       acceptance probability operationally per FIPS 204.

   Lean-bridged algebraic axioms (5):
     lagrange_inverse_eval, reconstruct_linear, shamir_correct,
     add_share_zeroR, threshold_partial_response_identity.
     See proofs/lean-easycrypt-bridge.md; CI guard
     scripts/check-lean-bridge.sh.

   Trust footprint structurally outside the corollary cone:
     - 0 ABI bridge identity axioms in either wrapper file
       (both wrapper bridges are lemmas).
     - 0 module-contract axioms (combine_body_axiom /
       S_functional_spec are section-local inside Pulsar_N1;
       this corollary instantiates the generic theorem with the
       concrete wrapper modules + bridge lemmas, NOT via the
       section's declare-axiom hypotheses).
     - ~21 per-type FIPS 204 codec round-trips across
       Pulsar_N1_Sign_Layout / Pulsar_N1_Combine_Layout /
       Pulsar_N1_Signature_Codec / Pulsar_N1 — encode/decode
       pairs with wf_* well-formedness predicates.
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
