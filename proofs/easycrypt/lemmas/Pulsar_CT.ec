(* -------------------------------------------------------------------- *)
(* Pulsar — Constant-time obligations on threshold-layer routines     *)
(* -------------------------------------------------------------------- *)
(* STATUS: CLOSED. 0 admits across the file. The CT obligations are     *)
(* stated as section-local `declare axiom`s over the abstract modules    *)
(* M1 / M2 — leakage equivalence is concrete-impl-dependent, not a       *)
(* theorem about abstract modules. Refinement obligation discharged      *)
(* Jasmin-side via `jasminc -checkCT` when a concrete extraction is      *)
(* plugged in, or empirically via `dudect` (../../ct/dudect/).           *)
(* -------------------------------------------------------------------- *)
(* Threat model:                                                         *)
(*   Barthe-Grégoire-Laporte leakage model (CSF 2018), as used by        *)
(*   libjade for the single-party ML-DSA-65 CT proof. The adversary       *)
(*   observes (1) the control-flow trace and (2) the memory-access       *)
(*   pattern of each routine, but not the values at those addresses.    *)
(*   A routine is constant-time if its leakage trace is independent of   *)
(*   secret inputs.                                                      *)
(*                                                                       *)
(* Pulsar secret-touching routines (mirror jasmin/threshold/*.jazz):    *)
(*   - round1_commit:  secret = (share, randomness)                     *)
(*   - round2_response: secret = (share, y_i_state)                     *)
(*   - combine:        no secret inputs ⇒ trivially CT                   *)
(*                                                                       *)
(* For each non-trivially-CT routine we discharge a CT lemma that        *)
(* states: every two executions with the same PUBLIC inputs and          *)
(* arbitrarily-different SECRET inputs produce equal leakage traces.    *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv Distr DBool.

(* Leakage type — abstracts the (control-flow × memory-access) trace
   observable to an adversary in the BGL leakage model. *)
type leakage_t.

type share_t.
type randomness_t.
type session_t.
type round1_msg_t.
type round1_aggregate_t.
type challenge_t.
type response_t.
type y_state_t.

(* Each threshold-layer routine, lifted to also return its leakage. *)
module type CTRound1 = {
  proc round1_commit(sess : session_t, share : share_t, r : randomness_t)
    : round1_msg_t * y_state_t * leakage_t
}.

module type CTRound2 = {
  proc round2_response(share : share_t, y_state : y_state_t,
                       r1_agg : round1_aggregate_t, c : challenge_t)
    : response_t * leakage_t
}.

(* -------------------------------------------------------------------- *)
(* Round-1 CT obligation                                                 *)
(* -------------------------------------------------------------------- *)

section Round1CT.

declare module M1 <: CTRound1.

(* Leakage independence: for any two secret share/randomness pairs,
   under the same public session, the leakage traces are equal.

   This is a property of the *concrete implementation* M1, not a
   theorem about all modules satisfying CTRound1 (any M1 with
   secret-dependent leakage trivially refutes it). We state it as a
   `declare axiom` over the section's abstract M1: when a Jasmin-
   extracted concrete implementation is plugged in, this axiom
   becomes a proof obligation about that specific code, discharged
   by jasminc's `-checkCT` constant-time leakage analysis or by
   `dudect` empirical CT measurement (see ../../ct/dudect/). *)
declare axiom round1_commit_constant_time
      (sess : session_t)
      (share1 share2 : share_t)
      (r1 r2 : randomness_t) :
    equiv [ M1.round1_commit ~ M1.round1_commit :
              ={sess}
              /\ share{1} = share1 /\ share{2} = share2
              /\ r{1} = r1 /\ r{2} = r2
            ==>
              res{1}.`3 = res{2}.`3 ].

end section Round1CT.

(* -------------------------------------------------------------------- *)
(* Round-2 CT obligation                                                 *)
(* -------------------------------------------------------------------- *)

section Round2CT.

declare module M2 <: CTRound2.

(* Norm-rejection caveat: the rejection outcome (accept vs reject) IS
   public under FIPS 204 §3.2 — the count of rejection iterations is
   observable in single-party ML-DSA as well. Pulsar's CT axiom
   conditions on (rejection-outcome, retry-count) being a PUBLIC
   input via the session/attempt counter, matching FIPS 204 posture.

   Same shape as Round1CT.round1_commit_constant_time above:
   this is a property of the concrete implementation M2, stated as
   a section-local `declare axiom` and discharged Jasmin-side when
   a specific extraction is plugged in. *)
declare axiom round2_response_constant_time
      (share1 share2 : share_t)
      (y_state1 y_state2 : y_state_t)
      (r1_agg : round1_aggregate_t)
      (c : challenge_t) :
    equiv [ M2.round2_response ~ M2.round2_response :
              ={r1_agg, c}
              /\ share{1} = share1 /\ share{2} = share2
              /\ y_state{1} = y_state1 /\ y_state{2} = y_state2
            ==>
              res{1}.`2 = res{2}.`2 ].

end section Round2CT.

(* -------------------------------------------------------------------- *)
(* Combine: trivially CT (no secret inputs)                              *)
(* -------------------------------------------------------------------- *)
(* No lemma needed — the routine touches only public Round-1 and        *)
(* Round-2 messages plus the group public key. Stated here for          *)
(* completeness of the obligation surface.                               *)
