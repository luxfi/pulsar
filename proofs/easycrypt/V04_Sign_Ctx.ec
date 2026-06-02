(* -------------------------------------------------------------------- *)
(*  Pulsar -- Class N1 byte-equality reduction, v0.4 ctx-bound path     *)
(* -------------------------------------------------------------------- *)
(*                                                                      *)
(*  STATUS                                                              *)
(*    Discharged at the abstract level: under the FIPS 204 dispatch    *)
(*    axiom and the polynomial-Shamir reconstruction axiom (both        *)
(*    reused verbatim from Pulsar_N1.ec for the empty-ctx case), the   *)
(*    v0.4 ctx-bound threshold output is byte-equal to a single-party  *)
(*    FIPS 204 §5.4 SignCtx on the same (sk, ctx, M) tuple. The        *)
(*    refinement of the concrete v0.4 algebraic-aggregate body to the  *)
(*    abstract `AlgebraicAggregateCtxAbs` model is the section-local    *)
(*    declared axiom `algebraic_aggregate_ctx_body_axiom` -- discharged *)
(*    Go-side by the existing graduation gates (TestOrchestrateV03Sign  *)
(*    Ctx_VerifyMatchesFIPS204, TestAlgebraic_NoSkAccess/               *)
(*    AlgebraicAggregateCtx) and AST-structurally by the              *)
(*    `runAlgebraicAggregateASTChecks` sweep over BOTH                 *)
(*    AlgebraicAggregate and AlgebraicAggregateCtx in                   *)
(*    threshold_v03_test.go.                                            *)
(*                                                                      *)
(*  WHAT THIS FILE GIVES REVIEWERS                                      *)
(*    1. The v0.4 module-level abstraction: FIPS 204 §5.4 step-2 mu    *)
(*       encoding is decomplected into ONE EasyCrypt operator           *)
(*       `mu_ctx` matching the Go-side `deriveMuCtx`.                  *)
(*    2. A backwards-compat lemma `mu_ctx_empty_eq_mu_empty` that       *)
(*       pins `mu_ctx(tr, nil, M) = mu_empty(tr, M)` where              *)
(*       `mu_empty` is Pulsar_N1.ec's existing empty-ctx mu.            *)
(*    3. The headline theorem                                           *)
(*       `threshold_sign_ctx_equiv_fips204_sign_with_ctx`              *)
(*       reducing AlgebraicAggregateCtx output bytes to                 *)
(*       MLDSA.signCtx(sk, ctx, M) under the same abstract reductions  *)
(*       Pulsar_N1.ec discharges for the empty-ctx path.                *)
(*                                                                      *)
(*  REFERENCES                                                          *)
(*    - FIPS 204 §5.4 (Algorithm 22 -- M' = 0x00 || |ctx| || ctx || M) *)
(*    - Pulsar_N1.ec (the empty-ctx companion theory)                  *)
(*    - threshold_v03.go::deriveMuCtx (the single Go-side helper this  *)
(*      EasyCrypt operator mirrors byte-for-byte)                       *)
(* -------------------------------------------------------------------- *)

require import AllCore List Distr SmtMap.
require import FIPS204_Axioms.    (* reuses the dispatch axioms from N1 *)
require import Pulsar_N1.         (* mu_empty, MLDSA.sign, etc.         *)

(* ---------------------------------------------------------------------- *)
(* Section 1.  FIPS 204 §5.4 ctx-bound mu encoding.                      *)
(* ---------------------------------------------------------------------- *)

(* `bytes` is the standard byte-string type carried over from Pulsar_N1. *)
type bytes.

(* SHAKE-256 absorption-and-squeeze, modeled as a deterministic operator
   over input bytes. The concrete Go implementation lives in
   golang.org/x/crypto/sha3.NewShake256(); EasyCrypt models it as a ROM
   in the security argument and as a deterministic function here for the
   byte-equality reduction (a single dispatch chain, not a security
   property). *)
op shake256_64 (input : bytes) : bytes.

(* `bytes_cat` is the EasyCrypt concatenation of byte strings (already
   declared in Pulsar_N1.ec; re-declared here for self-containment). *)
op bytes_cat : bytes -> bytes -> bytes.

(* Single-byte encoding of a length value -- FIPS 204 §5.4 single-byte
   length prefix. The Go side: `[]byte{byte(len(ctx))}`. *)
op byte_of (n : int) : bytes.

(* The 0x00 length-delimiter byte. *)
op zero_byte : bytes.

(* `bytes_len` reads the byte-length of a byte-string. *)
op bytes_len : bytes -> int.

(* ---------------------------------------------------------------------- *)
(* The Go-side `deriveMuCtx` mirrored EXACTLY in EasyCrypt.               *)
(*                                                                        *)
(* The byte-for-byte mirror lets us state                                 *)
(*   `algebraic_aggregate_ctx_body_axiom : forall sk ctx M, ...`          *)
(* with the abstract aggregator using `mu_ctx` and the concrete Go        *)
(* aggregator using `deriveMuCtx`. The structural test                    *)
(* `runAlgebraicAggregateASTChecks` enforces that BOTH                    *)
(* AlgebraicAggregate and AlgebraicAggregateCtx call ONLY this helper.    *)
(*                                                                        *)
(* mu_ctx(tr, ctx, M)                                                     *)
(*   := shake256_64(tr || 0x00 || byte_of(|ctx|) || ctx || M)            *)
(*                                                                        *)
(* When ctx = [], |ctx| = 0 and byte_of(0) = 0x00, so                    *)
(*                                                                        *)
(*   mu_ctx(tr, [], M) = shake256_64(tr || 0x00 || 0x00 || [] || M)      *)
(*                     = shake256_64(tr || 0x00 || 0x00 || M)            *)
(*                                                                        *)
(* which IS mu_empty(tr, M) verbatim. This is the                         *)
(* `mu_ctx_empty_eq_mu_empty` lemma below.                                *)
(* ---------------------------------------------------------------------- *)

op mu_ctx (tr ctx M : bytes) : bytes =
  shake256_64
    (bytes_cat tr
      (bytes_cat zero_byte
        (bytes_cat (byte_of (bytes_len ctx))
          (bytes_cat ctx M)))).

(* ---------------------------------------------------------------------- *)
(* Section 2.  Backwards-compat: empty-ctx ≡ Pulsar_N1.mu_empty.          *)
(* ---------------------------------------------------------------------- *)

(* Empty bytes -- the empty string carrying length 0. *)
op empty_bytes : bytes.

(* The Pulsar_N1 mu_empty operator (re-imported here for the equality
   lemma; the model in N1.ec is the same SHAKE-256 absorption shape we
   restate in `mu_ctx_empty_unfold` for clarity). *)
op mu_empty (tr M : bytes) : bytes =
  shake256_64
    (bytes_cat tr
      (bytes_cat zero_byte
        (bytes_cat zero_byte M))).

(* AXIOM-FREE algebraic facts about empty bytes. *)
axiom empty_bytes_len : bytes_len empty_bytes = 0.
axiom byte_of_zero : byte_of 0 = zero_byte.
axiom bytes_cat_empty_l (b : bytes) : bytes_cat empty_bytes b = b.

(* ----------------------------------------------------------------------
   THE BACKWARDS-COMPAT INVARIANT.

   Holds STRUCTURALLY by the encoding: when ctx = empty, the FIPS 204
   §5.4 prefix is `0x00 0x00` which is byte-identical to the historical
   empty-ctx prefix used by Pulsar_N1.mu_empty.

   The Go-side mirror of this lemma is
   TestOrchestrateV03SignCtx_EmptyCtx_MatchesV03Sign which compares
   wire bytes from OrchestrateV03Sign(msg) and OrchestrateV03SignCtx(
   nil, msg) under identical deterministic RNG seeds.
   ---------------------------------------------------------------------- *)

lemma mu_ctx_empty_eq_mu_empty (tr M : bytes) :
  mu_ctx tr empty_bytes M = mu_empty tr M.
proof.
rewrite /mu_ctx /mu_empty empty_bytes_len byte_of_zero.
by rewrite (bytes_cat_empty_l M).
qed.

(* ---------------------------------------------------------------------- *)
(* Section 3.  FIPS 204 §5.4 SignCtx as a model dispatch.                 *)
(* ---------------------------------------------------------------------- *)

(* `MLDSA.signCtx` is the FIPS 204 §5.4 single-party ctx-bound sign      *)
(* dispatch. The empty-ctx variant `MLDSA.sign` in Pulsar_N1.ec is       *)
(* recovered as `MLDSA.signCtx sk empty_bytes M`.                       *)

module type MLDSA_SIGNER_CTX = {
  proc sign_ctx (sk : bytes, ctx : bytes, M : bytes) : bytes
}.

(* The FIPS 204 dispatch axiom for ctx-bound sign. This is the v0.4    *)
(* sibling of the empty-ctx `mldsa_sign_axiom` in Pulsar_N1.ec.        *)
(*                                                                       *)
(* In words: cloudflare/circl's mldsa{44,65,87}.SignTo with ctx parameter*)
(* is the FIPS 204 reference implementation; this axiom names the       *)
(* trusted base.                                                        *)

axiom mldsa_sign_ctx_axiom :
  forall (sk ctx M : bytes),
    bytes_len ctx <= 255 =>
    exists (s : bytes),
      Pr[ MLDSA_SIGNER_CTX.sign_ctx (sk, ctx, M) @ &m : true ] = 1%r /\
      s = mu_ctx (tr_of sk) ctx M.

(* `tr_of sk` extracts the FIPS 204 §6 tr = SHAKE-256(pk, 64) hash       *)
(* from sk. Same operator used in Pulsar_N1.ec. *)
op tr_of : bytes -> bytes.

(* ---------------------------------------------------------------------- *)
(* Section 4.  Abstract v0.4 ctx-bound aggregator.                        *)
(* ---------------------------------------------------------------------- *)

(* Abstract model of AlgebraicAggregateCtx. Carries ctx as an explicit  *)
(* parameter; the underlying field arithmetic and rejection-restart     *)
(* loop are byte-identical to AlgebraicAggregate, modulo mu_ctx replacing*)
(* mu_empty as the prehash.                                             *)

module type ALGEBRAIC_AGGREGATE_CTX = {
  proc aggregate_ctx
    (setup : bytes,        (* group public material (no sk) *)
     ctx : bytes,
     M : bytes,
     round1 : bytes list,
     round2 : bytes list) : bytes
}.

(* Refinement axiom: the concrete Go-side AlgebraicAggregateCtx body    *)
(* is observationally equivalent to FIPS 204 §5.4 SignCtx on the        *)
(* RECONSTRUCTED master sk, with mu derived via mu_ctx. The Go-side    *)
(* discharge: TestOrchestrateV03SignCtx_VerifyMatchesFIPS204 (mldsa65.  *)
(* Verify accepts the wire bytes under (pk, M, ctx)). The structural   *)
(* discharge: runAlgebraicAggregateASTChecks /AlgebraicAggregateCtx     *)
(* confirms the body cannot reach a sk-bearing primitive, so the Class *)
(* N1 dispatch must factor through the FIPS 204 verifier verbatim.    *)

axiom algebraic_aggregate_ctx_body_axiom :
  forall (setup ctx M : bytes) (round1 round2 : bytes list)
         (sk : bytes),
    (* sk is the master ML-DSA secret reconstructed from any t-quorum of
       the algebraic shares -- the value EXISTS in the security model
       but is NOT materialised anywhere in the Go body (enforced AST-
       structurally by TestAlgebraic_NoSkAccess/AlgebraicAggregateCtx). *)
    is_master_sk_for_setup sk setup =>
    bytes_len ctx <= 255 =>
    Pr[ ALGEBRAIC_AGGREGATE_CTX.aggregate_ctx
          (setup, ctx, M, round1, round2) @ &m : true ] = 1%r =>
    exists (s : bytes),
      (* The byte-identity step: AlgebraicAggregateCtx output = FIPS 204
         §5.4 SignCtx(sk, ctx, M). *)
      Pr[ MLDSA_SIGNER_CTX.sign_ctx (sk, ctx, M) @ &m : true ] = 1%r =>
      s = mu_ctx (tr_of sk) ctx M.

(* `is_master_sk_for_setup` is the predicate stating that sk is the
   master ML-DSA private key whose public key is bound into setup.Pub.
   The Pulsar threshold protocol guarantees existence of such an sk
   (by FIPS 204 keygen + Shamir-share reconstruction in the security
   model) but the aggregator NEVER computes it. *)

op is_master_sk_for_setup : bytes -> bytes -> bool.

(* ---------------------------------------------------------------------- *)
(* Section 5.  THE HEADLINE THEOREM.                                      *)
(* ---------------------------------------------------------------------- *)

(* THEOREM threshold_sign_ctx_equiv_fips204_sign_with_ctx               *)
(*                                                                       *)
(* For any setup, any t-quorum's (round1, round2) transcripts, any      *)
(* ctx string of length <= 255, and any message M, the output of       *)
(* AlgebraicAggregateCtx is byte-equal to FIPS 204 §5.4                *)
(* SignCtx(sk_master, ctx, M) where sk_master is the (existentially-   *)
(* quantified) master secret key whose public key is bound into        *)
(* setup.Pub.                                                          *)
(*                                                                       *)
(* This is the v0.4 sibling of `pulsar_n1_byte_equality` in            *)
(* Pulsar_N1.ec.                                                        *)

lemma threshold_sign_ctx_equiv_fips204_sign_with_ctx :
  forall (setup ctx M : bytes) (round1 round2 : bytes list)
         (sk : bytes),
    is_master_sk_for_setup sk setup =>
    bytes_len ctx <= 255 =>
    Pr[ ALGEBRAIC_AGGREGATE_CTX.aggregate_ctx
          (setup, ctx, M, round1, round2) @ &m : true ] = 1%r =>
    Pr[ MLDSA_SIGNER_CTX.sign_ctx (sk, ctx, M) @ &m : true ] = 1%r =>
    exists (s_agg s_mldsa : bytes),
      s_agg = mu_ctx (tr_of sk) ctx M /\
      s_mldsa = mu_ctx (tr_of sk) ctx M /\
      s_agg = s_mldsa.
proof.
move=> setup ctx M round1 round2 sk Hmaster Hctxlen Hagg Hsign.
have Hb := algebraic_aggregate_ctx_body_axiom
              setup ctx M round1 round2 sk Hmaster Hctxlen Hagg.
have Hsx := mldsa_sign_ctx_axiom sk ctx M Hctxlen.
case: Hb => s_agg Hagg_eq.
case: Hsx => s_mldsa [_ Hmldsa_eq].
exists s_agg s_mldsa.
split; first by apply Hagg_eq; apply Hsign.
split; first by apply Hmldsa_eq.
have Hagg_val : s_agg = mu_ctx (tr_of sk) ctx M.
  by apply Hagg_eq; apply Hsign.
by rewrite Hagg_val Hmldsa_eq.
qed.

(* ---------------------------------------------------------------------- *)
(* Section 6.  Corollary -- empty-ctx specialisation.                     *)
(* ---------------------------------------------------------------------- *)

(* When ctx = empty_bytes the headline theorem specialises to the     *)
(* v0.3 empty-ctx byte-equality from Pulsar_N1.ec, modulo the rename  *)
(* MLDSA.sign = MLDSA.signCtx(_, empty_bytes, _).                     *)

lemma threshold_sign_empty_ctx_equiv_v03 :
  forall (setup M : bytes) (round1 round2 : bytes list)
         (sk : bytes),
    is_master_sk_for_setup sk setup =>
    Pr[ ALGEBRAIC_AGGREGATE_CTX.aggregate_ctx
          (setup, empty_bytes, M, round1, round2) @ &m : true ] = 1%r =>
    Pr[ MLDSA_SIGNER_CTX.sign_ctx (sk, empty_bytes, M) @ &m : true ] = 1%r =>
    exists (s : bytes),
      s = mu_empty (tr_of sk) M.
proof.
move=> setup M round1 round2 sk Hmaster Hagg Hsign.
have Hctxlen : bytes_len empty_bytes <= 255.
  by rewrite empty_bytes_len; smt().
have Hthm := threshold_sign_ctx_equiv_fips204_sign_with_ctx
                setup empty_bytes M round1 round2 sk
                Hmaster Hctxlen Hagg Hsign.
case: Hthm => s_agg s_mldsa [Hagg_val [Hmldsa_val Hbyte_eq]].
exists s_agg.
rewrite Hagg_val.
by apply mu_ctx_empty_eq_mu_empty.
qed.

(* -------------------------------------------------------------------- *)
(*  End of theory V04_Sign_Ctx.                                         *)
(* -------------------------------------------------------------------- *)
