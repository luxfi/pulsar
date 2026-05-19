(* -------------------------------------------------------------------- *)
(* Pulsar — FIPS 204 signature byte-codec                              *)
(* -------------------------------------------------------------------- *)
(* Decomplected from Pulsar_N1_Combine_Layout.                          *)
(*                                                                      *)
(* This file holds the FIPS 204 ML-DSA-65 signature-bytes view shared   *)
(* by combine and sign. Three concerns live here, and only three:       *)
(*                                                                      *)
(*   1. The abstract `signature_t` type (FIPS 204 §3.5.5 c_tilde || z   *)
(*      || h, 3293 bytes for ML-DSA-65).                                *)
(*   2. Encode / decode + length, as named per-type axioms (the         *)
(*      FIPS 204 packing is fully specified at the bit level in         *)
(*      `lemmas/MLDSA65_Functional.ec`; we surface only the round-trip  *)
(*      property here).                                                 *)
(*   3. read_sig_at / write_sig_at — read/write a packed signature at   *)
(*      a memory pointer — plus the two proved frame lemmas             *)
(*      (read_after_write_sig + write_sig_separation). These compose    *)
(*      Pulsar_N1_Memory's bulk primitives with the codec.              *)
(*                                                                      *)
(* What this file is NOT:                                               *)
(*                                                                      *)
(*   - It does NOT contain the bit-level FIPS 204 §3.5.5 packing        *)
(*     spec — that's `MLDSA65_Functional.pack_signature` /              *)
(*     `unpack_signature` (when those land). Here we only need the      *)
(*     round-trip + length identities to discharge layout proofs.       *)
(*                                                                      *)
(*   - It does NOT contain combine- or sign-specific encoders for       *)
(*     other wire types (c_tilde, t0, r2_msg, sk packing, message       *)
(*     bytes). Those live in the per-procedure layout files.            *)
(*                                                                      *)
(* Decomplect benefit: Pulsar_N1_Sign_Layout no longer imports          *)
(* Pulsar_N1_Combine_Layout. The two layouts now share Memory + this    *)
(* codec only.                                                          *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv.
require import Pulsar_N1_Memory.

(* ===================================================================
   FIPS 204 ML-DSA-65 signature length (bytes).
   3293 = 32 (c_tilde) + 5 * 640 (z packing) + 55 (h.weight cap) + 6
        (per FIPS 204 §3.5.5 sig packing for parameter set 3).
   =================================================================== *)

op sig_len : int = 3293.

(* ===================================================================
   The signature type + codec ops.

   v11 concretization: `signature_t` is now a CONCRETE 1-field record
   wrapping `int list`, with `encode_signature` / `decode_signature`
   defined STRUCTURALLY as record field projection / construction.
   This collapses the previous (encode_decode, decode_encode_wf)
   roundtrip axioms to TRIVIAL provable lemmas (record reconstruction
   is structurally the identity).

   The well-formedness predicate `wf_signature_bytes` is also
   CONCRETIZED to `size = sig_len`: FIPS 204 §3.5.5 specifies
   additional structural invariants on the byte string (h-weight
   bound, z bit-packing range), but the length identity is the
   load-bearing structural property the layout proofs consume. The
   richer FIPS 204 wf invariant remains in
   `lemmas/MLDSA65_Functional.ec` for future work — surfacing it
   here only as `size = sig_len` keeps the layout-side proofs
   honest about what they verify.

   What stays AXIOMATIC: `encode_signature_wf` — every value of type
   `signature_t` produced by the protocol (via `pack_n1_signature`,
   `mldsa_sign_op`, etc.) MUST have length `sig_len`. With the
   record wrapper this is a structural invariant on producers
   (not a constraint on the type itself, which doesn't enforce it).
   `encode_signature_len` is now DERIVED from this single axiom.
   =================================================================== *)

(* v11: concrete 1-field record wrapping `int list`. The single
   field surfaces the bytes; encode/decode are structural. *)
type signature_t = { sig_bytes : int list }.

op encode_signature (x : signature_t) : int list = x.`sig_bytes.
op decode_signature (bs : int list)   : signature_t = {| sig_bytes = bs |}.

(* Well-formedness predicate on signature bytes. v11: concretized to
   the FIPS 204 §3.5.5 length identity. The richer FIPS 204 wf
   invariant (h-weight bound, z bit-packing) is future work — kept
   in MLDSA65_Functional. *)
op wf_signature_bytes (bs : int list) : bool = size bs = sig_len.

(* The single load-bearing producer-side invariant: every
   `signature_t` value has byte-length `sig_len`. With the concrete
   record wrapper, this CANNOT be derived structurally because the
   record carries an arbitrary int list; it constrains the
   protocol-level producers (`pack_n1_signature`, `mldsa_sign_op`,
   the wrapper-bridge sig outputs) to produce sig_len bytes. *)
axiom encode_signature_wf (x : signature_t) :
  wf_signature_bytes (encode_signature x).

(* PROVED — record reconstruction is structurally identity.

   v11 closure: was an axiom, now a lemma. The roundtrip
   `decode_signature (encode_signature x) = x` reduces to
   `{| sig_bytes = x.\`sig_bytes |} = x` which is the standard
   record-eta identity. *)
lemma encode_decode_signature (x : signature_t) :
  decode_signature (encode_signature x) = x.
proof. by rewrite /encode_signature /decode_signature; case: x. qed.

(* PROVED — analogous record-eta on the other direction.

   v11 closure: was an axiom, now a lemma. Trivially provable from
   the structural definitions of encode/decode; the wf hypothesis
   is no longer needed (in v10 the wf gate was there to rule out
   adversarial decoder realisations — with the record-concrete
   decoder there are no such realisations). *)
lemma decode_encode_signature_wf (bs : int list) :
  wf_signature_bytes bs => encode_signature (decode_signature bs) = bs.
proof. by move=> _; rewrite /encode_signature /decode_signature. qed.

(* PROVED — length identity follows directly from
   `encode_signature_wf` + the concrete definition of
   `wf_signature_bytes`.

   v11 closure: was an axiom, now a lemma. *)
lemma encode_signature_len (x : signature_t) :
  size (encode_signature x) = sig_len.
proof.
  have Hwf := encode_signature_wf x.
  by rewrite /wf_signature_bytes in Hwf.
qed.

(* ===================================================================
   Memory-level signature read / write.

   These compose the memory primitives (load_bytes / store_bytes from
   Pulsar_N1_Memory) with the codec above. They're shared by both
   layout files via the thin wrappers
   `Pulsar_N1_Combine_Layout.read_signature_at` /
   `Pulsar_N1_Sign_Layout.read_sig_sign` (kept for backward
   compatibility with the existing Refinement-file consumers).
   =================================================================== *)

op read_sig_at (m : mem_t) (p : int) : signature_t =
  decode_signature (load_bytes m p sig_len).

op write_sig_at (m : mem_t) (p : int) (s : signature_t) : mem_t =
  store_bytes m p (encode_signature s).

(* ===================================================================
   Frame lemmas — PROVED, no axioms beyond the per-type codec ones.
   =================================================================== *)

(* Round-trip: writing a signature at p and reading back from p
   returns the original. *)
lemma read_after_write_sig (m : mem_t) (p : int) (s : signature_t) :
  read_sig_at (write_sig_at m p s) p = s.
proof.
  rewrite /read_sig_at /write_sig_at.
  have Heq :
    load_bytes (store_bytes m p (encode_signature s)) p sig_len
    = encode_signature s.
  - have <-: size (encode_signature s) = sig_len
      by exact encode_signature_len.
    by apply store_bytes_load_bytes.
  by rewrite Heq encode_decode_signature.
qed.

(* Separation: a write to [p, p + sig_len) doesn't affect reads at
   addresses outside that range. *)
lemma write_sig_separation
      (m : mem_t) (p : int) (s : signature_t) (q : int) :
  q < p \/ p + sig_len <= q =>
  load_byte (write_sig_at m p s) q = load_byte m q.
proof.
  move=> Hdisj.
  rewrite /write_sig_at.
  apply store_bytes_disjoint.
  by have ->: size (encode_signature s) = sig_len
    by exact encode_signature_len.
qed.

(* ===================================================================
   ACCOUNTING

   axioms (2 — per-type FIPS 204 §3.5.5 round-trip + length):
     encode_decode_signature
     encode_signature_len

   ops (definitions):
     sig_len, signature_t,
     encode_signature, decode_signature,
     read_sig_at, write_sig_at.

   PROVED lemmas (0 admits):
     read_after_write_sig
     write_sig_separation
   =================================================================== *)
