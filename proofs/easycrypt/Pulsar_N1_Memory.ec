(* -------------------------------------------------------------------- *)
(* Pulsar — byte-level memory model                                    *)
(* -------------------------------------------------------------------- *)
(* Decomplected from the layout files.                                  *)
(*                                                                      *)
(* This file holds the byte-level memory abstraction shared by every    *)
(* layout and refinement file. Three ideas live here, and only three:   *)
(*                                                                      *)
(*   1. `mem_t` — bytes addressed by integers.                          *)
(*   2. Single-byte primitives — load_byte / store_byte.                *)
(*   3. Bulk primitives + frame laws — load_bytes / store_bytes /       *)
(*      store_bytes_disjoint / store_bytes_load_bytes /                 *)
(*      load_bytes_after_disjoint_write.                                *)
(*                                                                      *)
(* These three pieces are independent of any FIPS 204 / Pulsar specific *)
(* type or codec. Previously the same content lived inside              *)
(* `Pulsar_N1_Combine_Layout.ec`, which forced the sign-side layout to  *)
(* import combine-specific encoders solely to reach the memory model —  *)
(* a classic complect of "what bytes do" with "what combine bytes mean". *)
(* That complect is now removed.                                        *)
(*                                                                      *)
(* The memory model corresponds to the JModel_x86 `Glob.mem` storeW8 /  *)
(* loadW8 view at the byte level, abstracted from word-aligned          *)
(* semantics that aren't needed for the layout proofs.                  *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv.

(* ===================================================================
   The byte-memory type.
   =================================================================== *)

type mem_t = int -> int.

(* ===================================================================
   Single-byte primitives.
   =================================================================== *)

op load_byte (m : mem_t) (a : int) : int = m a.

op store_byte (m : mem_t) (a : int) (v : int) : mem_t =
  fun (x : int) => if x = a then v else m x.

lemma load_store_same (m : mem_t) (a v : int) :
  load_byte (store_byte m a v) a = v.
proof. by rewrite /load_byte /store_byte /=. qed.

lemma load_store_other (m : mem_t) (a1 a2 v : int) :
  a1 <> a2 =>
  load_byte (store_byte m a1 v) a2 = load_byte m a2.
proof. by move=> ha; rewrite /load_byte /store_byte /=; smt(). qed.

(* ===================================================================
   Bulk primitives.

   `load_bytes m base len` reads `len` contiguous bytes starting at
   `base` into a list.

   `store_bytes m base bs` writes the byte list `bs` starting at
   `base`. RECURSIVE definition: writes the head at base, then
   recursively writes the tail starting at base + 1. This shape
   exposes the induction principle the frame laws need.
   =================================================================== *)

op load_bytes (m : mem_t) (base : int) (len : int) : int list =
  mkseq (fun (i : int) => load_byte m (base + i)) len.

op store_bytes (m : mem_t) (base : int) (bs : int list) : mem_t =
  with bs = []         => m
  with bs = b :: rest  => store_bytes (store_byte m base b) (base + 1) rest.

(* ===================================================================
   Frame laws — all PROVED, no axioms in this file.
   =================================================================== *)

(* Bulk-write frame law: a write to range [p, p + size bs) leaves
   reads at addresses outside that range unchanged.

   Proof: induction on bs using the recursive store_bytes definition
   + load_store_other. *)
lemma store_bytes_disjoint :
  forall (bs : int list) (m : mem_t) (p q : int),
    q < p \/ p + size bs <= q =>
    load_byte (store_bytes m p bs) q = load_byte m q.
proof.
  elim => [|b rest IH] m p q Hdisj /=; first by trivial.
  rewrite IH; first by smt(size_ge0).
  by rewrite /load_byte /store_byte /=; smt(size_ge0).
qed.

(* Bulk store-then-load identity: reading `size bs` bytes back from
   the address we wrote `bs` to returns `bs`.

   Proof: extensional list equality at each index i. At i = 0 the
   head byte is what we wrote at p (store_bytes_disjoint skips the
   tail writes, which all touch addresses >= p + 1). At i > 0 the
   IH on rest gives the result. *)
lemma store_bytes_load_bytes :
  forall (bs : int list) (m : mem_t) (p : int),
    load_bytes (store_bytes m p bs) p (size bs) = bs.
proof.
  elim => [|b rest IH] m p.
  - by rewrite /load_bytes mkseq0.
  rewrite /load_bytes /=.
  apply (eq_from_nth witness).
  - by rewrite size_mkseq; smt(size_ge0).
  move=> i Hi.
  rewrite size_mkseq in Hi.
  rewrite nth_mkseq /=; first by smt(size_ge0).
  case (i = 0) => Hi0.
  - by smt(store_bytes_disjoint load_store_same size_ge0).
  - have HIH := IH (store_byte m p b) (p + 1).
    rewrite /load_bytes in HIH.
    have Hir : 0 <= i - 1 < size rest by smt(size_ge0).
    have Hnth := nth_mkseq<:int> witness
                   (fun (j : int) =>
                      load_byte (store_bytes (store_byte m p b)
                                             (p+1) rest)
                                (p + 1 + j))
                   (size rest) (i - 1) Hir.
    move: HIH Hnth => HIH Hnth.
    smt().
qed.

(* A load_bytes at base p with length L is unchanged by a subsequent
   store_bytes write at base q with len `size bs`, whenever the
   ranges [p, p + L) and [q, q + size bs) are disjoint. *)
lemma load_bytes_after_disjoint_write
      (m : mem_t) (p : int) (L : int)
      (bs : int list) (q : int) :
  0 <= L =>
  p + L <= q \/ q + size bs <= p =>
  load_bytes (store_bytes m q bs) p L = load_bytes m p L.
proof.
  move=> HL Hdisj.
  rewrite /load_bytes.
  apply (eq_from_nth witness); first by rewrite !size_mkseq.
  move=> i Hi; rewrite size_mkseq in Hi.
  rewrite !nth_mkseq /=; first 2 by smt().
  apply store_bytes_disjoint; smt().
qed.

(* ===================================================================
   ACCOUNTING

   Concrete definitions (no proof obligation):
     mem_t, load_byte, store_byte, load_bytes, store_bytes.

   PROVED lemmas (0 axioms in this file):
     load_store_same
     load_store_other
     store_bytes_disjoint
     store_bytes_load_bytes
     load_bytes_after_disjoint_write
   =================================================================== *)
