// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// share_commit.go — per-party DKG / nonce share commitments and the
// IDENTIFIABLE-ABORT design for valid-sigma wrong-z (RED MEDIUM).
//
// ── What this closes, and the residual it scaffolds ──────────────────────
//
// The partial-z sigma proof (partial_proof.go) is SOUND for what it proves:
// knowledge of SOME (y_i, s1_i) opening the public image z_i under the linear
// map, bound by Fiat–Shamir to (session, nonce, party, c, λ_i) and to the
// DKG/nonce commitment BYTES. It does NOT prove that (y_i, s1_i) are the DEALT
// share — SHA-3 is not linear, so the hash-commitment OPENING is outside the
// linear-sigma scope (partial_proof.go header §SCOPE).
//
// CONSEQUENCE (RED MEDIUM, identifiable-abort): a malicious member can submit a
// VALID-sigma but WRONG-z partial — pick any (y', s') it knows, prove the
// (correct) statement for z' = φ(y', s'). The proof verifies, the aggregate is
// wrong, the round dies, and NO party is blamed (unattributable DoS). Today
// this is bounded to a LIVENESS fault: the wrong aggregate NEVER yields a
// signature that verifies under FIPS 204 (no forgery) and leaks nothing (no
// secret crosses the wire). It is simply not yet ATTRIBUTED.
//
// ── Why the cheap homomorphic fix is REJECTED ────────────────────────────
//
// The textbook identifiable-abort check is per-party A·z_i ?= λ_i·(A·y_i) +
// c·λ_i·(A·s1_i). It needs PUBLIC V_i = A·y_i and U_i = A·s1_i. Both REOPEN
// closed leaks:
//   - Σ_i λ_i·V_i = A·ȳ = w  ⇒ publishing the V_i reveals the joint
//     commitment w (PULSAR-V13-W-LEAK: w' − w = c·t0 − c·s2 leaks the key).
//   - Σ_i λ_i·U_i = A·s1 = t − s2 = t1·2^d + t0 − s2; with t1 public this
//     reveals (t0 − s2) — t0 is a SECRET ML-DSA component (PULSAR-V13-HINT-LEAK).
// So no homomorphic-image commitment is admissible.
//
// ── The SOUND design (RESIDUAL — scaffolded, fail-closed) ────────────────
//
// Use a HIDING lattice commitment (BDLOP, ia.cr/2017/1235 / Ajtai) under a
// SEPARATE public matrix B (independent of A), established at deal time:
//
//	Com_s_i = B·r_s_i + embed(s1_i)      (commitment to the key share)
//	Com_y_i = B·r_y_i + embed(y_i)       (commitment to the nonce share)
//
// with SHORT randomness r_*. These are hiding (MLWE) so they reveal neither
// A·s1_i nor A·y_i ⇒ no W-/HINT-LEAK. At sign time the party proves, in ONE
// extended linear sigma over the joint witness (y_i, s1_i, r_y_i, r_s_i), the
// THREE simultaneous LINEAR relations:
//
//	(1) z_i      = λ_i·y_i + c·λ_i·s1_i          (the partial)
//	(2) Com_y_i  = B·r_y_i + embed(y_i)          (nonce-share opening)
//	(3) Com_s_i  = B·r_s_i + embed(s1_i)         (key-share opening)
//
// All three are Z_q-module homomorphisms, so the existing Maurer/CDS sigma
// framework extends with no novel cryptography (plus a norm proof on the
// witness so BDLOP binding holds under MSIS — the same exact-ℓ∞ wall as
// rangeproof.go). A wrong-z party now CANNOT produce a valid proof (the
// commitment binds (y_i, s1_i)), so wrong-z ⇒ proof fails ⇒ that PartyID is
// BLAMED. The commitments are hiding ⇒ no leak.
//
// IMPLEMENTING THIS is the gated residual (Residual A, BLOCKERS.md). It
// requires: (a) BDLOP commitment matrix B + embed/randomness in the public
// setup and nonce deal; (b) the extended PartialStatement/Witness/proof; (c)
// the witness norm proof. Until adopted, shareCommitmentsFor returns the
// authoritative commitments WHEN the setup carries them, else nil — and the
// wrong-z blame path returns ErrIdentifiableAbortResidual.

import "errors"

// ErrIdentifiableAbortResidual marks the SOUND valid-sigma wrong-z attribution
// as the scaffolded-but-unbuilt BDLOP residual. The malicious-secure path that
// flips wrong-z into an attributable blame is fail-closed behind this marker.
var ErrIdentifiableAbortResidual = errors.New(
	"pulsar: sound valid-sigma wrong-z attribution requires BDLOP share-commitment " +
		"binding (Residual A) — wrong-z is currently a liveness fault, never a forgery/leak")

// shareCommitmentsFor returns the per-party DKG (s1-share) and nonce (y-share)
// commitment BYTES that the partial-z proof binds via Fiat–Shamir. It is the
// SINGLE SOURCE OF TRUTH called by BOTH the prover (Round2) and the verifier
// (AggregateBCC), so the bound bytes are SYMMETRIC by construction with no
// registry and no globals — a pure function of PUBLIC inputs (setup, nonceID,
// party eval point).
//
// TODAY it returns (nil, nil): the production setup/nonce-deal do not yet carry
// BDLOP commitments, so there is nothing authoritative to bind. The proof's
// non-transferability across (session, nonce, party, c, λ) is ALREADY provided
// by the Fiat–Shamir statement binding in partial_proof.go; these commitments
// add DEALT-SHARE binding, which is meaningful only WITH the BDLOP opening proof
// (the residual above). When the setup carries authoritative commitments
// (S1ShareCommitments / nonce YCommitments), this function returns them and the
// extended sigma enforces the opening — at which point wrong-z becomes
// attributable. Keeping it ONE function guarantees the prover and verifier never
// drift apart.
func shareCommitmentsFor(setup *AlgSetup, nonceID [32]byte, evalPoint uint32) (dkgCommit, nonceCommit []byte) {
	if setup == nil {
		return nil, nil
	}
	if c, ok := setup.s1ShareCommit[evalPoint]; ok {
		dkgCommit = c
	}
	// Nonce-share commitments travel with the nonce deal; until the leak-free
	// NonceMPC publishes per-party Com_y_i they are absent (nil). Bound here for
	// symmetry once present.
	_ = nonceID
	return dkgCommit, nonceCommit
}
