// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// nonce_transcript_proof.go — the SOUND LINEAR core of the NonceMPC
// transcript, plus an honest fail-closed boundary for the genuinely
// novel non-linear part.
//
// The NonceMPC (nonce.go) certifies a boundary-clear hidden commitment
// w = A·y with public w1 = HighBits(w), without ever opening w. Three
// sub-claims underlie it. They split cleanly by whether they are LINEAR:
//
//	LINEAR (sound here):
//	  (A) aggregation + Decompose consistency:
//	          Σ_i λ_i·(A·y_i)  −  w0  =  w1·α          (α = 2γ2, public)
//	      i.e. the λ-weighted nonce shares aggregate to a w = A·y whose
//	      Power2Round high part is the PUBLIC w1, with low part w0. The
//	      witness is the per-party masks y_i (which the nonce commitments
//	      bind) and the low part w0. Proven SOUNDLY via the Maurer linear
//	      sigma protocol (same machinery as partial_proof.go), binding
//	      nonce commitments + w1 by Fiat–Shamir (tag "PULSAR/Nonce/v1").
//
//	NON-LINEAR (fail-closed, REVIEW):
//	  (B) the boundary margin  |w0|∞ ≤ γ2 − 2β − slack : a small-norm
//	      RANGE on the committed w0. A uniform-mask sigma proves the
//	      identity (A) but its responses carry NO norm information; a
//	      tight lattice range proof is novel, not a linear sigma → the ZK
//	      range verifier is fail-closed. A NON-ZK local self-check
//	      (nonceW0InMargin) lets a single party validate its OWN w0.
//	  (C) HighBits(w) / BoundaryClear(w) computed IN validator-MPC over
//	      the SECRET-SHARED w: this is the genuinely novel MPC and is
//	      fail-closed (ErrNonceMPCBoundaryUnsound). It is NOT faked.
//
// Decomplection: identity (A) is one sound proof; the range (B) and the
// MPC predicate (C) are separate fail-closed concerns — never braided
// into (A) so the sound part stands on its own.

import (
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/sha3"
)

const nonceFSTag = "PULSAR/Nonce/v1"

var (
	// ErrNonceProofMalformed is returned for an unparseable transcript proof.
	ErrNonceProofMalformed = errors.New("pulsar: nonce-transcript proof malformed")

	// ErrNonceProofInvalid is returned when the linear-consistency sigma
	// equation fails for some repetition.
	ErrNonceProofInvalid = errors.New("pulsar: nonce-transcript linear-consistency proof rejected")

	// ErrNonceMPCBoundaryUnsound is the FAIL-CLOSED default for the
	// HighBits(w)/BoundaryClear(w)-in-MPC predicate over secret-shared w.
	//
	// REVIEW: novel MPC, not yet sound. Computing HighBits / the
	// boundary-clearance predicate over a secret-shared w (so that full w
	// is never opened) is the genuinely-novel part of Pulsar-BCC; it has
	// no standard linear-sigma construction and is NOT faked here. It is
	// fail-closed until an externally-reviewed MPC protocol is registered.
	ErrNonceMPCBoundaryUnsound = errors.New(
		"pulsar: HighBits/BoundaryClear-in-MPC over secret-shared w not " +
			"implemented (novel MPC, not a linear sigma); boundary-clearance " +
			"soundness is DISABLED until an externally-reviewed protocol is registered")

	// ErrNonceRangeProofUnsound is the FAIL-CLOSED default for the w0
	// small-norm boundary-margin range proof.
	ErrNonceRangeProofUnsound = errors.New(
		"pulsar: nonce w0 boundary-margin range proof not implemented " +
			"(tight lattice range proof is novel, not a linear sigma)")
)

// NonceConsistencyWitness is the SECRET input: every party's mask y_i
// (length L, normalized) in λ-quorum order, and the aggregate low part
// w0 = w − w1·α (length K, normalized). Never serialized.
type NonceConsistencyWitness struct {
	Y  []polyVec // per-party masks y_i (each length L), in quorum order
	W0 polyVec   // length K, the Decompose low part of w
}

// NonceConsistencyStatement is the PUBLIC statement: A (NTT domain), the
// per-party Lagrange scalars λ_i (quorum order), the public w1, and the
// binding context (nonce id, per-party nonce-commitment bytes).
type NonceConsistencyStatement struct {
	Mode         Mode
	A            []polyVec // K×L, NTT domain
	Lambdas      []uint32  // λ_i, one per party, quorum order
	W1           polyVec   // length K, public high part
	NonceID      [32]byte
	NonceCommits [][]byte // per-party nonce commitments (bind y_i)
}

// nonceLinearMap computes Φ(y_1..y_t, w0) = Σ_i λ_i·(A·y_i) − w0 (mod q),
// normalized. aHat is A in NTT domain.
func nonceLinearMap(aHat []polyVec, lambdas []uint32, ys []polyVec, w0 polyVec) polyVec {
	K := len(aHat)
	acc := make(polyVec, K) // Σ λ_i (A·y_i)
	for i, y := range ys {
		yHat := make(polyVec, len(y))
		for l := range y {
			yHat[l] = y[l]
			yHat[l].reduceLe2Q()
			yHat[l].ntt()
		}
		for k := 0; k < K; k++ {
			var ay poly
			polyDotHat(&ay, aHat[k], yHat)
			ay.reduceLe2Q()
			ay.invNTT()
			ay.normalize()
			lam := lambdas[i]
			for j := 0; j < mldsaN; j++ {
				acc[k][j] = uint32((uint64(acc[k][j]) + (uint64(ay[j])*uint64(lam))%mldsaQ) % mldsaQ)
			}
		}
	}
	// subtract w0
	out := make(polyVec, K)
	for k := 0; k < K; k++ {
		for j := 0; j < mldsaN; j++ {
			v := (int64(acc[k][j]) - int64(w0[k][j])) % mldsaQ
			if v < 0 {
				v += mldsaQ
			}
			out[k][j] = uint32(v)
		}
	}
	return out
}

// noncePublicImage returns w1·α (mod q), α = 2γ2 — the public RHS.
func noncePublicImage(mode Mode, w1 polyVec) polyVec {
	gamma2, _, _, _ := bccParams(mode)
	alpha := uint64(2 * gamma2)
	out := make(polyVec, len(w1))
	for k := range w1 {
		for j := 0; j < mldsaN; j++ {
			out[k][j] = uint32((uint64(w1[k][j]) * alpha) % mldsaQ)
		}
	}
	return out
}

// ProveNonceConsistency produces the SOUND linear-consistency proof that
// the λ-weighted nonce shares aggregate to a w whose Power2Round/Decompose
// high part is the public w1 (identity (A)). It does NOT prove the |w0|
// boundary margin (B) or the HighBits-in-MPC predicate (C).
func ProveNonceConsistency(st *NonceConsistencyStatement, w *NonceConsistencyWitness, rng io.Reader) ([]byte, error) {
	K, L, _ := modeShape(st.Mode)
	t := len(st.Lambdas)
	if len(st.A) != K || len(st.W1) != K || len(w.Y) != t || len(w.W0) != K {
		return nil, ErrNonceProofMalformed
	}
	for _, y := range w.Y {
		if len(y) != L {
			return nil, ErrNonceProofMalformed
		}
	}

	// Masks: per-party a_{r,i} ∈ R_q^L and aggregate-low mask d_r ∈ R_q^K.
	// Commitment T_r = Φ(a_{r,·}, d_r).
	aMasks := make([][]polyVec, sigmaReps) // [rep][party] of R_q^L
	dMasks := make([]polyVec, sigmaReps)
	ts := make([]polyVec, sigmaReps)
	for r := 0; r < sigmaReps; r++ {
		aMasks[r] = make([]polyVec, t)
		for i := 0; i < t; i++ {
			aMasks[r][i] = sampleUniformVec(rng, L)
		}
		dMasks[r] = sampleUniformVec(rng, K)
		ts[r] = nonceLinearMap(st.A, st.Lambdas, aMasks[r], dMasks[r])
	}

	es := nonceFSChallenges(st, ts)

	// Responses: u_{r,i} = a_{r,i} + e_r·y_i ; x_r = d_r + e_r·w0.
	us := make([][]polyVec, sigmaReps)
	xs := make([]polyVec, sigmaReps)
	for r := 0; r < sigmaReps; r++ {
		us[r] = make([]polyVec, t)
		for i := 0; i < t; i++ {
			us[r][i] = addVecModNorm(aMasks[r][i], scalarMulVec(es[r], w.Y[i]))
		}
		xs[r] = addVecModNorm(dMasks[r], scalarMulVec(es[r], w.W0))
	}
	return marshalNonceProof(ts, us, xs, t), nil
}

// VerifyNonceConsistency verifies the SOUND linear-consistency proof.
func VerifyNonceConsistency(st *NonceConsistencyStatement, proof []byte) error {
	K, L, _ := modeShape(st.Mode)
	t := len(st.Lambdas)
	if len(st.A) != K || len(st.W1) != K {
		return ErrNonceProofMalformed
	}
	ts, us, xs, err := unmarshalNonceProof(proof, K, L, t)
	if err != nil {
		return err
	}
	es := nonceFSChallenges(st, ts)
	image := noncePublicImage(st.Mode, st.W1)
	for r := 0; r < sigmaReps; r++ {
		lhs := nonceLinearMap(st.A, st.Lambdas, us[r], xs[r])
		rhs := addVecModNorm(ts[r], scalarMulVec(es[r], image))
		if !polyVecEqual(lhs, rhs) {
			return ErrNonceProofInvalid
		}
	}
	return nil
}

// nonceFSChallenges binds the full public statement (mode, λ_i, w1, nonce
// id, per-party commitments) and all round commitments.
func nonceFSChallenges(st *NonceConsistencyStatement, ts []polyVec) []uint32 {
	h := sha3.NewCShake256([]byte(functionName), []byte(nonceFSTag))
	writePart := func(b []byte) { _, _ = h.Write(encodeString(b)) }
	var u8 [8]byte
	writePart([]byte{byte(st.Mode)})
	binary.BigEndian.PutUint64(u8[:], uint64(len(st.Lambdas)))
	_, _ = h.Write(u8[:])
	var u4 [4]byte
	for _, lam := range st.Lambdas {
		binary.BigEndian.PutUint32(u4[:], lam)
		writePart(u4[:])
	}
	writePart(packPolyVec(st.W1))
	writePart(st.NonceID[:])
	for _, c := range st.NonceCommits {
		writePart(c)
	}
	binary.BigEndian.PutUint64(u8[:], uint64(len(ts)))
	_, _ = h.Write(u8[:])
	for _, tt := range ts {
		writePart(packPolyVec(tt))
	}
	es := make([]uint32, len(ts))
	var buf [4]byte
	for r := range es {
		for {
			_, _ = h.Read(buf[:])
			v := binary.LittleEndian.Uint32(buf[:]) & 0x7FFFFF
			if v != 0 && v < mldsaQ {
				es[r] = v
				break
			}
		}
	}
	return es
}

// nonceW0InMargin is the LOCAL self-check that a known w0 satisfies the
// boundary margin |w0|∞ ≤ γ2 − 2β − slack. NOT a zero-knowledge proof —
// it requires w0 in the clear. A single party validates its OWN aggregate
// low part before contributing; it is a local invariant, never a proof to
// a third party (full w / w0 must never be opened publicly).
func nonceW0InMargin(mode Mode, w0 polyVec) bool {
	gamma2, beta, _, _ := bccParams(mode)
	bound := boundaryThreshold(gamma2, beta) // γ2 − 2β − slack
	for k := range w0 {
		for j := 0; j < mldsaN; j++ {
			c := w0[k][j]
			mag := c
			if c > mldsaQ/2 {
				mag = mldsaQ - c
			}
			if mag >= bound {
				return false
			}
		}
	}
	return true
}

// ---- fail-closed boundary-MPC predicate (REVIEW: novel MPC) ----

// NonceBoundaryMPCVerifier verifies that HighBits(w)/BoundaryClear(w) were
// correctly computed over a SECRET-SHARED w (so full w is never opened).
type NonceBoundaryMPCVerifier interface {
	VerifyNonceBoundary(st *NonceConsistencyStatement, transcript []byte) error
}

// failClosedNonceBoundary is the default: the HighBits/BoundaryClear-in-MPC
// predicate is novel and NOT faked.
//
// REVIEW: novel MPC, not yet sound. See ErrNonceMPCBoundaryUnsound.
type failClosedNonceBoundary struct{}

func (failClosedNonceBoundary) VerifyNonceBoundary(*NonceConsistencyStatement, []byte) error {
	return ErrNonceMPCBoundaryUnsound
}

var registeredNonceBoundaryVerifier NonceBoundaryMPCVerifier = failClosedNonceBoundary{}

// RegisterNonceBoundaryMPCVerifier installs an externally-reviewed
// boundary-clearance MPC verifier.
func RegisterNonceBoundaryMPCVerifier(v NonceBoundaryMPCVerifier) {
	registeredNonceBoundaryVerifier = v
}

// NonceBoundaryMPCReady reports whether a sound boundary-MPC verifier is
// registered (false ⇒ the novel MPC predicate is fail-closed).
func NonceBoundaryMPCReady() bool {
	_, unsound := registeredNonceBoundaryVerifier.(failClosedNonceBoundary)
	return !unsound
}

// ---- proof serialization: sigmaReps × (T_r(K) ‖ u_{r,0..t-1}(L) ‖ x_r(K)) ----

func marshalNonceProof(ts []polyVec, us [][]polyVec, xs []polyVec, t int) []byte {
	out := make([]byte, 0, sigmaReps*(1+t+1)*8*mldsaN*4)
	for r := 0; r < sigmaReps; r++ {
		out = append(out, packPolyVec(ts[r])...)
		for i := 0; i < t; i++ {
			out = append(out, packPolyVec(us[r][i])...)
		}
		out = append(out, packPolyVec(xs[r])...)
	}
	return out
}

func unmarshalNonceProof(proof []byte, K, L, t int) (ts []polyVec, us [][]polyVec, xs []polyVec, err error) {
	kBytes := K * mldsaN * 4
	lBytes := L * mldsaN * 4
	want := sigmaReps * (kBytes + t*lBytes + kBytes)
	if len(proof) != want {
		return nil, nil, nil, ErrNonceProofMalformed
	}
	ts = make([]polyVec, sigmaReps)
	us = make([][]polyVec, sigmaReps)
	xs = make([]polyVec, sigmaReps)
	off := 0
	takeK := func() polyVec { v := unpackPolyVec(proof[off:off+kBytes], K); off += kBytes; return v }
	takeL := func() polyVec { v := unpackPolyVec(proof[off:off+lBytes], L); off += lBytes; return v }
	for r := 0; r < sigmaReps; r++ {
		ts[r] = takeK()
		us[r] = make([]polyVec, t)
		for i := 0; i < t; i++ {
			us[r][i] = takeL()
		}
		xs[r] = takeK()
	}
	return ts, us, xs, nil
}
