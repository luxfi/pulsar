// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// partial_proof.go — a SOUND, STANDARD linear sigma protocol for the
// partial-z relation
//
//	z_i = λ_i · y_i + c · λ_i · s1_i        (over R_q^L)
//
// This is the Maurer / generalized-Schnorr proof of knowledge of a
// preimage under a module homomorphism (Cramer–Damgård–Schoenmakers
// '94; Maurer, "Unifying Zero-Knowledge Proofs of Knowledge", 2009).
// The relation is LINEAR in the witness (y_i, s1_i), so the textbook
// sigma protocol applies with NO novel cryptography:
//
//	φ(y, s) := λ_i·y + c·λ_i·s   (a Z_q-module homomorphism R_q^L×R_q^L → R_q^L)
//	public image:  z_i = φ(y_i, s1_i)
//
//	1. (commit)   prover samples masks (a, b) ←$ R_q^L × R_q^L,
//	              sends T := φ(a, b).
//	2. (challenge) e := FS(statement, T) ∈ Z_q\{0}  (Fiat–Shamir).
//	3. (response)  u := a + e·y_i,  v := b + e·s1_i  (in R_q^L).
//	   verify:    φ(u, v) == T + e·z_i.
//
// SOUNDNESS (special soundness): two accepting transcripts (T,e,·),
// (T,e',·) with e≠e' extract the witness via (u−u')/(e−e') = y_i,
// (v−v')/(e−e') = s1_i — valid because e−e' ≠ 0 is invertible in Z_q
// (q = 8380417 is prime). Per-round soundness error is 1/(q−1) ≈ 2⁻²³;
// the protocol is run sigmaReps times in PARALLEL (independent masks,
// one shared Fiat–Shamir hash) so the NIZK soundness error is
// (1/(q−1))^sigmaReps. With sigmaReps = 8 this is ≈ 2⁻¹⁸⁶.
//
// HONEST-VERIFIER ZERO-KNOWLEDGE: u = a + e·y_i is uniform in R_q^L for
// uniform a, independent of y_i (likewise v). The simulator picks
// (e, u, v) uniformly and sets T := φ(u, v) − e·z_i; transcripts are
// identically distributed. The serialized proof therefore reveals
// NOTHING about y_i or s1_i — guarded by a serialized-bytes test.
//
// SCOPE — what this proves vs. what it does NOT:
//   - PROVES, soundly: knowledge of (y_i, s1_i) opening the PUBLIC image
//     z_i under the linear map, bound by Fiat–Shamir to
//     (session, nonce, party, c, λ_i) and to the DKG/nonce commitment
//     BYTES (so a proof for one tuple does not transfer to another).
//   - DOES NOT prove (cannot, soundly, with a non-homomorphic hash): the
//     opening of the hash commitments C_y = H(y_i‖·), C_s = H(s1_i‖·) —
//     SHA-3 is not linear, so that relation is outside the linear-sigma
//     scope. The commitment bytes are BOUND into the transcript (tying
//     the proof to specific commitments) but their hash-opening is not
//     re-proven here. Binding the algebraic relation to z_i is the sound
//     guarantee; the hash-opening binding is integrity, not ZK soundness.
//
// Fiat–Shamir domain separation tag: "PULSAR/Partial/v1".

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/luxfi/mlwe/transcript"
	"golang.org/x/crypto/sha3"
)

// sigmaReps is the parallel-repetition count for the partial-z linear
// sigma protocol. Per-round soundness error is 1/(q−1) ≈ 2⁻²³; with
// sigmaReps rounds the NIZK soundness error is (1/(q−1))^sigmaReps.
// 8 ⇒ ≈ 2⁻¹⁸⁶, comfortably below any practical forgery bound.
const sigmaReps = 8

// partialFSTag is the Fiat–Shamir domain-separation customisation tag.
const partialFSTag = "PULSAR/Partial/v1"

var (
	// ErrPartialProofMalformed is returned when a serialized partial-z
	// proof does not parse (wrong length / structure).
	ErrPartialProofMalformed = errors.New("pulsar: partial-z proof malformed")

	// ErrPartialProofInvalid is returned when the sigma verification
	// equation φ(u,v) == T + e·z fails for some repetition, or the
	// Fiat–Shamir challenge does not re-derive.
	ErrPartialProofInvalid = errors.New("pulsar: partial-z sigma proof rejected")

	// ErrPartialZeroLambda rejects λ_i = 0: the relation z_i = λ_i·(…)
	// is degenerate (z_i ≡ 0) and carries no knowledge.
	ErrPartialZeroLambda = errors.New("pulsar: partial-z lambda is zero (degenerate)")

	// ErrChallengeNotInBall rejects a challenge c that is not a FIPS 204
	// SampleInBall output (exactly τ coefficients ±1, rest 0). A degenerate
	// c — c = 0 being the worst case — collapses z_i = λy_i + cλs1_i to
	// z_i = λy_i, removing the s1 binding the proof is meant to certify.
	ErrChallengeNotInBall = errors.New("pulsar: partial-z challenge is not a FIPS 204 SampleInBall (τ ±1 coefficients)")
)

// challengeIsBall reports whether c is a FIPS 204 SampleInBall challenge:
// exactly tau coefficients are ±1 (1 or q−1 in [0,q) form) and the rest are 0.
// polyDeriveUniformBall produces exactly this shape, so a verifier that
// requires it cannot be fed a low-weight or zero c that weakens the s1 binding.
func challengeIsBall(c *poly, tau int) bool {
	nonzero := 0
	for j := 0; j < mldsaN; j++ {
		switch c[j] {
		case 0:
		case 1, mldsaQ - 1:
			nonzero++
		default:
			return false
		}
	}
	return nonzero == tau
}

// PartialWitness is the prover's secret input: the masking nonce share
// y_i and the signing-key share s1_i, both in R_q^L (un-NTT'd, normalized
// in [0,q)).
type PartialWitness struct {
	Y  polyVec // y_i  (length L)
	S1 polyVec // s1_i (length L)
}

// PartialStatement is the PUBLIC statement the proof is bound to. λ is the
// scalar Lagrange coefficient in Z_q; c is the challenge polynomial; z is
// the public partial z_i. The session/nonce/party identifiers and the
// DKG/nonce commitment bytes bind the proof to its context via Fiat–Shamir.
type PartialStatement struct {
	Mode            Mode
	Lambda          uint32 // λ_i ∈ Z_q (scalar)
	C               poly   // challenge polynomial c
	Z               polyVec
	SessionID       [32]byte
	NonceID         [32]byte
	PartyID         uint32
	DKGCommitment   []byte
	NonceCommitment []byte
}

// partialLinearMap computes φ(y, s)[l] = λ·y[l] + λ·(c·s[l]) for every l,
// the Z_q-module homomorphism whose preimage the proof demonstrates
// knowledge of. cHat is c in NTT/Montgomery form (precomputed once).
// Output is normalized in [0, q).
func partialLinearMap(lambda uint32, cHat *poly, y, s polyVec) polyVec {
	L := len(y)
	out := make(polyVec, L)
	for l := 0; l < L; l++ {
		// c·s[l] via NTT pointwise mul.
		var cs poly
		sHat := s[l]
		sHat.reduceLe2Q()
		sHat.ntt()
		cs.mulHat(cHat, &sHat)
		cs.reduceLe2Q()
		cs.invNTT()
		cs.normalize()
		// λ·(y[l] + c·s[l]) — scalar mul distributes, fold y in first.
		for j := 0; j < mldsaN; j++ {
			yc := (uint64(y[l][j]) + uint64(cs[j])) % mldsaQ
			out[l][j] = uint32((yc * uint64(lambda)) % mldsaQ)
		}
	}
	return out
}

// scalarMulVec returns e·v coefficient-wise mod q for a Z_q scalar e.
func scalarMulVec(e uint32, v polyVec) polyVec {
	out := make(polyVec, len(v))
	for i := range v {
		for j := 0; j < mldsaN; j++ {
			out[i][j] = uint32((uint64(v[i][j]) * uint64(e)) % mldsaQ)
		}
	}
	return out
}

// ProvePartial produces a sound non-interactive linear-sigma proof for
// the relation z_i = λ_i·y_i + c·λ_i·s1_i. The returned bytes are placed
// in Partial.Proof. rng supplies the per-round masks; pass a
// deterministic reader for reproducible proofs.
func ProvePartial(st *PartialStatement, w *PartialWitness, rng io.Reader) ([]byte, error) {
	if st.Lambda%mldsaQ == 0 {
		return nil, ErrPartialZeroLambda
	}
	tau, _, _, _ := modeTauOmega(st.Mode)
	if !challengeIsBall(&st.C, tau) {
		return nil, ErrChallengeNotInBall
	}
	_, L, _ := modeShape(st.Mode)
	if len(w.Y) != L || len(w.S1) != L || len(st.Z) != L {
		return nil, ErrPartialProofMalformed
	}
	cHat := st.C
	cHat.ntt()

	// Round 1: sample masks (a_r, b_r) and commitments T_r = φ(a_r, b_r).
	as := make([]polyVec, sigmaReps)
	bs := make([]polyVec, sigmaReps)
	ts := make([]polyVec, sigmaReps)
	for r := 0; r < sigmaReps; r++ {
		as[r] = sampleUniformVec(rng, L)
		bs[r] = sampleUniformVec(rng, L)
		ts[r] = partialLinearMap(st.Lambda, &cHat, as[r], bs[r])
	}

	// Fiat–Shamir: e_r = FS(statement ‖ T_0 ‖ … ‖ T_{reps-1}), one shared
	// hash, distinct nonzero e_r per round drawn from the same stream.
	es := partialFSChallenges(st, ts)

	// Round 3: responses u_r = a_r + e_r·y, v_r = b_r + e_r·s1.
	us := make([]polyVec, sigmaReps)
	vs := make([]polyVec, sigmaReps)
	for r := 0; r < sigmaReps; r++ {
		us[r] = addVecModNorm(as[r], scalarMulVec(es[r], w.Y))
		vs[r] = addVecModNorm(bs[r], scalarMulVec(es[r], w.S1))
	}

	return marshalPartialProof(ts, us, vs), nil
}

// VerifyPartialProof checks the sigma verification equation for every
// repetition and that the Fiat–Shamir challenges re-derive from the
// (statement, T) transcript. Sound: an accepting proof implies knowledge
// of (y_i, s1_i) opening z_i under φ except with probability (1/(q−1))^reps.
func VerifyPartialProof(st *PartialStatement, proof []byte) error {
	if st.Lambda%mldsaQ == 0 {
		return ErrPartialZeroLambda
	}
	tau, _, _, _ := modeTauOmega(st.Mode)
	if !challengeIsBall(&st.C, tau) {
		return ErrChallengeNotInBall
	}
	_, L, _ := modeShape(st.Mode)
	if len(st.Z) != L {
		return ErrPartialProofMalformed
	}
	ts, us, vs, err := unmarshalPartialProof(proof, L)
	if err != nil {
		return err
	}
	cHat := st.C
	cHat.ntt()

	// Re-derive the Fiat–Shamir challenges from the prover's T values.
	es := partialFSChallenges(st, ts)

	for r := 0; r < sigmaReps; r++ {
		// φ(u_r, v_r) must equal T_r + e_r·z.
		lhs := partialLinearMap(st.Lambda, &cHat, us[r], vs[r])
		rhs := addVecModNorm(ts[r], scalarMulVec(es[r], st.Z))
		if !polyVecEqual(lhs, rhs) {
			return ErrPartialProofInvalid
		}
	}
	return nil
}

// partialFSChallenges derives sigmaReps distinct nonzero Z_q challenges by
// hashing the full public statement and all round commitments under the
// domain-separated cSHAKE tag. Binding every statement field (mode, λ, c,
// z, session, nonce, party, commitments) means a proof is valid ONLY for
// the exact tuple it was produced for.
func partialFSChallenges(st *PartialStatement, ts []polyVec) []uint32 {
	h := sha3.NewCShake256([]byte(functionName), []byte(partialFSTag))
	// Statement binding (SP 800-185 encode_string framing for each part).
	writePart := func(b []byte) { _, _ = h.Write(transcript.EncodeString(b)) }
	var u4 [4]byte
	var u8 [8]byte
	u4[0] = byte(st.Mode)
	writePart(u4[:1])
	binary.BigEndian.PutUint32(u4[:], st.Lambda)
	writePart(u4[:])
	writePart(packPoly(&st.C))
	writePart(packPolyVec(st.Z))
	writePart(st.SessionID[:])
	writePart(st.NonceID[:])
	binary.BigEndian.PutUint32(u4[:], st.PartyID)
	writePart(u4[:])
	writePart(st.DKGCommitment)
	writePart(st.NonceCommitment)
	binary.BigEndian.PutUint64(u8[:], uint64(len(ts)))
	_, _ = h.Write(u8[:])
	for _, t := range ts {
		writePart(packPolyVec(t))
	}

	es := make([]uint32, len(ts))
	var buf [4]byte
	for r := range es {
		for {
			_, _ = h.Read(buf[:])
			v := binary.LittleEndian.Uint32(buf[:]) & 0x7FFFFF // < 2^23
			if v != 0 && v < mldsaQ {
				es[r] = v
				break
			}
		}
	}
	return es
}

// sampleUniformVec draws an R_q^L vector with each coefficient uniform in
// [0,q) by rejection from the rng stream. Used for the sigma masks.
func sampleUniformVec(rng io.Reader, L int) polyVec {
	out := make(polyVec, L)
	var buf [4]byte
	for i := 0; i < L; i++ {
		for j := 0; j < mldsaN; j++ {
			for {
				_, _ = rng.Read(buf[:])
				v := binary.LittleEndian.Uint32(buf[:]) & 0x7FFFFF
				if v < mldsaQ {
					out[i][j] = v
					break
				}
			}
		}
	}
	return out
}

// addVecModNorm returns (a + b) mod q coefficient-wise, normalized.
func addVecModNorm(a, b polyVec) polyVec {
	out := make(polyVec, len(a))
	for i := range a {
		for j := 0; j < mldsaN; j++ {
			out[i][j] = uint32((uint64(a[i][j]) + uint64(b[i][j])) % mldsaQ)
		}
	}
	return out
}

// polyVecEqual reports coefficient-wise equality (both must be normalized).
func polyVecEqual(a, b polyVec) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		for j := 0; j < mldsaN; j++ {
			if a[i][j] != b[i][j] {
				return false
			}
		}
	}
	return true
}

// packPoly serializes one poly (4 bytes/coeff LE). Mirrors packPolyVec for
// a single polynomial (used for the challenge c in the FS hash).
func packPoly(p *poly) []byte {
	out := make([]byte, 4*mldsaN)
	for j := 0; j < mldsaN; j++ {
		binary.LittleEndian.PutUint32(out[4*j:4*j+4], p[j])
	}
	return out
}

// ---- proof serialization: sigmaReps × (T_r ‖ u_r ‖ v_r), each polyVec ----

func marshalPartialProof(ts, us, vs []polyVec) []byte {
	out := make([]byte, 0, sigmaReps*3*len(ts[0])*mldsaN*4)
	for r := 0; r < sigmaReps; r++ {
		out = append(out, packPolyVec(ts[r])...)
		out = append(out, packPolyVec(us[r])...)
		out = append(out, packPolyVec(vs[r])...)
	}
	return out
}

func unmarshalPartialProof(proof []byte, L int) (ts, us, vs []polyVec, err error) {
	vecBytes := L * mldsaN * 4
	if len(proof) != sigmaReps*3*vecBytes {
		return nil, nil, nil, ErrPartialProofMalformed
	}
	ts = make([]polyVec, sigmaReps)
	us = make([]polyVec, sigmaReps)
	vs = make([]polyVec, sigmaReps)
	off := 0
	take := func() polyVec {
		v := unpackPolyVec(proof[off:off+vecBytes], L)
		off += vecBytes
		return v
	}
	for r := 0; r < sigmaReps; r++ {
		ts[r] = take()
		us[r] = take()
		vs[r] = take()
	}
	return ts, us, vs, nil
}

// ---- sound PartialZVerifier wired into the proof.go registry ----

// soundPartialZ is the SOUND replacement for the fail-closed default
// PartialZVerifier. It reconstructs the public statement from the Partial
// + bindings and runs VerifyPartialProof. It is registered via
// RegisterPartialZVerifier(SoundPartialZVerifier{...}).
//
// The verifier needs the public (λ_i, c, z_i) to form the statement. λ_i
// and c arrive via the bindings (challenge bytes carry c̃→c is NOT possible
// here without μ/w1; instead c is supplied directly as a poly through the
// statement builder). To keep VerifyPartial's interface (which only gets
// challenge + commitments), the sound verifier is constructed with the
// per-session public parameters (Mode, Lambda, C, Z) already bound.
type soundPartialZ struct {
	mode   Mode
	lambda uint32
	c      poly
	z      polyVec
}

// SoundPartialZVerifier builds a sound PartialZVerifier bound to the
// public (mode, λ_i, c, z_i) of a specific partial. Register it with
// RegisterPartialZVerifier to enable sound partial-z checking.
func SoundPartialZVerifier(mode Mode, lambda uint32, c poly, z polyVec) PartialZVerifier {
	return soundPartialZ{mode: mode, lambda: lambda, c: c, z: z}
}

// VerifyPartial implements PartialZVerifier. challenge/dkgShareCommit/
// nonceCommit bind the proof; the algebraic statement (λ, c, z) is the
// verifier's bound public parameters.
func (v soundPartialZ) VerifyPartial(p *Partial, challenge, dkgShareCommit, nonceCommit []byte) error {
	st := &PartialStatement{
		Mode:            v.mode,
		Lambda:          v.lambda,
		C:               v.c,
		Z:               v.z,
		SessionID:       p.SessionID,
		NonceID:         p.NonceID,
		PartyID:         p.PartyID,
		DKGCommitment:   dkgShareCommit,
		NonceCommitment: nonceCommit,
	}
	return VerifyPartialProof(st, p.Proof)
}
