// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// dkg_wellformed_proof.go — sound DKG well-formedness.
//
// The DKG public output is the joint public key (ρ, t1) plus share
// commitments. A relying party must be convinced the committed secret
// material is WELL-FORMED — i.e. that it actually reconstructs the
// advertised public key — WITHOUT ever learning t0, s2, or the master
// secret (PULSAR-V13). Two FIPS 204 relations underlie the key:
//
//	(1)  t   = A·s1 + s2          (linear in (s1, s2) given public A)
//	(2)  t   = t1·2^d + t0        (Power2Round split; t1 public, t0 secret)
//
// Eliminating the internal t gives ONE linear relation over the secret
// witness (s1, s2, t0):
//
//	A·s1 + s2 − t0  =  t1·2^d           (public RHS; t1 from the pk)
//
// This is LINEAR, so the Maurer / generalized-Schnorr proof of knowledge
// of a module-homomorphism preimage applies SOUNDLY (same machinery as
// partial_proof.go), with:
//
//	Ψ(s1, s2, t0) := A·s1 + s2 − t0   (Z_q-module hom R_q^L×R_q^K×R_q^K → R_q^K)
//	public image:  t1·2^d
//
// SOUND part (implemented here): the linear-consistency proof. An
// accepting proof certifies knowledge of (s1, s2, t0) reconstructing t1,
// bound by Fiat–Shamir (tag "PULSAR/DKG/v1") to the pk epoch, ρ, t1, and
// the share-commitment root — except with probability (1/(q−1))^sigmaReps.
// It is honest-verifier zero-knowledge (uniform masks ⇒ uniform
// responses), so the serialized proof reveals nothing about s1/s2/t0.
//
// NOT-YET-SOUND part (fail-closed): a TIGHT small-norm range proof
// (‖s1‖,‖s2‖ ≤ η, ‖t0‖ ≤ 2^(d−1)). A uniform-mask sigma protocol gives
// perfect ZK but its responses carry NO norm information, so it cannot
// also bound the witness norm; a tight lattice range proof (BDLOP /
// Lyubashevsky–Nguyen–Seiler) is genuine research crypto, NOT a linear
// sigma. It is therefore fail-closed (ErrDKGRangeProofUnsound) — see the
// REVIEW marker on dkgRangeProofVerifier. A NON-ZK local self-check
// (dkgWitnessInRange) lets the dealer validate its OWN witness; that is a
// local invariant, never a proof to a third party.

import (
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/sha3"
)

const dkgFSTag = "PULSAR/DKG/v1"

var (
	// ErrDKGProofMalformed is returned when a serialized DKG
	// well-formedness proof does not parse.
	ErrDKGProofMalformed = errors.New("pulsar: DKG well-formedness proof malformed")

	// ErrDKGProofInvalid is returned when the linear-consistency sigma
	// equation fails for some repetition.
	ErrDKGProofInvalid = errors.New("pulsar: DKG linear-consistency proof rejected")

	// ErrDKGRangeProofUnsound is the FAIL-CLOSED default for the tight
	// small-norm range proof: no sound linear-sigma construction exists
	// (a tight lattice range proof is novel, not a linear sigma).
	ErrDKGRangeProofUnsound = errors.New(
		"pulsar: DKG small-norm range proof not implemented (tight lattice " +
			"range proof is novel, not a linear sigma); range soundness is " +
			"DISABLED until an externally-reviewed proof is registered")
)

// DKGWellFormedWitness is the dealer's secret input: the signing-key
// share s1, the error share s2, and the Power2Round low part t0 — all in
// normalized [0,q) form. NEVER serialized; consumed to build the proof.
type DKGWellFormedWitness struct {
	S1 polyVec // length L
	S2 polyVec // length K
	T0 polyVec // length K (centred low part, normalized to [0,q))
}

// DKGWellFormedStatement is the PUBLIC statement: the matrix A (NTT
// domain), the public t1 (high part from the pk), and the binding
// context (pk epoch, ρ, share-commitment root).
type DKGWellFormedStatement struct {
	Mode            Mode
	A               []polyVec // K×L, NTT domain (km.a)
	T1              polyVec   // length K, public high part
	PKEpoch         uint64
	Rho             [32]byte
	ShareCommitRoot [32]byte
}

// dkgLinearMap computes Ψ(s1, s2, t0) = A·s1 + s2 − t0 (mod q),
// normalized. aHat is A in NTT domain; s1 is NTT'd inside.
func dkgLinearMap(aHat []polyVec, s1, s2, t0 polyVec) polyVec {
	K := len(aHat)
	s1Hat := make(polyVec, len(s1))
	for l := range s1 {
		s1Hat[l] = s1[l]
		s1Hat[l].reduceLe2Q()
		s1Hat[l].ntt()
	}
	out := make(polyVec, K)
	for k := 0; k < K; k++ {
		var as poly
		polyDotHat(&as, aHat[k], s1Hat)
		as.reduceLe2Q()
		as.invNTT()
		as.normalize()
		for j := 0; j < mldsaN; j++ {
			// (A·s1 + s2 − t0) mod q
			v := (int64(as[j]) + int64(s2[k][j]) - int64(t0[k][j])) % mldsaQ
			if v < 0 {
				v += mldsaQ
			}
			out[k][j] = uint32(v)
		}
	}
	return out
}

// dkgPublicImage returns t1·2^d (mod q), the public RHS of the linear
// relation.
func dkgPublicImage(t1 polyVec) polyVec {
	out := make(polyVec, len(t1))
	for k := range t1 {
		for j := 0; j < mldsaN; j++ {
			out[k][j] = uint32((uint64(t1[k][j]) << mldsaD) % mldsaQ)
		}
	}
	return out
}

// ProveDKGWellFormed produces the SOUND linear-consistency proof that the
// witness (s1, s2, t0) satisfies A·s1 + s2 − t0 = t1·2^d. It does NOT
// prove small-norm ranges (that is fail-closed). rng supplies masks.
func ProveDKGWellFormed(st *DKGWellFormedStatement, w *DKGWellFormedWitness, rng io.Reader) ([]byte, error) {
	K, L, _ := modeShape(st.Mode)
	if len(st.A) != K || len(st.T1) != K || len(w.S1) != L || len(w.S2) != K || len(w.T0) != K {
		return nil, ErrDKGProofMalformed
	}

	// Masks (a∈R_q^L, b∈R_q^K, d∈R_q^K) and commitments T_r = Ψ(a,b,d).
	as := make([]polyVec, sigmaReps)
	bs := make([]polyVec, sigmaReps)
	ds := make([]polyVec, sigmaReps)
	ts := make([]polyVec, sigmaReps)
	for r := 0; r < sigmaReps; r++ {
		as[r] = sampleUniformVec(rng, L)
		bs[r] = sampleUniformVec(rng, K)
		ds[r] = sampleUniformVec(rng, K)
		ts[r] = dkgLinearMap(st.A, as[r], bs[r], ds[r])
	}

	es := dkgFSChallenges(st, ts)

	// Responses u=a+e·s1, v=b+e·s2, x=d+e·t0.
	us := make([]polyVec, sigmaReps)
	vs := make([]polyVec, sigmaReps)
	xs := make([]polyVec, sigmaReps)
	for r := 0; r < sigmaReps; r++ {
		us[r] = addVecModNorm(as[r], scalarMulVec(es[r], w.S1))
		vs[r] = addVecModNorm(bs[r], scalarMulVec(es[r], w.S2))
		xs[r] = addVecModNorm(ds[r], scalarMulVec(es[r], w.T0))
	}
	return marshalDKGProof(ts, us, vs, xs), nil
}

// VerifyDKGWellFormed verifies the SOUND linear-consistency proof. It
// does NOT check small-norm ranges (use the registered range verifier,
// fail-closed by default).
func VerifyDKGWellFormed(st *DKGWellFormedStatement, proof []byte) error {
	K, L, _ := modeShape(st.Mode)
	if len(st.A) != K || len(st.T1) != K {
		return ErrDKGProofMalformed
	}
	ts, us, vs, xs, err := unmarshalDKGProof(proof, K, L)
	if err != nil {
		return err
	}
	es := dkgFSChallenges(st, ts)
	image := dkgPublicImage(st.T1)
	for r := 0; r < sigmaReps; r++ {
		// Ψ(u,v,x) must equal T_r + e_r·(t1·2^d).
		lhs := dkgLinearMap(st.A, us[r], vs[r], xs[r])
		rhs := addVecModNorm(ts[r], scalarMulVec(es[r], image))
		if !polyVecEqual(lhs, rhs) {
			return ErrDKGProofInvalid
		}
	}
	return nil
}

// dkgFSChallenges derives sigmaReps nonzero Z_q challenges bound to the
// full public statement (mode, ρ, t1, epoch, share-commit root) and all
// round commitments. A is NOT hashed coefficient-wise (it is fixed by ρ);
// ρ binds it.
func dkgFSChallenges(st *DKGWellFormedStatement, ts []polyVec) []uint32 {
	h := sha3.NewCShake256([]byte(functionName), []byte(dkgFSTag))
	writePart := func(b []byte) { _, _ = h.Write(encodeString(b)) }
	var u8 [8]byte
	writePart([]byte{byte(st.Mode)})
	writePart(st.Rho[:])
	writePart(packPolyVec(st.T1))
	binary.BigEndian.PutUint64(u8[:], st.PKEpoch)
	writePart(u8[:])
	writePart(st.ShareCommitRoot[:])
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
			v := binary.LittleEndian.Uint32(buf[:]) & 0x7FFFFF
			if v != 0 && v < mldsaQ {
				es[r] = v
				break
			}
		}
	}
	return es
}

// dkgWitnessInRange is the dealer's LOCAL self-check that its own witness
// is small-norm: ‖s1‖∞ ≤ η, ‖s2‖∞ ≤ η, ‖t0‖∞ ≤ 2^(d−1). This is NOT a
// zero-knowledge proof to a third party — it is a local invariant the
// dealer asserts before publishing. Inputs are in normalized [0,q) form;
// the centred magnitude is checked.
func dkgWitnessInRange(mode Mode, w *DKGWellFormedWitness) bool {
	_, _, eta := modeShape(mode)
	const t0Bound = 1 << (mldsaD - 1)
	inf := func(v polyVec, bound uint32) bool {
		for i := range v {
			for j := 0; j < mldsaN; j++ {
				c := v[i][j]
				mag := c
				if c > mldsaQ/2 {
					mag = mldsaQ - c
				}
				if mag > bound {
					return false
				}
			}
		}
		return true
	}
	return inf(w.S1, eta) && inf(w.S2, eta) && inf(w.T0, t0Bound)
}

// ---- fail-closed range-proof verifier (REVIEW: novel, not a linear sigma) ----

// DKGRangeProofVerifier verifies a tight small-norm range proof on the
// committed DKG shares without learning them.
type DKGRangeProofVerifier interface {
	VerifyDKGRange(st *DKGWellFormedStatement, proof []byte) error
}

// failClosedDKGRange is the default. The fail-closed decision is DERIVED,
// not asserted: the FIPS DKG bounds (‖s1‖∞,‖s2‖∞ ≤ η, ‖t0‖∞ ≤ 2^(d−1))
// are ℓ∞ (per-coefficient) requirements, and the strongest range proof
// faithfully available to this package (a BDLOP/LNS approximate Euclidean
// proof, availableRangeProofClass) certifies an ℓ2 bound that cannot imply
// any ℓ∞ bound here — rangeGateOpen computes exactly this from the live
// parameters and returns false. See rangeproof.go for the full bound
// argument and citations.
//
// REVIEW: the only family that WOULD imply the ℓ∞ bound is the LNS exact
// range proof, which needs a Module-SIS-binding BDLOP commitment layer
// that Pulsar does not have; do NOT hand-roll it. Register an externally-
// reviewed exact-range implementation via RegisterDKGRangeProofVerifier.
type failClosedDKGRange struct{}

func (failClosedDKGRange) VerifyDKGRange(st *DKGWellFormedStatement, _ []byte) error {
	// Derive the gate from the bound arithmetic. For every real parameter
	// set this is closed (an ℓ2 proof never implies these ℓ∞ bounds); the
	// branch documents that the closure is computed, not assumed.
	if rangeGateOpen(dkgRangeRequirements(st.Mode)) {
		return nil
	}
	return ErrDKGRangeProofUnsound
}

var registeredDKGRangeVerifier DKGRangeProofVerifier = failClosedDKGRange{}

// RegisterDKGRangeProofVerifier installs a sound, externally-reviewed
// small-norm range verifier for DKG shares.
func RegisterDKGRangeProofVerifier(v DKGRangeProofVerifier) { registeredDKGRangeVerifier = v }

// DKGRangeProofReady reports whether a sound range verifier is registered.
func DKGRangeProofReady() bool {
	_, unsound := registeredDKGRangeVerifier.(failClosedDKGRange)
	return !unsound
}

// ---- proof serialization: sigmaReps × (T_r ‖ u_r ‖ v_r ‖ x_r) ----
//
// T_r, x_r, v_r are K-vectors; u_r is an L-vector.

func marshalDKGProof(ts, us, vs, xs []polyVec) []byte {
	out := make([]byte, 0, sigmaReps*4*8*mldsaN*4)
	for r := 0; r < sigmaReps; r++ {
		out = append(out, packPolyVec(ts[r])...)
		out = append(out, packPolyVec(us[r])...)
		out = append(out, packPolyVec(vs[r])...)
		out = append(out, packPolyVec(xs[r])...)
	}
	return out
}

func unmarshalDKGProof(proof []byte, K, L int) (ts, us, vs, xs []polyVec, err error) {
	kBytes := K * mldsaN * 4
	lBytes := L * mldsaN * 4
	want := sigmaReps * (kBytes + lBytes + kBytes + kBytes) // T(K)+u(L)+v(K)+x(K)
	if len(proof) != want {
		return nil, nil, nil, nil, ErrDKGProofMalformed
	}
	ts = make([]polyVec, sigmaReps)
	us = make([]polyVec, sigmaReps)
	vs = make([]polyVec, sigmaReps)
	xs = make([]polyVec, sigmaReps)
	off := 0
	takeK := func() polyVec { v := unpackPolyVec(proof[off:off+kBytes], K); off += kBytes; return v }
	takeL := func() polyVec { v := unpackPolyVec(proof[off:off+lBytes], L); off += lBytes; return v }
	for r := 0; r < sigmaReps; r++ {
		ts[r] = takeK()
		us[r] = takeL()
		vs[r] = takeK()
		xs[r] = takeK()
	}
	return ts, us, vs, xs, nil
}
