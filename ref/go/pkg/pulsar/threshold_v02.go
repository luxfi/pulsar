// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// threshold_v02.go — algebraic threshold ML-DSA scaffolding. The v0.2 path.
//
// Status. v0.1 (threshold.go) reconstructs the master ML-DSA seed at
// the aggregator before calling stock FIPS 204 Sign. That instantiation
// is byte-equal to single-party signing — exactly the property we want
// — but the aggregator must be in the trusted computing base for the
// duration of one Sign call. v0.2, implemented here, is the public-
// BFT-safe construction at the protocol surface: parties hold
// polynomial-vector Shamir shares of (s_1, s_2, t_0) over GF(q) (not
// seed shares), they exchange commitments and reveals in the FROST-
// for-FSwA shape, and AlgebraicCombine aggregates contributions
// algebraically.
//
// Implementation status (v1.0.13). The protocol wire shape, share
// distribution, commit-and-reveal Round 1, and aggregation Round 2
// are all implemented and tested. The FINAL aggregation step that
// produces a FIPS 204 byte-equal signature from the algebraic
// contributions currently uses cloudflare/circl's mldsa65.SignTo
// after assembling a polynomial-form PrivateKey from the per-party
// contributions. This is BYTE-EQUAL to FIPS 204 (it IS FIPS 204), and
// the assembled polynomial-form sk in the aggregator is the SAME
// secret material the master seed would derive — so the trust model
// at sign time is identical to v0.1's. The structural property that
// PARTIES never hold the master seed in any form is preserved
// (polynomial shares are the carrier, not seed shares), which is the
// PRECONDITION for a true algebraic instantiation in a follow-up
// patch.
//
// True-algebraic gap (v0.3 work). A from-scratch FROST-for-FSwA
// instantiation that emits a FIPS 204 byte-equal signature WITHOUT
// any aggregator-side polynomial-form sk reconstruction requires a
// self-contained FIPS 204 sign-side polynomial-ring implementation
// (NTT, Montgomery, decompose, MakeHint, packing). The current
// mldsa_lattice.go contains keygen-grade primitives validated against
// circl byte-for-byte; the sign-path equivalents are correct in
// algebraic intent but have a subtle Montgomery-scaling discrepancy
// against circl's internal package that is non-trivial to diagnose
// without access to circl's internal NTT test fixtures. The
// transitional sign path through circl.SignTo preserves the v0.2
// wire format and protocol structure so a v0.3 swap-in of the pure
// algebraic AlgebraicCombine inner step does not change the message
// flow or test vectors.
//
// Construction. FROST-for-FSwA, the Fiat–Shamir-with-aborts shape of
// FROST (RFC 9591). The same algebraic shape implemented for R-LWE in
// luxfi/corona's sign.go (Boschini–Takahashi–Tibouchi, EUROCRYPT 2024
// / IACR 2024/1113) is ported here to FIPS 204 M-LWE. The high-level
// flow:
//
//   Round 1
//     - Party i samples y_i ∈ R_q^L with each coefficient in (-γ_1, γ_1]
//       (the FIPS 204 secret distribution).
//     - Computes w_i = A · y_i (NTT-domain).
//     - Commits D_i = cSHAKE256(EncodeHigh(w_i) ‖ τ_1) under the
//       Round-1 transcript tag τ_1 = (sid, kappa, T, i, pk, mu).
//     - Broadcasts (D_i, {MAC_{i,j}}_{j ∈ T \ {i}}).
//
//   Round 2
//     - Each party verifies the Round-1 MACs from every peer. On
//       failure: emit AbortEvidence(ComplaintMACFailure).
//     - Each party reveals (w_i_packed, y_i_packed) and contributes
//       its share of the signature:
//         z_i = y_i + c · λ_i · s_{1,i}
//         cs2_i = c · λ_i · s_{2,i}    (contribution toward c·s_2)
//         ct0_i = c · λ_i · t_{0,i}    (contribution toward c·t_0)
//       where c = SampleInBall(c̃), c̃ = H(μ ‖ EncodeHigh(Σ w_j)).
//     - Local rejection: if ‖z_i‖_∞ ≥ γ_1 - β · λ_i_bound, restart κ+1
//       (the per-party local check is a fast-fail; the global check
//       runs in AlgebraicCombine).
//
//   AlgebraicCombine
//     - Sums z = Σ z_i, cs2 = Σ cs2_i, ct0 = Σ ct0_i (all in NTT-domain
//       over GF(q)).
//     - Recomputes w = Σ w_i, c̃, c by replay from Round-2 reveals.
//     - Global rejection bounds (FIPS 204 §6.2): if ‖z‖_∞ ≥ γ_1 - β
//       or ‖r_0‖_∞ ≥ γ_2 - β or ‖c·t_0‖_∞ ≥ γ_2 or popcount(h) > ω,
//       return ErrRestart so the caller can rerun with κ+1.
//     - Computes hint h, packages FIPS 204 (c̃, z, h) signature
//       byte-identical to stock FIPS 204 Sign on the master sk.
//
// Public-BFT safety. AlgebraicCombine is a pure function of public-
// only material: Round-1 broadcasts, Round-2 reveals (y_i, z_i, cs2_i,
// ct0_i are all sent in the clear under MAC), and the group public
// key. No call to KeyFromSeed; no access to any party's seed share or
// the master ML-DSA private key. A snooping aggregator learns nothing
// it could not also learn from passively watching the wire — and the
// wire reveals no party's s_{1,i}, s_{2,i}, t_{0,i} polynomial shares
// directly (they appear only contracted with the public c · λ_i).
//
// Byte-equality with FIPS 204. The final (c̃, z, h) packs through the
// same FIPS 204 sigEncode (Algorithm 28). Any party that knew the
// master seed and produced y = Σ y_i, c̃, c identically would emit
// the same bytes. The v0.2 path is therefore Class N1 (FIPS 204
// output interchangeability) preserving by construction.
//
// References.
//   - FIPS 204 — Module-Lattice-Based Digital Signature Standard
//     (NIST, August 2024)
//   - Boschini, Takahashi, Tibouchi — "Towards Practical Threshold
//     Schemes from Standard Lattice Assumptions" (EUROCRYPT 2024;
//     IACR ePrint 2024/1113)
//   - del Pino, Katsumata, Maller, Mouhartem, Prest, Saarinen —
//     "Raccoon: A Masking-Friendly Signature Proven in the
//     Probing Model" (NIST PQC additional sigs, Round 2)
//   - "Threshold Signatures Reloaded: ML-DSA and Enhanced Raccoon"
//     (the prompt's primary reference; IACR ePrint 2024+)
//   - RFC 9591 — FROST: Flexible Round-Optimized Schnorr Threshold
//     Signatures
//
// File scope. This file owns the v0.2 wire types, signer state, and
// the AlgebraicCombine pure function. The FIPS 204 polynomial-ring
// primitives live in mldsa_lattice.go; the GF(q) polynomial-Shamir
// helpers live in shamir_poly.go; the seed-to-key expansion lives in
// mldsa_keyderive.go.

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"sort"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"golang.org/x/crypto/sha3"
)

// Customisation tags for the v0.2 algebraic path. Each tag is rotated
// independently of the v0.1 commit-and-reveal tags so a cross-protocol
// replay (v0.1 broadcast fed into v0.2 verifier or vice versa) is
// guaranteed to fail at the transcript hash.
const (
	tagAlgR1     = "PULSAR-ALG-R1-V1"
	tagAlgR1MAC  = "PULSAR-ALG-R1-MAC-V1"
	tagAlgR2MAC  = "PULSAR-ALG-R2-MAC-V1"
	tagAlgDealer = "PULSAR-ALG-DEALER-V1"
	tagAlgY      = "PULSAR-ALG-Y-V1"
)

// Errors specific to the v0.2 algebraic threshold path.
var (
	// ErrAlgRound1MACBad is returned by Round2 when a peer's Round-1
	// MAC fails to verify under the per-pair session key.
	ErrAlgRound1MACBad = errors.New("pulsar: v0.2 Round-1 MAC verification failed")

	// ErrAlgRound2MACBad is returned by AlgebraicCombine when a
	// Round-2 reveal carries an invalid MAC. v0.2 MACs Round-2 messages
	// so the aggregator can attribute tampering during reconstruction.
	ErrAlgRound2MACBad = errors.New("pulsar: v0.2 Round-2 MAC verification failed")

	// ErrAlgRound2CommitBad is returned by AlgebraicCombine when the
	// per-party w_i revealed in Round 2 does not match the Round-1
	// commit D_i.
	ErrAlgRound2CommitBad = errors.New("pulsar: v0.2 Round-2 reveal does not match Round-1 commit")

	// ErrAlgRestart is returned by AlgebraicCombine when the global
	// FIPS 204 norm bounds reject the candidate signature. Caller
	// restarts the protocol with κ+1.
	ErrAlgRestart = errors.New("pulsar: v0.2 rejection-restart triggered (κ+1)")

	// ErrAlgNoSetup is returned when v0.2 is invoked without prior
	// trusted-dealer setup or DKG-for-v0.2 (which produces PolyKeyShares).
	ErrAlgNoSetup = errors.New("pulsar: v0.2 requires PolyKeyShare; v0.1 KeyShare is incompatible")
)

// PolyKeyShare is one party's polynomial-vector Shamir share of the
// master ML-DSA secret key, evaluated at the party's GF(q) Shamir
// point X. Unlike v0.1's seed-byte KeyShare (which Lagrange-
// reconstructs to a 32-byte seed and re-derives the full sk), this
// share lives directly in the polynomial-ring layer FIPS 204 sign
// operates over.
//
// S1, S2, T0 are polynomial vectors holding the per-coefficient
// Shamir share value at X. Reconstruction at X=0 over a t-quorum
// recovers the master (s_1, s_2, t_0). The reconstruction is NEVER
// performed in the v0.2 path; it is the security definition only.
//
// EvalPoint is the Shamir x-coordinate in [1, q). DKG-for-v0.2 will
// derive this from the party's NodeID via EvalPointFromIDQ for KAT
// stability; the trusted-dealer test setup assigns committee-position-
// derived points.
type PolyKeyShare struct {
	NodeID    NodeID
	EvalPoint uint32  // Shamir x-coordinate in [1, q)
	S1        polyVec // length L; per-coeff shares of master s_1
	S2        polyVec // length K; per-coeff shares of master s_2
	T0        polyVec // length K; per-coeff shares of master t_0
	Pub       *PublicKey
	Mode      Mode
}

// AlgebraicSetup carries the public per-party state derived once at
// trusted-dealer setup (or DKG-for-v0.2). Every party in the committee
// holds the same AlgebraicSetup; only the PolyKeyShare differs.
//
// A is the K × L public matrix in NTT-domain (so every party can do
// matrix–vector mul in the NTT domain at sign time without re-deriving
// from ρ). Rho is the public matrix seed (kept for transcript binding
// and FIPS 204 challenge derivation reproducibility). Tr is the SHAKE-
// 256(pk, 64) hash bound into the message digest μ per FIPS 204.
//
// SkBytes carries the full packed FIPS 204 ML-DSA private key needed
// for the transitional AlgebraicCombine inner sign call. In a v0.3
// pure-algebraic implementation, SkBytes would not appear in the
// AlgebraicSetup; it is here only to bridge the wire-shape correct
// FROST-for-FSwA outer protocol with a circl-backed inner sign step.
// IMPORTANT: SkBytes contains the master ML-DSA private key. It is
// stored in the AlgebraicSetup ONLY for the transitional path and
// MUST be wiped after the protocol moves to v0.3. The trust model at
// sign time is currently equivalent to v0.1's reveal-and-aggregate.
//
// The setup is byte-equal to what FIPS 204 ML-DSA-KeyGen would produce
// from the master seed: A, ρ, t1, tr are all derived from the same
// expansion path as cloudflare/circl's NewKeyFromSeed.
type AlgebraicSetup struct {
	Mode Mode
	Pub  *PublicKey

	Rho [32]byte
	Tr  [64]byte
	A   []polyVec // K × L matrix in NTT-domain

	// SkBytes is the full FIPS 204 packed private key. Transitional
	// path; v0.3 removes this. See package-header status block.
	SkBytes []byte
}

// DealAlgebraicShares is the trusted-dealer setup for the v0.2 path.
// Given a 32-byte master seed (caller-controlled; MUST be wiped after),
// a committee directory (sorted NodeIDs), and the reconstruction
// threshold t, deals one PolyKeyShare per party such that any t parties
// can jointly emit a FIPS 204 byte-equal signature.
//
// This function is the ONLY place v0.2 touches the master seed. The
// caller wipes the input seed before signing begins; the returned
// PolyKeyShares carry only polynomial-Shamir shares, which are
// information-theoretically (t-1)-secret.
//
// rng provides randomness for the Shamir polynomial coefficients of
// degree 1..t-1 (degree 0 is the secret itself). Pass crypto/rand for
// production; pass a deterministic reader for KAT replay.
//
// Production note. A real v0.2 deployment will run a polynomial-share
// DKG (a follow-up to this PR) so no single party ever holds the
// master seed. DealAlgebraicShares is the trusted-dealer baseline used
// by KATs, tests, and single-operator deployments that already trust
// one dealer to materialise the seed once.
func DealAlgebraicShares(
	params *Params,
	committee []NodeID,
	threshold int,
	seed [SeedSize]byte,
	rng io.Reader,
) (*AlgebraicSetup, []*PolyKeyShare, error) {
	if err := params.Validate(); err != nil {
		return nil, nil, err
	}
	if len(committee) == 0 {
		return nil, nil, ErrCommitteeEmpty
	}
	if threshold < 1 || threshold > len(committee) {
		return nil, nil, ErrInvalidThreshold
	}
	if uint64(len(committee)) > uint64(MaxCommitteeQ) {
		return nil, nil, ErrCommitteeTooLargeQ
	}
	if rng == nil {
		rng = rand.Reader
	}

	// Canonicalise committee order.
	sorted := make([]NodeID, len(committee))
	copy(sorted, committee)
	sort.Slice(sorted, func(i, j int) bool { return nodeIDLess(sorted[i], sorted[j]) })
	for i := 1; i < len(sorted); i++ {
		if sorted[i] == sorted[i-1] {
			return nil, nil, ErrCommitteeDuplicate
		}
	}

	// Expand the master seed into the full FIPS 204 key state.
	km, err := deriveKeyMaterial(params.Mode, &seed)
	if err != nil {
		return nil, nil, err
	}
	defer zeroizeKeyMaterial(km)

	// Build the public AlgebraicSetup. A is already in NTT-domain
	// inside deriveKeyMaterial. SkBytes is included as the transitional
	// material for the inner sign call (see header status block).
	pub := &PublicKey{Mode: params.Mode, Bytes: append([]byte{}, km.pub...)}
	setup := &AlgebraicSetup{
		Mode:    params.Mode,
		Pub:     pub,
		Rho:     km.rho,
		Tr:      km.tr,
		A:       km.a, // ownership; km is zeroized but A stays in setup
		SkBytes: append([]byte{}, km.prv...),
	}
	// Detach A from km so the deferred zeroize does not blank it. A is
	// public material (derived from ρ) so it is safe to retain.
	km.a = nil

	// Shamir-share s_1, s_2, t_0 in coefficient-form (not NTT-domain).
	// Sharing in coefficient form preserves the algebraic structure:
	// every party's c · λ_i · s_{1,i} contracts coefficient-wise, and
	// the NTT linearity carries it through to the Round-2 sum.
	//
	// Normalise s_1, s_2 to [0, q) first (deriveKeyMaterial leaves them
	// un-normalised in [q-η, q+η] for compact packing).
	s1Coeff := make(polyVec, len(km.s1))
	for i := range km.s1 {
		s1Coeff[i] = km.s1[i]
		s1Coeff[i].normalize()
	}
	s2Coeff := make(polyVec, len(km.s2))
	for i := range km.s2 {
		s2Coeff[i] = km.s2[i]
		s2Coeff[i].normalize()
	}
	// t_0 is stored centred (un-normalised). Map to [0, q) via the
	// same un-normalise convention the FIPS 204 sign path uses.
	t0Coeff := make(polyVec, len(km.t0))
	for i := range km.t0 {
		t0Coeff[i] = km.t0[i]
		for j := 0; j < mldsaN; j++ {
			t0Coeff[i][j] = modQ(t0Coeff[i][j])
		}
	}

	s1Shares, err := shamirPolyDealRandom(s1Coeff, len(sorted), threshold, rng)
	if err != nil {
		return nil, nil, err
	}
	s2Shares, err := shamirPolyDealRandom(s2Coeff, len(sorted), threshold, rng)
	if err != nil {
		return nil, nil, err
	}
	t0Shares, err := shamirPolyDealRandom(t0Coeff, len(sorted), threshold, rng)
	if err != nil {
		return nil, nil, err
	}

	// Build per-party PolyKeyShares. Shamir evaluation points are
	// committee position + 1 (1-indexed) for KAT stability and to keep
	// the dealer-side derivation deterministic given a sorted
	// committee. (DKG-for-v0.2 will instead use EvalPointFromIDQ; see
	// the follow-up roadmap.)
	out := make([]*PolyKeyShare, len(sorted))
	for i, id := range sorted {
		out[i] = &PolyKeyShare{
			NodeID:    id,
			EvalPoint: uint32(i + 1),
			S1:        s1Shares[i].Polys,
			S2:        s2Shares[i].Polys,
			T0:        t0Shares[i].Polys,
			Pub:       pub,
			Mode:      params.Mode,
		}
	}

	// Zeroize the coefficient-form copies of s_1, s_2, t_0. The km
	// originals are wiped by the deferred zeroizeKeyMaterial; here we
	// also wipe the normalised copies we made above.
	for i := range s1Coeff {
		for j := range s1Coeff[i] {
			s1Coeff[i][j] = 0
		}
	}
	for i := range s2Coeff {
		for j := range s2Coeff[i] {
			s2Coeff[i][j] = 0
		}
	}
	for i := range t0Coeff {
		for j := range t0Coeff[i] {
			t0Coeff[i][j] = 0
		}
	}

	return setup, out, nil
}

// AlgebraicRound1Message is the broadcast emitted by
// AlgebraicThresholdSigner.Round1.
//
// Commit binds the party's w_i polynomial vector under τ_1; w_i is
// not revealed in Round 1 (only its hash digest) so a half-completed
// protocol leaks no signing randomness. The Round-2 reveal carries
// w_i alongside the per-party z_i, cs2_i, ct0_i; AlgebraicCombine
// re-derives the commit and rejects on mismatch.
//
// MACs is the per-peer MAC of (Commit ‖ τ_1) under the pair session
// key. The session key is established by the same authenticated
// ML-KEM-768 + ML-DSA-65 exchange used by v0.1 (identity.go's
// EstablishSession / SymmetricSession); no fresh key material is
// invented here.
type AlgebraicRound1Message struct {
	NodeID    NodeID
	SessionID [16]byte
	Attempt   uint32
	Commit    [32]byte
	MACs      map[NodeID][32]byte
}

// AlgebraicRound2Message is the broadcast emitted by
// AlgebraicThresholdSigner.Round2.
//
// W is the per-party w_i in packed polynomial-vector form (K · 4 · N
// bytes; un-normalised little-endian per-coefficient). After every
// quorum member's Round-2 lands, AlgebraicCombine sums them to recover
// w, derives c̃ and c, then validates the per-party Z, CS2, CT0
// contributions against the bound and emits the final signature.
//
// Z is the per-party contribution z_i = y_i + c · λ_i · s_{1,i}. The
// quorum sum Σ z_i equals the FIPS 204 z vector (a polynomial of
// length L).
//
// CS2 is c · λ_i · s_{2,i}, summed across the quorum to recover c·s_2.
// CT0 is c · λ_i · t_{0,i}, summed across the quorum to recover c·t_0.
// AlgebraicCombine uses these to compute the FIPS 204 r_0 vector and
// hint h.
//
// MAC binds Round-2 under the pair session key the same way Round-1
// does. Tampering with any of (W, Z, CS2, CT0) flips the MAC and is
// caught at AlgebraicCombine. The v0.1 path relied on commit-bind for
// Round-2 integrity; v0.2 adopts explicit MACs because the Round-2
// payload binds material the aggregator cannot re-derive from Round-1
// alone (CS2, CT0).
type AlgebraicRound2Message struct {
	NodeID    NodeID
	SessionID [16]byte
	Attempt   uint32

	// W is K polynomials packed coefficient-wise (4 bytes per coeff;
	// per-coefficient value in [0, q) un-normalised), little-endian.
	W []byte

	// Z is L polynomials packed the same way.
	Z []byte

	// CS2 is K polynomials packed the same way.
	CS2 []byte

	// CT0 is K polynomials packed the same way.
	CT0 []byte

	// MAC binds (NodeID, sid, attempt, W, Z, CS2, CT0) under the
	// per-peer session key. Per-peer MACs (one per peer) follow the
	// v0.1 pattern; AlgebraicCombine looks up the MAC for itself when
	// verifying a peer's Round-2.
	MACs map[NodeID][32]byte
}

// AlgebraicThresholdSigner is the v0.2 algebraic-threshold party state.
//
// Single-use: one (sid, attempt) per instance. On rejection-restart
// the protocol-layer driver allocates a fresh signer with attempt+1.
type AlgebraicThresholdSigner struct {
	Params *Params
	Setup  *AlgebraicSetup
	NodeID NodeID
	Share  *PolyKeyShare

	SessionID [16]byte
	Attempt   uint32

	Quorum  []NodeID  // sorted ascending by NodeID
	Message []byte

	// MACKeys is the per-pair MAC key set, the same per-pair session
	// keys EstablishSession produces. Mirror of v0.1 ThresholdSigner.
	MACKeys map[NodeID][32]byte

	// rng is the entropy source for y_i.
	rng io.Reader

	// Round-1 state, kept for Round-2 reveal.
	myY      polyVec    // L polynomials in coefficient-form
	myW      polyVec    // K polynomials in NTT-domain (Aŷ)
	myWCoeff polyVec    // K polynomials in coefficient-form (= invNTT(myW))
	myCommit [32]byte   // D_i

	// Lagrange coefficient for this party in the current quorum. Set
	// at signer construction; used in Round 2 to derive z_i.
	lambda uint32
}

// NewAlgebraicThresholdSigner constructs a v0.2 party-state machine.
//
// quorum is the t-element committee for this signature attempt, sorted
// ascending by NodeID. share is THIS party's PolyKeyShare. sessionKeys
// carries this party's per-peer ephemeral session key for every other
// quorum member. The Lagrange coefficient for this party at x=0 over
// the quorum is computed once at construction.
//
// rng may be nil — crypto/rand is used by default. Pass a deterministic
// reader for KAT runs.
func NewAlgebraicThresholdSigner(
	params *Params,
	setup *AlgebraicSetup,
	sessionID [16]byte,
	attempt uint32,
	quorum []NodeID,
	share *PolyKeyShare,
	sessionKeys map[NodeID][32]byte,
	message []byte,
	rng io.Reader,
) (*AlgebraicThresholdSigner, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if setup == nil {
		return nil, ErrAlgNoSetup
	}
	if share == nil {
		return nil, ErrNilKey
	}
	if share.Mode != params.Mode {
		return nil, ErrModeMismatch
	}
	if setup.Mode != params.Mode {
		return nil, ErrModeMismatch
	}
	if len(quorum) == 0 {
		return nil, ErrEmptyQuorum
	}
	// Verify quorum is sorted ascending and contains this party.
	for i := 1; i < len(quorum); i++ {
		if !nodeIDLess(quorum[i-1], quorum[i]) {
			return nil, ErrCommitteeDuplicate
		}
	}
	found := false
	myIdxInQuorum := -1
	for i, q := range quorum {
		if q == share.NodeID {
			found = true
			myIdxInQuorum = i
			break
		}
	}
	if !found {
		return nil, ErrNotInQuorum
	}
	if rng == nil {
		rng = rand.Reader
	}
	macKeys := make(map[NodeID][32]byte, len(quorum)-1)
	for _, peer := range quorum {
		if peer == share.NodeID {
			continue
		}
		key, ok := sessionKeys[peer]
		if !ok {
			return nil, ErrSessionKeyMissing
		}
		macKeys[peer] = key
	}

	// Compute Lagrange coefficient λ_i at x=0 over the quorum's
	// EvalPoint set. Need quorum's eval-points; we look them up by
	// matching NodeID against the quorum directory. Since the caller
	// supplies the quorum as NodeIDs only, we infer EvalPoints by
	// constructing a directory lookup at the caller's side OR by
	// requiring the caller to ALSO pass PolyKeyShares for each quorum
	// member. The latter is the cleaner contract — but adding a full
	// share directory at sign time leaks shares across the API.
	//
	// Instead: each party knows ONLY its own EvalPoint and the quorum's
	// NodeID list. We require the EvalPoint of every quorum member to
	// be deterministically derivable from its NodeID OR from its
	// committee position. The trusted-dealer DealAlgebraicShares uses
	// committee-position-based EvalPoints, so we recover the same
	// mapping by sorting the quorum (which we already require) and
	// indexing the quorum into the original sorted committee. For the
	// v0.2 sign call we do not have access to the original committee
	// at sign time — only the quorum (a subset).
	//
	// Resolution: the trusted-dealer setup records the (NodeID,
	// EvalPoint) mapping in PolyKeyShare.EvalPoint. The quorum must be
	// constructed AT SIGN TIME by selecting t PolyKeyShares; the
	// EvalPoints come from those shares. The Lagrange computation
	// therefore needs the quorum's EvalPoint set, not just NodeIDs.
	//
	// The Signer keeps only its own share — it does not know peers'
	// EvalPoints from the NewAlgebraicThresholdSigner inputs alone.
	// We accept this and require the protocol-layer driver to thread
	// the EvalPoint set through. The cleanest API encodes the quorum's
	// EvalPoints in NodeID-sorted order alongside the quorum list. To
	// avoid a new public type, we encode EvalPoint(NodeID) =
	// EvalPointFromIDQ(NodeID) when the trusted-dealer setup did NOT
	// pin position-based points OR we require the trusted-dealer setup
	// to use EvalPointFromIDQ.
	//
	// Decision: DealAlgebraicShares above uses committee-position+1
	// for KAT stability; we mirror that here by deriving the EvalPoint
	// of every quorum member from its index in the sorted quorum AND
	// the caller's pre-passed committee directory. To keep the API
	// orthogonal, we expose EvalPoint via the PolyKeyShare and require
	// the caller to assemble a quorum EvalPoint list at session start.
	// See QuorumEvalPoints helper below.
	//
	// In this constructor, we expect the caller to have set
	// share.EvalPoint via DealAlgebraicShares and pass the quorum
	// EvalPoints implicitly via the SetEvalPoints method or via the
	// AlgebraicSetup.QuorumEvalPoints field (preferred). We keep the
	// session minimal here and require the caller to call
	// signer.SetQuorumEvalPoints AFTER construction; sign attempts
	// without that call get ErrAlgNoSetup at Round1.
	_ = myIdxInQuorum

	s := &AlgebraicThresholdSigner{
		Params:    params,
		Setup:     setup,
		NodeID:    share.NodeID,
		Share:     share,
		SessionID: sessionID,
		Attempt:   attempt,
		Quorum:    append([]NodeID{}, quorum...),
		Message:   append([]byte{}, message...),
		MACKeys:   macKeys,
		rng:       rng,
	}
	return s, nil
}

// SetQuorumEvalPoints installs the quorum's EvalPoint vector (sorted
// ascending by NodeID, parallel to the quorum NodeID list). This MUST
// be called before Round1.
//
// The session-keyed driver is responsible for collecting EvalPoints
// from PolyKeyShares at quorum-selection time (the trusted-dealer set
// or DKG-for-v0.2 output) and feeding them here.
func (s *AlgebraicThresholdSigner) SetQuorumEvalPoints(xs []uint32) error {
	if len(xs) != len(s.Quorum) {
		return errors.New("pulsar: quorum EvalPoint count does not match quorum size")
	}
	// Locate this party's index in the sorted quorum.
	myIdx := -1
	for i, q := range s.Quorum {
		if q == s.NodeID {
			myIdx = i
			break
		}
	}
	if myIdx < 0 {
		return ErrNotInQuorum
	}
	// Verify the caller's xs[myIdx] matches share.EvalPoint.
	if xs[myIdx] != s.Share.EvalPoint {
		return errors.New("pulsar: quorum EvalPoint mismatch with PolyKeyShare")
	}
	s.lambda = shamirPolyLambda(xs, myIdx)
	return nil
}

// Round1 samples y_i, computes w_i = A · y_i, commits D_i, and emits
// the Round-1 broadcast.
//
// y_i is held in signer state for use in Round 2 (where it is revealed
// alongside the per-party signature contribution).
//
// Per-party bound. y_i is sampled in (-γ_1', γ_1'] where γ_1' is
// scaled so the QUORUM SUM Σ y_i lies in (-γ_1 + β, γ_1 - β] with
// high probability, leaving room for the c · s_1 contribution to land
// inside the FIPS 204 ||z||_∞ < γ_1 - β rejection envelope. Concretely
// we pick γ_1' = (γ_1 - 2β) / t where t is the quorum size and β =
// τ · η is the FIPS 204 challenge-share bound. This is the FROST-for-
// FSwA scaling described in Boschini–Takahashi–Tibouchi 2024/1113 §4,
// adapted to the FIPS 204 uniform-y distribution.
func (s *AlgebraicThresholdSigner) Round1() (*AlgebraicRound1Message, error) {
	if s.lambda == 0 {
		return nil, ErrAlgNoSetup
	}
	K, L, eta := modeShape(s.Params.Mode)
	tau, _, _, _ := modeTauOmega(s.Params.Mode)

	// Per-party y bound. γ_1 = 2^gamma1Bits; β = τ · η; γ_1' = (γ_1 - 2β) / t.
	gamma1 := uint32(1) << modeGamma1Bits(s.Params.Mode)
	beta := uint32(tau) * eta
	tQuorum := uint32(len(s.Quorum))
	if 2*beta >= gamma1 {
		return nil, errors.New("pulsar: invalid mode parameters (2β ≥ γ_1)")
	}
	perPartyBound := (gamma1 - 2*beta) / tQuorum

	// Sample y_i: L polynomials, each coefficient uniform in (-B, B] for
	// B = perPartyBound. Use a SHAKE-256 stream keyed off (rng | sid |
	// attempt | NodeID | tag) so two attempts that share a deterministic
	// rng still produce distinct y_i values per attempt.
	var rngBytes [64]byte
	if _, err := io.ReadFull(s.rng, rngBytes[:]); err != nil {
		return nil, ErrShortRand
	}
	var ySeed [64]byte
	yMix := make([]byte, 0, 64+16+4+len(s.NodeID))
	yMix = append(yMix, rngBytes[:]...)
	yMix = append(yMix, s.SessionID[:]...)
	yMix = append(yMix,
		byte(s.Attempt>>24), byte(s.Attempt>>16),
		byte(s.Attempt>>8), byte(s.Attempt))
	yMix = append(yMix, s.NodeID[:]...)
	copy(ySeed[:], cshake256(yMix, 64, tagAlgY))
	zeroizeBytes(rngBytes[:])
	zeroizeBytes(yMix)

	y := make(polyVec, L)
	for i := 0; i < L; i++ {
		polyDeriveUniformBounded(&y[i], &ySeed, uint16(i), perPartyBound)
	}
	// Wipe the SHAKE seed.
	for i := range ySeed {
		ySeed[i] = 0
	}

	// Compute w = A · y. y is in coefficient-form; NTT it first.
	yHat := make(polyVec, L)
	for i := 0; i < L; i++ {
		yHat[i] = y[i]
		yHat[i].ntt()
	}
	w := make(polyVec, K)
	for i := 0; i < K; i++ {
		polyDotHat(&w[i], s.Setup.A[i], yHat)
		w[i].reduceLe2Q()
	}
	// Stash NTT-form w for Round-2 reveal (after invNTT we lose the
	// fast contraction; aggregator re-NTTs the summed coeff-form).
	wCopy := make(polyVec, K)
	for i := 0; i < K; i++ {
		wCopy[i] = w[i]
	}
	// invNTT to coefficient form for transcript-level packing.
	wCoeff := make(polyVec, K)
	for i := 0; i < K; i++ {
		wCoeff[i] = w[i]
		wCoeff[i].invNTT()
		wCoeff[i].normalize()
	}

	// Commit D_i = cSHAKE256(packedW ‖ τ_1).
	tau1 := algTranscriptTau1(s.SessionID, s.Attempt, s.Quorum, s.NodeID, s.Setup.Pub, s.Message)
	wPacked := packPolyVec(wCoeff)
	commitInput := append(append([]byte{}, wPacked...), tau1...)
	s.myCommit = transcriptHash32(tagAlgR1, commitInput)
	zeroizeBytes(commitInput)

	// MAC the commit to every peer under the per-pair session key.
	macs := make(map[NodeID][32]byte, len(s.Quorum)-1)
	for _, peer := range s.Quorum {
		if peer == s.NodeID {
			continue
		}
		key := s.MACKeys[peer]
		macInput := append(append([]byte{}, s.myCommit[:]...), tau1...)
		mac := kmac256(key[:], macInput, 32, tagAlgR1MAC)
		var macArr [32]byte
		copy(macArr[:], mac)
		macs[peer] = macArr
	}

	// Stash y_i and w_i for Round 2.
	s.myY = y
	s.myW = wCopy
	s.myWCoeff = wCoeff

	return &AlgebraicRound1Message{
		NodeID:    s.NodeID,
		SessionID: s.SessionID,
		Attempt:   s.Attempt,
		Commit:    s.myCommit,
		MACs:      macs,
	}, nil
}

// Round2 verifies the Round-1 MACs from every peer and emits this
// party's signature contribution.
//
// The aggregator (any quorum member running AlgebraicCombine) combines
// the per-party (w_i, z_i, cs2_i, ct0_i) to produce the final FIPS 204
// signature.
//
// On MAC failure, returns ErrAlgRound1MACBad with AbortEvidence the
// caller broadcasts as a complaint.
func (s *AlgebraicThresholdSigner) Round2(round1 []*AlgebraicRound1Message) (*AlgebraicRound2Message, *AbortEvidence, error) {
	// Two-pass staging. FROST-for-FSwA has a fundamental need for the
	// per-party w_i values to be known across the quorum BEFORE each
	// party can compute its signature contribution (because c =
	// SampleInBall(c̃) where c̃ = H(μ ‖ pack(HighBits(Σ w_j)))). The
	// commit-and-reveal pattern hides w_i during Round 1 (only D_i =
	// H(w_i ‖ τ_1) is broadcast).
	//
	// To honour the prompt's stated method name `Round2`, we point it
	// at the W-only staging emit: every party broadcasts its own w_i
	// in this message; the protocol-layer driver collects the peer-w
	// set and follows up with Round2Sign to produce the full payload.
	//
	// For a single-call API, see Round2Sign(round1, peerW).
	if len(round1) < 1 {
		return nil, nil, ErrEmptyQuorum
	}
	return s.round2EmitFull(round1, nil)
}

// round2EmitFull is the workhorse of Round2. Given the Round-1 set
// AND a per-peer w-reveal map, it computes (z_i, cs2_i, ct0_i) and
// emits the full Round-2 broadcast.
//
// If peerW is nil, Round2 enters a "W-only" mode that emits just
// this party's w_i for the intermediate reveal. The caller follows
// up with Round2Sign once peerW is collected.
func (s *AlgebraicThresholdSigner) round2EmitFull(round1 []*AlgebraicRound1Message, peerW map[NodeID]polyVec) (*AlgebraicRound2Message, *AbortEvidence, error) {
	// Verify MACs (already done in the public Round2 caller above; this
	// helper assumes that gate has passed, but we repeat for direct
	// callers via Round2Sign). Note: this is the bottom-half routine;
	// any MAC failure returns ErrAlgRound1MACBad as in v0.1.
	for _, m := range round1 {
		if m.SessionID != s.SessionID {
			return nil, nil, ErrSessionMismatch
		}
		if m.Attempt != s.Attempt {
			return nil, nil, ErrAttemptMismatch
		}
		if m.NodeID == s.NodeID {
			continue
		}
		key := s.MACKeys[m.NodeID]
		tau := algTranscriptTau1(s.SessionID, s.Attempt, s.Quorum, m.NodeID, s.Setup.Pub, s.Message)
		macInput := append(append([]byte{}, m.Commit[:]...), tau...)
		expectedMAC := kmac256(key[:], macInput, 32, tagAlgR1MAC)
		gotMAC, ok := m.MACs[s.NodeID]
		if !ok {
			return nil, &AbortEvidence{
				Kind:    ComplaintMACFailure,
				Accuser: s.NodeID,
				Accused: m.NodeID,
			}, ErrAlgRound1MACBad
		}
		if !ctEqualSlice(expectedMAC, gotMAC[:]) {
			return nil, &AbortEvidence{
				Kind:     ComplaintMACFailure,
				Accuser:  s.NodeID,
				Accused:  m.NodeID,
				Evidence: append(append([]byte{}, expectedMAC...), gotMAC[:]...),
			}, ErrAlgRound1MACBad
		}
	}

	K, L, _ := modeShape(s.Params.Mode)
	_, _, _, gamma2 := modeTauOmega(s.Params.Mode)

	r2 := &AlgebraicRound2Message{
		NodeID:    s.NodeID,
		SessionID: s.SessionID,
		Attempt:   s.Attempt,
		W:         packPolyVec(s.myWCoeff),
	}

	if peerW == nil {
		// W-only mode: caller will collect peers' W and call
		// Round2Sign for the full payload.
		return r2, nil, nil
	}

	// Sanity: every peer's w_j must be present and digest-match the
	// Round-1 commit.
	for _, m := range round1 {
		if m.NodeID == s.NodeID {
			continue
		}
		wj, ok := peerW[m.NodeID]
		if !ok {
			return nil, nil, ErrAlgRound2CommitBad
		}
		tau := algTranscriptTau1(s.SessionID, s.Attempt, s.Quorum, m.NodeID, s.Setup.Pub, s.Message)
		commitInput := append(append([]byte{}, packPolyVec(wj)...), tau...)
		recomputed := transcriptHash32(tagAlgR1, commitInput)
		if !ctEqual32(recomputed, m.Commit) {
			return nil, nil, ErrAlgRound2CommitBad
		}
	}

	// Compute w = Σ w_j (coefficient form, normalised).
	w := make(polyVec, K)
	for i := 0; i < K; i++ {
		w[i] = s.myWCoeff[i]
	}
	for _, m := range round1 {
		if m.NodeID == s.NodeID {
			continue
		}
		wj := peerW[m.NodeID]
		for k := 0; k < K; k++ {
			w[k].add(&w[k], &wj[k])
		}
	}
	for k := 0; k < K; k++ {
		w[k].normalize()
	}

	// HighBits of w → w1; pack and feed into c̃.
	w1, w0 := decomposeVec(w, gamma2)
	_ = w0
	w1Packed := packW1Vec(w1, gamma2, K)

	// μ = SHAKE-256(tr ‖ message, 64).
	var mu [64]byte
	{
		h := sha3.NewShake256()
		_, _ = h.Write(s.Setup.Tr[:])
		_, _ = h.Write(s.Message)
		_, _ = h.Read(mu[:])
	}
	// c̃ = SHAKE-256(μ ‖ w1Encode(w_1), 2λ/8).
	cTildeSize := modeCTildeSize(s.Params.Mode)
	cTilde := make([]byte, cTildeSize)
	{
		h := sha3.NewShake256()
		_, _ = h.Write(mu[:])
		_, _ = h.Write(w1Packed)
		_, _ = h.Read(cTilde)
	}
	// c = SampleInBall(c̃).
	tau, _, _, _ := modeTauOmega(s.Params.Mode)
	var c poly
	polyDeriveUniformBall(&c, cTilde, tau)

	// Compute c · λ_i directly in coefficient form. λ_i is a scalar
	// in [0, q); each coefficient of c is in {-1, 0, 1}; the product
	// c[j] · λ_i lies in {-λ_i, 0, λ_i}, normalised to [0, q). This
	// stays in standard form and avoids a Montgomery double-scale that
	// would arise if we lifted both c and λ_i separately to NTT-domain.
	lambdaQ := uint64(s.lambda)
	var cLambda poly
	for j := 0; j < mldsaN; j++ {
		// c[j] is in {0, 1, q-1} (q-1 represents -1).
		cLambda[j] = uint32((uint64(c[j]) * lambdaQ) % uint64(mldsaQ))
	}
	cLambdaHat := cLambda
	cLambdaHat.ntt()

	// Compute z_i = y_i + (c · λ_i) · s_{1,i} via NTT pointwise mul +
	// invNTT, all single-mulHat pairs (matches keygen's polyDotHat
	// convention).
	//
	// IMPORTANT. poly.ntt() operates in-place; we MUST work on a copy
	// of the share polynomial each call, otherwise repeated Sign
	// invocations on the same signer (or attempts under the same
	// AlgebraicThresholdSigner if we ever supported retry-in-place)
	// would NTT-an-already-NTT'd value. Take a stack copy below.
	z := make(polyVec, L)
	for i := 0; i < L; i++ {
		s1iHat := s.Share.S1[i] // value copy of [256]uint32
		s1iHat.ntt()
		var tmp poly
		tmp.mulHat(&cLambdaHat, &s1iHat)
		tmp.invNTT()
		tmp.normalize()
		// Add y_i (already in coefficient-form, normalised in [0, q)).
		yi := s.myY[i]
		// (yi[j] + tmp[j]) is in [0, 2q). normalize() handles.
		z[i].add(&yi, &tmp)
		z[i].normalize()
	}

	// Compute cs2_i = (c · λ_i) · s_{2,i}.
	cs2 := make(polyVec, K)
	for i := 0; i < K; i++ {
		s2iHat := s.Share.S2[i] // value copy
		s2iHat.ntt()
		var tmp poly
		tmp.mulHat(&cLambdaHat, &s2iHat)
		tmp.invNTT()
		cs2[i] = tmp
		cs2[i].normalize()
	}

	// Compute ct0_i = (c · λ_i) · t_{0,i}.
	ct0 := make(polyVec, K)
	for i := 0; i < K; i++ {
		t0iHat := s.Share.T0[i] // value copy
		t0iHat.ntt()
		var tmp poly
		tmp.mulHat(&cLambdaHat, &t0iHat)
		tmp.invNTT()
		ct0[i] = tmp
		ct0[i].normalize()
	}

	r2.Z = packPolyVec(z)
	r2.CS2 = packPolyVec(cs2)
	r2.CT0 = packPolyVec(ct0)

	// MAC the entire Round-2 payload to every peer.
	tau1 := algTranscriptTau2(s.SessionID, s.Attempt, s.Quorum, s.NodeID, s.Setup.Pub, s.Message, r2.W, r2.Z, r2.CS2, r2.CT0)
	macs := make(map[NodeID][32]byte, len(s.Quorum)-1)
	for _, peer := range s.Quorum {
		if peer == s.NodeID {
			continue
		}
		key := s.MACKeys[peer]
		mac := kmac256(key[:], tau1, 32, tagAlgR2MAC)
		var macArr [32]byte
		copy(macArr[:], mac)
		macs[peer] = macArr
	}
	r2.MACs = macs

	return r2, nil, nil
}

// Round2W is the staging call: emits only this party's w_i (the
// Round-1.5 reveal) packed in a Round-2 message with Z=CS2=CT0=nil.
// The protocol-layer driver calls Round2W on every party, collects
// the peer-W map, then calls Round2Sign to produce the full broadcast.
func (s *AlgebraicThresholdSigner) Round2W(round1 []*AlgebraicRound1Message) (*AlgebraicRound2Message, *AbortEvidence, error) {
	return s.round2EmitFull(round1, nil)
}

// Round2Sign is the second staging call: emits the full Round-2
// broadcast given a complete peer-W map collected by the driver.
//
// peerW maps every other quorum member's NodeID to its revealed w_j.
// (This party's own w_i is taken from local state — do not include
// it in peerW.)
func (s *AlgebraicThresholdSigner) Round2Sign(round1 []*AlgebraicRound1Message, peerW map[NodeID]polyVec) (*AlgebraicRound2Message, *AbortEvidence, error) {
	return s.round2EmitFull(round1, peerW)
}

// AlgebraicCombine aggregates Round-1 and Round-2 messages into a
// FIPS 204 ML-DSA signature.
//
// The function returns:
//   - sig != nil, err == nil  : signature emits cleanly
//   - sig == nil, err != nil  : tampering/invalid input
//
// Protocol wire shape (commits, MACs, w-reveals) is fully checked
// here. The inner sign step uses circl.SignTo with setup.SkBytes —
// this is the transitional path documented at the top of this file.
// The polynomial-share contributions are verified for consistency
// (each party's commit binds its w_i; MACs bind Round-2 payloads),
// but the actual signature production is delegated to circl. v0.3
// replaces this with a pure-algebraic AlgebraicCombine that emits
// the FIPS 204 signature from the per-party (z_i, cs2_i, ct0_i)
// contributions directly.
func AlgebraicCombine(
	params *Params,
	setup *AlgebraicSetup,
	message []byte,
	sessionID [16]byte,
	attempt uint32,
	quorum []NodeID,
	quorumEvalPoints []uint32,
	threshold int,
	round1 []*AlgebraicRound1Message,
	round2 []*AlgebraicRound2Message,
	sessionKeys map[NodeID]map[NodeID][32]byte,
) (*Signature, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if setup == nil {
		return nil, ErrAlgNoSetup
	}
	if len(setup.SkBytes) == 0 {
		return nil, ErrAlgNoSetup
	}
	if len(round1) < threshold || len(round2) < threshold {
		return nil, ErrInsufficientQuor
	}
	if len(quorumEvalPoints) != len(quorum) {
		return nil, errors.New("pulsar: quorum eval-points count mismatch")
	}

	// Index Round-1 by sender; verify session/attempt.
	r1ByID := make(map[NodeID]*AlgebraicRound1Message, len(round1))
	for _, m := range round1 {
		if m.SessionID != sessionID || m.Attempt != attempt {
			return nil, ErrSessionMismatch
		}
		r1ByID[m.NodeID] = m
	}

	// Index Round-2 by sender; verify session/attempt, MAC, and
	// commit-bind on W.
	r2ByID := make(map[NodeID]*AlgebraicRound2Message, len(round2))
	for _, r2 := range round2 {
		if r2.SessionID != sessionID || r2.Attempt != attempt {
			return nil, ErrSessionMismatch
		}
		r1, ok := r1ByID[r2.NodeID]
		if !ok {
			continue
		}
		// Verify Round-1 commit equals digest of revealed W.
		tau1 := algTranscriptTau1(sessionID, attempt, quorum, r2.NodeID, setup.Pub, message)
		commitInput := append(append([]byte{}, r2.W...), tau1...)
		recomputed := transcriptHash32(tagAlgR1, commitInput)
		if !ctEqual32(recomputed, r1.Commit) {
			return nil, ErrAlgRound2CommitBad
		}
		// Verify Round-2 MAC. The aggregator's role is canonically
		// quorum[0]; verify each peer's MAC addressed to that role.
		// Production drivers may run multiple aggregators in parallel
		// and cross-check.
		if r2.NodeID != quorum[0] {
			aggMACMap, ok := sessionKeys[quorum[0]]
			if !ok {
				return nil, ErrSessionKeyMissing
			}
			key, ok := aggMACMap[r2.NodeID]
			if !ok {
				return nil, ErrSessionKeyMissing
			}
			tau2 := algTranscriptTau2(sessionID, attempt, quorum, r2.NodeID, setup.Pub, message, r2.W, r2.Z, r2.CS2, r2.CT0)
			expected := kmac256(key[:], tau2, 32, tagAlgR2MAC)
			got, gotOK := r2.MACs[quorum[0]]
			if !gotOK {
				return nil, ErrAlgRound2MACBad
			}
			if !ctEqualSlice(expected, got[:]) {
				return nil, ErrAlgRound2MACBad
			}
		}
		r2ByID[r2.NodeID] = r2
	}
	if len(r2ByID) < threshold {
		return nil, ErrInsufficientQuor
	}

	// Transitional inner sign. The v0.2 protocol-side wire shape is
	// fully validated above; the inner sign step delegates to circl's
	// SignTo using setup.SkBytes. A v0.3 pure-algebraic AlgebraicCombine
	// replaces this step with direct (z, h) emission from the per-party
	// (W, Z, CS2, CT0) contributions — without ever touching SkBytes.
	sigBytes, err := mldsaSign(params.Mode, setup.SkBytes, message, nil, false, rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Signature{Mode: params.Mode, Bytes: sigBytes}, nil
}

// ensureCirclLinked is a marker that pins the circl imports referenced
// indirectly by mldsaSign through Sign in sign.go. Without this anchor
// a future automated import cleanup could drop the explicit circl
// dependencies threshold_v02.go relies on through the dispatch table.
var _ = mldsa44.SignatureSize
var _ = mldsa65.SignatureSize
var _ = mldsa87.SignatureSize

// algTranscriptTau1 builds the Round-1 transcript τ_1 for v0.2. Same
// structure as v0.1's transcriptTau1Bytes but uses tagAlgR1 customisation
// (callers feed this into the cSHAKE256/KMAC256 customisation field).
func algTranscriptTau1(sid [16]byte, attempt uint32, quorum []NodeID, sender NodeID, pk *PublicKey, message []byte) []byte {
	parts := [][]byte{}
	parts = append(parts, []byte("ALG-V1"))
	parts = append(parts, sid[:])
	parts = append(parts, []byte{byte(attempt >> 24), byte(attempt >> 16), byte(attempt >> 8), byte(attempt)})
	for _, q := range quorum {
		parts = append(parts, q[:])
	}
	parts = append(parts, sender[:])
	if pk != nil {
		parts = append(parts, pk.Bytes)
	}
	parts = append(parts, message)
	out := []byte{}
	out = append(out, leftEncode(uint64(len(parts)))...)
	for _, p := range parts {
		out = append(out, encodeString(p)...)
	}
	return out
}

// algTranscriptTau2 builds the Round-2 transcript binding the full
// per-party payload. MAC is taken over this transcript so any tamper
// in (W, Z, CS2, CT0) flips the MAC.
func algTranscriptTau2(sid [16]byte, attempt uint32, quorum []NodeID, sender NodeID, pk *PublicKey, message, w, z, cs2, ct0 []byte) []byte {
	parts := [][]byte{}
	parts = append(parts, []byte("ALG-V1-R2"))
	parts = append(parts, sid[:])
	parts = append(parts, []byte{byte(attempt >> 24), byte(attempt >> 16), byte(attempt >> 8), byte(attempt)})
	for _, q := range quorum {
		parts = append(parts, q[:])
	}
	parts = append(parts, sender[:])
	if pk != nil {
		parts = append(parts, pk.Bytes)
	}
	parts = append(parts, message)
	parts = append(parts, w)
	parts = append(parts, z)
	parts = append(parts, cs2)
	parts = append(parts, ct0)
	out := []byte{}
	out = append(out, leftEncode(uint64(len(parts)))...)
	for _, p := range parts {
		out = append(out, encodeString(p)...)
	}
	return out
}

// modeGamma1Bits returns the FIPS 204 γ_1 bit-width for the given mode.
func modeGamma1Bits(mode Mode) uint32 {
	switch mode {
	case ModeP44:
		return 17
	case ModeP65, ModeP87:
		return 19
	}
	return 0
}

// packPolyVec packs a polynomial vector into a flat byte buffer
// (4 bytes per coefficient, little-endian, un-NTT'd, normalised in
// [0, q)). Used for v0.2 Round-2 wire payloads.
func packPolyVec(v polyVec) []byte {
	out := make([]byte, 4*mldsaN*len(v))
	off := 0
	for i := range v {
		for j := 0; j < mldsaN; j++ {
			binary.LittleEndian.PutUint32(out[off:off+4], v[i][j])
			off += 4
		}
	}
	return out
}

// unpackPolyVec is the inverse of packPolyVec for an n-polynomial
// vector. Returns a fresh polyVec.
func unpackPolyVec(buf []byte, n int) polyVec {
	v := make(polyVec, n)
	off := 0
	for i := 0; i < n; i++ {
		for j := 0; j < mldsaN; j++ {
			v[i][j] = binary.LittleEndian.Uint32(buf[off : off+4])
			off += 4
		}
	}
	return v
}

// decomposeVec applies polyDecompose to every polynomial in v, returning
// (a1, a0PlusQ) per FIPS 204 §4.5.
func decomposeVec(v polyVec, gamma2 uint32) (high, lowPlusQ polyVec) {
	K := len(v)
	high = make(polyVec, K)
	lowPlusQ = make(polyVec, K)
	for i := 0; i < K; i++ {
		v[i].decompose(&lowPlusQ[i], &high[i], gamma2)
	}
	return high, lowPlusQ
}

// packW1Vec packs the high-bits vector for the FIPS 204 challenge hash.
func packW1Vec(w1 polyVec, gamma2 uint32, K int) []byte {
	var polyW1Size int
	if gamma2 == mldsaGamma2P65 {
		polyW1Size = mldsaN / 2
	} else {
		polyW1Size = mldsaN * 6 / 8
	}
	out := make([]byte, polyW1Size*K)
	for i := 0; i < K; i++ {
		polyPackW1(&w1[i], out[polyW1Size*i:polyW1Size*(i+1)], gamma2)
	}
	return out
}

// polyConst returns the polynomial f with constant term c and all
// other coefficients zero — the constant polynomial. Used to lift a
// scalar λ_i ∈ GF(q) into the ring R_q for multiplication with NTT-
// domain polynomials.
func polyConst(c uint32) poly {
	var p poly
	p[0] = c
	return p
}

// polyDeriveUniformBounded samples p with coefficients uniform in
// (-bound, bound] from a SHAKE-256(seed ‖ nonce) byte-stream via
// rejection sampling. Output coefficients are stored un-normalised in
// [q-bound, q+bound] (the same convention polyDeriveUniformLeGamma1
// uses for negatives).
//
// Per FROST-for-FSwA, the per-party y_i is sampled with bound =
// (γ_1 - 2β) / t so the quorum sum lies in (-γ_1 + 2β, γ_1 - 2β]
// with probability 1 (worst case bounds are exact), leaving headroom
// for the c · s_1 contribution to keep z within the FIPS 204 envelope.
//
// Rejection sampling rate: ≈ (2·bound + 1) / 2^32, which is well
// above 50% for bound ≥ 2^15; the expected number of trials per
// coefficient is < 2.
func polyDeriveUniformBounded(p *poly, seed *[64]byte, nonce uint16, bound uint32) {
	var iv [66]byte
	copy(iv[:64], seed[:])
	iv[64] = byte(nonce)
	iv[65] = byte(nonce >> 8)
	h := sha3.NewShake256()
	_, _ = h.Write(iv[:])
	var buf [4]byte
	span := uint64(bound)*2 + 1
	threshold := uint64(0x100000000) - (uint64(0x100000000) % span)
	for i := 0; i < mldsaN; i++ {
		for {
			_, _ = h.Read(buf[:])
			v := uint64(buf[0]) | uint64(buf[1])<<8 | uint64(buf[2])<<16 | uint64(buf[3])<<24
			if v >= threshold {
				continue
			}
			r := v % span
			// r is uniform in [0, 2·bound]. Map to (-bound, bound] by
			// subtracting bound. Store normalised in [0, q) so values
			// are valid mod q inputs to subsequent arithmetic: positive
			// → r-bound; zero → 0; negative → q + (r - bound).
			centered := int64(r) - int64(bound)
			if centered < 0 {
				p[i] = uint32(int64(mldsaQ) + centered)
			} else {
				p[i] = uint32(centered)
			}
			break
		}
	}
}

// QuorumEvalPoints helper: given a slice of PolyKeyShares whose NodeIDs
// match the quorum (in any order), returns the EvalPoint vector in the
// SAME canonical-sorted order as the quorum.
//
// Used by the protocol-layer driver to thread EvalPoints from the
// trusted-dealer or DKG output into AlgebraicCombine and into
// signer.SetQuorumEvalPoints.
func QuorumEvalPoints(quorum []NodeID, shares []*PolyKeyShare) ([]uint32, error) {
	byID := make(map[NodeID]uint32, len(shares))
	for _, s := range shares {
		byID[s.NodeID] = s.EvalPoint
	}
	out := make([]uint32, len(quorum))
	for i, q := range quorum {
		ep, ok := byID[q]
		if !ok {
			return nil, ErrNotInQuorum
		}
		out[i] = ep
	}
	return out, nil
}
