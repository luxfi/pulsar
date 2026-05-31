// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// threshold_v03.go — v0.3 TRUE ALGEBRAIC threshold ML-DSA. PUBLIC-BFT-SAFE.
//
// READ THIS BEFORE EXTENDING:
//
//   v0.3 closes the v0.2 "Transitional" caveat. The aggregator running
//   AlgebraicAggregate NEVER materialises the master ML-DSA private
//   key, in any form, at any party (parties OR aggregator), at any
//   point during the sign ceremony. The headline structural property:
//
//     AlgebraicSetup carries NO sk material — only public matrix A,
//     public hash tr, public seed ρ, and the public group key.
//
//     AlgebraicKeyShare carries ONLY polynomial-vector Shamir shares
//     of (s_1, s_2, t_0) over R_q^k. These are (t-1)-secret against
//     any sub-quorum coalition.
//
//     AlgebraicAggregate's call signature has NO *PrivateKey, NO
//     SkBytes []byte, NO seed [32]byte parameter. The function body
//     does NOT touch KeyFromSeed, mldsaSign, or any master-sk-bearing
//     primitive. The signature is emitted from the per-party (Z, CS2,
//     CT0) contributions via FIPS 204 sigEncode applied to the
//     algebraic sums.
//
//   This is the load-bearing public-BFT-safety contract. It is enforced
//   by:
//     (a) the type system (no sk-bearing field on AlgebraicSetup);
//     (b) the function signature of AlgebraicAggregate;
//     (c) TestAlgebraic_NoSkAccess (structural test asserting no
//         KeyFromSeed / mldsaSign reachable from AlgebraicAggregate).
//
// CONSTRUCTION
//
//   FROST-for-FSwA (Fiat–Shamir-with-Aborts threshold-Schnorr), the
//   FIPS 204 M-LWE analogue of Boschini–Takahashi–Tibouchi 2024/1113's
//   R-LWE threshold-Raccoon. The wire shape is identical to v0.2;
//   only the inner sign step changes.
//
//   Per-party arithmetic (Round 2):
//     z_i := y_i + c · λ_i · s_{1,i}
//     cs2_i := c · λ_i · s_{2,i}
//     ct0_i := c · λ_i · t_{0,i}
//     where c = SampleInBall(c̃), c̃ = H(μ ‖ HighBits(Σ w_j)),
//     λ_i is the party's Lagrange coefficient at x=0 over the quorum.
//
//   Aggregator arithmetic (AlgebraicAggregate, pure-public-side):
//     w := Σ w_j         (sum of per-party reveals; standard form)
//     w_0+q, w_1 := Decompose(w)
//     c̃ := H(μ ‖ EncodeHigh(w_1))
//     c := SampleInBall(c̃)
//     z := Σ z_j         (= y_total + c · s_1; standard form)
//     cs2 := Σ cs2_j     (= c · s_2; standard form)
//     ct0 := Σ ct0_j     (= c · t_0; standard form)
//     w0_mcs2 := (w_0 - cs2)               normalised
//     IF Exceeds(w0_mcs2, γ_2 - β):        restart (κ+1)
//     IF Exceeds(z,        γ_1 - β):        restart (κ+1)
//     IF Exceeds(ct0,      γ_2):            restart (κ+1)
//     w0_mcs2_pct0 := w0_mcs2 + ct0        normaliseAssumingLe2Q
//     hint, pop := MakeHint(w0_mcs2_pct0, w_1)
//     IF pop > ω:                           restart (κ+1)
//     sig := sigEncode(c̃, z, hint)        (FIPS 204 Algorithm 28)
//
// CORRECTNESS PROOF SKETCH
//
//   Define s_1 := Σ_{j ∈ Q} λ_j(0) · s_{1,j} (Shamir reconstruction at x=0
//   over the quorum Q). Then:
//     Σ z_j = Σ_j (y_j + c · λ_j · s_{1,j})
//           = (Σ y_j) + c · (Σ_j λ_j · s_{1,j})
//           = y_total + c · s_1.
//   This is the FIPS 204 z polynomial vector. Similarly Σ cs2_j = c · s_2
//   and Σ ct0_j = c · t_0. The aggregator then runs the exact FIPS 204
//   §6.2 rejection-check sequence on (z, cs2, ct0) and emits the
//   FIPS 204 sigEncode-format signature.
//
// BYTE-EQUALITY CONTRACT (Class N1)
//
//   The output Signature.Bytes is in canonical FIPS 204 sigEncode
//   format. It verifies under unmodified mldsa{44,65,87}.Verify(pk,
//   message, sig). This is the Class N1 manifesto property: every
//   v0.3 signature is byte-decodable as a single-party FIPS 204
//   signature. The honest cryptographer note:
//
//     Threshold signatures CANNOT be byte-equal to single-party
//     mldsa.SignTo(masterSk, message, rnd) for arbitrary rnd because
//     the y vector in FIPS 204 single-party comes from
//     ExpandMask(SHAKE256(key ‖ rnd ‖ μ), κ), while the v0.3 y_total
//     is the sum of t independent party samples. The byte-equality
//     contract is "valid FIPS 204 signature", not "matches a specific
//     circl SignTo output". TestAlgebraic_ByteValid pins this.
//
// CONSTRAINTS HONOURED
//
//   - Combine() (v0.1) and TransitionalAggregate() (v0.2) UNTOUCHED.
//     v0.3 ships in this new file alongside, not on top of, the
//     existing aggregators. The forward-only discipline: when a v0.3
//     consumer ships, it switches to AlgebraicAggregate; v0.1 and v0.2
//     consumers stay where they are.
//   - The v0.3 wire shape REUSES the v0.2 wire types (TransitionalRound1Message,
//     TransitionalRound2Message) verbatim. The wire bytes for
//     (Commit, MACs, W, Z, CS2, CT0) are byte-identical across v0.2
//     and v0.3 — only the inner aggregator changes. This is
//     intentional: it lets v0.3 land as a pure aggregator-side upgrade
//     without re-stabilising any wire shape.
//   - Naming: this file uses "Algebraic*" because the wire shape IS
//     algebraic AND the aggregator IS algebraic. The v0.2 "Transitional"
//     prefix names the half-algebraic v0.2 state. v0.3 is honestly
//     algebraic end-to-end.
//
// REFERENCES
//   - FIPS 204 §6 ML-DSA-Sign (Algorithm 22 + §7 polynomial subroutines)
//   - Boschini, Takahashi, Tibouchi 2024/1113 — Threshold Raccoon /
//     R-LWE FROST-for-FSwA template (we port to M-LWE)
//   - del Pino et al. "Threshold Signatures Reloaded: ML-DSA and
//     Enhanced Raccoon" (the prompt's primary reference)
//   - RFC 9591 FROST — commit-reveal-then-sign with restart
//
// SECURITY DEFINITION
//   IND-ID-EUF-CMA against any (t-1)-corruption adversary in the
//   ROM, under the M-LWE hardness assumption (FIPS 204's security
//   foundation). The reduction is the FROST-for-FSwA reduction of
//   Boschini–Takahashi–Tibouchi 2024/1113 §5, adapted to M-LWE: an
//   adversary that wins the threshold-EUF-CMA game with non-negligible
//   advantage yields an M-LWE solver with comparable advantage in the
//   ROM, modulo the standard rejection-sampling completeness gap.

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"sort"

	"golang.org/x/crypto/sha3"
)

// Customisation tags for the v0.3 algebraic path. Distinct from the
// v0.2 tagAlg* tags so a cross-version replay (v0.2 broadcast fed into
// a v0.3 aggregator or vice versa) is guaranteed to fail at the
// transcript hash.
//
// Wire-frozen literal values pinned for KAT stability; the Go
// identifier prefix tracks the literal.
const (
	tagV03R1     = "PULSAR-V03-R1-V1"
	tagV03R1MAC  = "PULSAR-V03-R1-MAC-V1"
	tagV03R2MAC  = "PULSAR-V03-R2-MAC-V1"
	tagV03Dealer = "PULSAR-V03-DEALER-V1"
	tagV03Y      = "PULSAR-V03-Y-V1"
)

// Errors specific to the v0.3 algebraic threshold path.
var (
	// ErrAlgebraicRound1MACBad is returned when a peer's Round-1 MAC
	// fails to verify under the per-pair session key.
	ErrAlgebraicRound1MACBad = errors.New("pulsar: v0.3 Round-1 MAC verification failed")

	// ErrAlgebraicRound2MACBad is returned when a Round-2 reveal
	// carries an invalid MAC.
	ErrAlgebraicRound2MACBad = errors.New("pulsar: v0.3 Round-2 MAC verification failed")

	// ErrAlgebraicRound2CommitBad is returned when the per-party w_i
	// revealed in Round 2 does not match the Round-1 commit D_i.
	ErrAlgebraicRound2CommitBad = errors.New("pulsar: v0.3 Round-2 reveal does not match Round-1 commit")

	// ErrAlgebraicRestart is returned when the global FIPS 204 norm
	// bounds reject the candidate signature. Caller restarts κ+1.
	ErrAlgebraicRestart = errors.New("pulsar: v0.3 rejection-restart triggered (κ+1)")

	// ErrAlgebraicNoSetup is returned when v0.3 is invoked without a
	// prior dealer ceremony.
	ErrAlgebraicNoSetup = errors.New("pulsar: v0.3 requires AlgebraicKeyShare; v0.1 KeyShare is incompatible")

	// ErrAlgebraicHintOverflow is returned when the FIPS 204 hint
	// vector population exceeds ω. Restart-restart-able.
	ErrAlgebraicHintOverflow = errors.New("pulsar: v0.3 hint popcount exceeds ω")
)

// AlgebraicSetup is the per-committee public setup state for the v0.3
// algebraic threshold signer. Every party in the committee holds the
// same AlgebraicSetup; only the AlgebraicKeyShare differs.
//
// THE LOAD-BEARING STRUCTURAL PROPERTY: this struct has NO sk-bearing
// field. There is no SkBytes, no master seed, no packed FIPS 204
// private-key blob. The aggregator running AlgebraicAggregate has access
// to ONLY public material — A, ρ, tr, Pub — exactly what a stateless
// FIPS 204 block-verifier sees.
//
// A is the K × L public matrix in NTT-domain (so every party can do
// matrix–vector mul in NTT-domain at sign time without re-deriving from
// ρ). Rho is the public matrix seed (kept for transcript binding and
// FIPS 204 challenge derivation reproducibility). Tr is the SHAKE-
// 256(pk, 64) hash bound into the message digest μ per FIPS 204 §6.2.
type AlgebraicSetup struct {
	Mode Mode
	Pub  *PublicKey

	Rho [32]byte
	Tr  [64]byte
	A   []polyVec // K × L matrix in NTT-domain
}

// AlgebraicKeyShare is one party's polynomial-vector Shamir share of
// the master ML-DSA secret key, evaluated at the party's GF(q) Shamir
// point X. The share carries ONLY the polynomial fields s_1, s_2, t_0
// — there is no seed component and no path back to the master sk
// short of a t-quorum-or-more reconstruction.
//
// S1, S2, T0 are polynomial vectors holding the per-coefficient
// Shamir share value at X. Reconstruction at X=0 over a t-quorum
// recovers (s_1, s_2, t_0). The reconstruction is NEVER performed in
// the v0.3 sign path; it is the security definition only.
//
// EvalPoint is the Shamir x-coordinate in [1, q). The DealAlgebraicV03Shares
// dealer assigns committee-position-derived points (1-indexed) for
// KAT stability.
type AlgebraicKeyShare struct {
	NodeID    NodeID
	EvalPoint uint32  // Shamir x-coordinate in [1, q)
	S1        polyVec // length L; per-coeff shares of master s_1
	S2        polyVec // length K; per-coeff shares of master s_2
	T0        polyVec // length K; per-coeff shares of master t_0
	Pub       *PublicKey
	Mode      Mode
}

// DealAlgebraicV03Shares is the trusted-dealer setup for v0.3.
//
// Given a 32-byte master seed (caller-controlled; MUST be wiped immediately
// after) a committee directory (sorted NodeIDs), and the reconstruction
// threshold t, deals one AlgebraicKeyShare per party such that any t
// parties can jointly emit a FIPS 204 sigEncode-valid signature WITHOUT
// any party (including the aggregator) ever holding the master sk.
//
// LIFECYCLE OF THE MASTER SEED
//
//  1. Caller derives or supplies seed.
//  2. DealAlgebraicV03Shares expands seed → (s_1, s_2, t_0, A, Tr) via
//     deriveKeyMaterial.
//  3. Polynomial-vector Shamir-splits each of s_1, s_2, t_0.
//  4. ZEROISES km.s1, km.s2, km.t0, km.key, km.prv before return.
//     (km.a, km.t1, km.rho, km.tr, km.pub are public — not zeroised.)
//  5. Caller zeroises the original seed.
//
// After step 4, the master sk no longer exists in this process. Steps
// 2–4 happen in a single function-call lifetime under defer — see the
// zeroizeKeyMaterial call below.
//
// # PRODUCTION PATH
//
// A real v0.3 deployment runs a polynomial-share DKG instead of a
// trusted-dealer ceremony, so no single party ever holds the master
// seed. DealAlgebraicV03Shares is the trusted-dealer baseline used by
// KATs, tests, and single-operator deployments that already trust one
// dealer for the one-time genesis material.
//
// The follow-up work is a Pedersen-DKG-style joint key generation
// (luxfi/corona's BootstrapPedersen path is the R-LWE analogue at
// /Users/z/work/lux/corona/keyera/) ported to M-LWE.
func DealAlgebraicV03Shares(
	params *Params,
	committee []NodeID,
	threshold int,
	seed [SeedSize]byte,
	rng io.Reader,
) (*AlgebraicSetup, []*AlgebraicKeyShare, error) {
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

	// Expand the master seed into the full FIPS 204 key state. This is
	// the ONE point in the v0.3 lifetime where the master sk exists; it
	// is wiped before this function returns.
	km, err := deriveKeyMaterial(params.Mode, &seed)
	if err != nil {
		return nil, nil, err
	}
	defer zeroizeKeyMaterial(km)

	pub := &PublicKey{Mode: params.Mode, Bytes: append([]byte{}, km.pub...)}
	setup := &AlgebraicSetup{
		Mode: params.Mode,
		Pub:  pub,
		Rho:  km.rho,
		Tr:   km.tr,
		A:    km.a, // A is public (derived from ρ)
	}
	// Detach A from km so the deferred zeroize does not blank it.
	km.a = nil

	// Shamir-share s_1, s_2, t_0 in coefficient-form. Sharing
	// coefficient-wise preserves the algebraic structure: every party's
	// c · λ_i · s_{1,i} contracts coefficient-wise, and NTT linearity
	// carries it through to the Round-2 sum.
	//
	// Normalise s_1, s_2 to [0, q) (deriveKeyMaterial leaves them
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
	// t_0 is stored centred (un-normalised); normalise to [0, q).
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

	out := make([]*AlgebraicKeyShare, len(sorted))
	for i, id := range sorted {
		out[i] = &AlgebraicKeyShare{
			NodeID:    id,
			EvalPoint: uint32(i + 1),
			S1:        s1Shares[i].Polys,
			S2:        s2Shares[i].Polys,
			T0:        t0Shares[i].Polys,
			Pub:       pub,
			Mode:      params.Mode,
		}
	}

	// Zeroise the coefficient-form copies we made (km's originals are
	// wiped by the deferred zeroizeKeyMaterial).
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

// AlgebraicRound1Message is the broadcast emitted by AlgebraicThresholdSigner.Round1.
// Wire-byte-identical to TransitionalRound1Message — the v0.2 and v0.3 wire
// shapes are intentionally the same so v0.3 can land as a pure aggregator
// upgrade. The semantic distinction is the customisation tag:
// algV03TranscriptTau1 / kmac256 use tagV03R1MAC where v0.2 uses
// tagAlgR1MAC, so a cross-version replay (v0.2 broadcast into a v0.3
// verifier or vice versa) fails at the MAC.
type AlgebraicRound1Message struct {
	NodeID    NodeID
	SessionID [16]byte
	Attempt   uint32
	Commit    [32]byte
	MACs      map[NodeID][32]byte
}

// AlgebraicRound2Message is the broadcast emitted by AlgebraicThresholdSigner.Round2Sign.
// Wire-byte-identical to TransitionalRound2Message.
type AlgebraicRound2Message struct {
	NodeID    NodeID
	SessionID [16]byte
	Attempt   uint32

	// W is K polynomials packed (4 bytes per coefficient, little-endian).
	W []byte

	// Z is L polynomials packed.
	Z []byte

	// CS2 is K polynomials packed.
	CS2 []byte

	// CT0 is K polynomials packed.
	CT0 []byte

	// MACs binds (NodeID, sid, attempt, W, Z, CS2, CT0) under the
	// per-peer session key.
	MACs map[NodeID][32]byte
}

// AlgebraicThresholdSigner is the v0.3 party-state machine. Single-use:
// one (sid, attempt) per instance. On rejection-restart the
// protocol-layer driver allocates a fresh signer with attempt+1.
type AlgebraicThresholdSigner struct {
	Params *Params
	Setup  *AlgebraicSetup
	NodeID NodeID
	Share  *AlgebraicKeyShare

	SessionID [16]byte
	Attempt   uint32

	Quorum  []NodeID
	Message []byte

	// MACKeys is the per-pair MAC key set, same per-pair session keys
	// EstablishSession produces. Mirror of v0.1/v0.2 ThresholdSigner.
	MACKeys map[NodeID][32]byte

	rng io.Reader

	// Round-1 state, kept for Round-2 reveal.
	myY      polyVec  // L polynomials in coefficient-form
	myW      polyVec  // K polynomials in NTT-domain (Aŷ)
	myWCoeff polyVec  // K polynomials in coefficient-form (= invNTT(myW))
	myCommit [32]byte // D_i

	// Lagrange coefficient for this party in the current quorum.
	lambda uint32
}

// NewAlgebraicThresholdSigner constructs a v0.3 party-state machine.
//
// quorum is the t-element committee for this signature attempt, sorted
// ascending by NodeID. share is THIS party's AlgebraicKeyShare.
// sessionKeys carries this party's per-peer ephemeral session key for
// every other quorum member. The Lagrange coefficient for this party
// at x=0 over the quorum's EvalPoint set is installed by SetQuorumEvalPoints
// before Round1.
//
// rng may be nil — crypto/rand is used by default. Pass a deterministic
// reader for KAT runs.
func NewAlgebraicThresholdSigner(
	params *Params,
	setup *AlgebraicSetup,
	sessionID [16]byte,
	attempt uint32,
	quorum []NodeID,
	share *AlgebraicKeyShare,
	sessionKeys map[NodeID][32]byte,
	message []byte,
	rng io.Reader,
) (*AlgebraicThresholdSigner, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if setup == nil {
		return nil, ErrAlgebraicNoSetup
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
	for i := 1; i < len(quorum); i++ {
		if !nodeIDLess(quorum[i-1], quorum[i]) {
			return nil, ErrCommitteeDuplicate
		}
	}
	found := false
	for _, q := range quorum {
		if q == share.NodeID {
			found = true
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

	return &AlgebraicThresholdSigner{
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
	}, nil
}

// SetQuorumEvalPoints installs the quorum's EvalPoint vector (sorted
// ascending by NodeID, parallel to the quorum NodeID list). MUST be
// called before Round1.
//
// The session-keyed driver is responsible for collecting EvalPoints
// from AlgebraicKeyShares at quorum-selection time (the trusted-dealer
// set or v0.4 DKG output) and feeding them here.
func (s *AlgebraicThresholdSigner) SetQuorumEvalPoints(xs []uint32) error {
	if len(xs) != len(s.Quorum) {
		return errors.New("pulsar: v0.3 quorum EvalPoint count does not match quorum size")
	}
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
	if xs[myIdx] != s.Share.EvalPoint {
		return errors.New("pulsar: v0.3 quorum EvalPoint mismatch with AlgebraicKeyShare")
	}
	s.lambda = shamirPolyLambda(xs, myIdx)
	return nil
}

// Round1 samples y_i, computes w_i = A · y_i, commits D_i, and emits
// the Round-1 broadcast.
//
// y_i is sampled in (-γ_1', γ_1'] where γ_1' = (γ_1 - 2β) / t to keep
// the quorum sum Σ y_i inside the FIPS 204 ||z||_∞ < γ_1 - β rejection
// envelope after the c · s_1 contribution lands.
func (s *AlgebraicThresholdSigner) Round1() (*AlgebraicRound1Message, error) {
	if s.lambda == 0 {
		return nil, ErrAlgebraicNoSetup
	}
	K, L, eta := modeShape(s.Params.Mode)
	tau, _, _, _ := modeTauOmega(s.Params.Mode)

	gamma1 := uint32(1) << modeGamma1Bits(s.Params.Mode)
	beta := uint32(tau) * eta
	tQuorum := uint32(len(s.Quorum))
	if 2*beta >= gamma1 {
		return nil, errors.New("pulsar: invalid mode parameters (2β ≥ γ_1)")
	}
	perPartyBound := (gamma1 - 2*beta) / tQuorum

	// Sample y_i via SHAKE-256(rng | sid | attempt | NodeID | tag)
	// so two attempts under a deterministic RNG still produce distinct y_i.
	var rngBytes [64]byte
	if _, err := io.ReadFull(s.rng, rngBytes[:]); err != nil {
		return nil, ErrShortRand
	}
	var ySeed [64]byte
	var attemptBE [4]byte
	binary.BigEndian.PutUint32(attemptBE[:], s.Attempt)
	yMix := make([]byte, 0, 64+16+4+len(s.NodeID))
	yMix = append(yMix, rngBytes[:]...)
	yMix = append(yMix, s.SessionID[:]...)
	yMix = append(yMix, attemptBE[:]...)
	yMix = append(yMix, s.NodeID[:]...)
	copy(ySeed[:], cshake256(yMix, 64, tagV03Y))
	zeroizeBytes(rngBytes[:])
	zeroizeBytes(yMix)

	y := make(polyVec, L)
	for i := 0; i < L; i++ {
		polyDeriveUniformBounded(&y[i], &ySeed, uint16(i), perPartyBound)
	}
	for i := range ySeed {
		ySeed[i] = 0
	}

	// Compute w = A · y.
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
	wCopy := make(polyVec, K)
	for i := 0; i < K; i++ {
		wCopy[i] = w[i]
	}
	wCoeff := make(polyVec, K)
	for i := 0; i < K; i++ {
		wCoeff[i] = w[i]
		wCoeff[i].invNTT()
		wCoeff[i].normalize()
	}

	tau1 := algV03TranscriptTau1(s.SessionID, s.Attempt, s.Quorum, s.NodeID, s.Setup.Pub, s.Message)
	wPacked := packPolyVec(wCoeff)
	commitInput := append(append([]byte{}, wPacked...), tau1...)
	s.myCommit = transcriptHash32(tagV03R1, commitInput)
	zeroizeBytes(commitInput)

	macs := make(map[NodeID][32]byte, len(s.Quorum)-1)
	for _, peer := range s.Quorum {
		if peer == s.NodeID {
			continue
		}
		key := s.MACKeys[peer]
		macInput := append(append([]byte{}, s.myCommit[:]...), tau1...)
		mac := kmac256(key[:], macInput, 32, tagV03R1MAC)
		var macArr [32]byte
		copy(macArr[:], mac)
		macs[peer] = macArr
	}

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

// Round2W is the staging call: emits only this party's w_i (the
// Round-1.5 reveal) packed in a Round-2 message with Z=CS2=CT0=nil.
// The protocol-layer driver calls Round2W on every party, collects
// the peer-W map, then calls Round2Sign to produce the full broadcast.
func (s *AlgebraicThresholdSigner) Round2W(round1 []*AlgebraicRound1Message) (*AlgebraicRound2Message, *AbortEvidence, error) {
	if len(round1) < 1 {
		return nil, nil, ErrEmptyQuorum
	}
	return s.round2EmitFull(round1, nil)
}

// Round2Sign is the second staging call: emits the full Round-2
// broadcast given a complete peer-W map collected by the driver.
//
// peerW maps every other quorum member's NodeID to its revealed w_j.
// (This party's own w_i is taken from local state — do not include it
// in peerW.)
//
// PUBLIC-BFT-SAFETY NOTE: this party's contribution (z_i, cs2_i, ct0_i)
// is INFORMATION-THEORETICALLY (t-1)-secret about its share material —
// the per-party arithmetic is z_i = y_i + c·λ_i·s_{1,i} where y_i is
// fresh randomness from this party's RNG and c is a public challenge.
// An adversary that obtains t-1 such contributions cannot recover any
// single party's s_{1,i} because the y_i mask hides it (each y_i is
// drawn from the FIPS 204 (-γ_1', γ_1'] uniform distribution, which
// is sufficient to mask under the M-LWE assumption).
func (s *AlgebraicThresholdSigner) Round2Sign(round1 []*AlgebraicRound1Message, peerW map[NodeID]polyVec) (*AlgebraicRound2Message, *AbortEvidence, error) {
	return s.round2EmitFull(round1, peerW)
}

// round2EmitFull is the workhorse of Round2W/Round2Sign. If peerW is
// nil emits the W-only staging message; otherwise emits the full
// Round-2 broadcast with (Z, CS2, CT0).
func (s *AlgebraicThresholdSigner) round2EmitFull(round1 []*AlgebraicRound1Message, peerW map[NodeID]polyVec) (*AlgebraicRound2Message, *AbortEvidence, error) {
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
		tau := algV03TranscriptTau1(s.SessionID, s.Attempt, s.Quorum, m.NodeID, s.Setup.Pub, s.Message)
		macInput := append(append([]byte{}, m.Commit[:]...), tau...)
		expectedMAC := kmac256(key[:], macInput, 32, tagV03R1MAC)
		gotMAC, ok := m.MACs[s.NodeID]
		if !ok {
			return nil, &AbortEvidence{
				Kind:    ComplaintMACFailure,
				Accuser: s.NodeID,
				Accused: m.NodeID,
			}, ErrAlgebraicRound1MACBad
		}
		if !ctEqualSlice(expectedMAC, gotMAC[:]) {
			return nil, &AbortEvidence{
				Kind:     ComplaintMACFailure,
				Accuser:  s.NodeID,
				Accused:  m.NodeID,
				Evidence: append(append([]byte{}, expectedMAC...), gotMAC[:]...),
			}, ErrAlgebraicRound1MACBad
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
		// W-only mode.
		return r2, nil, nil
	}

	// Verify every peer's w_j hashes back to its Round-1 commit.
	for _, m := range round1 {
		if m.NodeID == s.NodeID {
			continue
		}
		wj, ok := peerW[m.NodeID]
		if !ok {
			return nil, nil, ErrAlgebraicRound2CommitBad
		}
		tau := algV03TranscriptTau1(s.SessionID, s.Attempt, s.Quorum, m.NodeID, s.Setup.Pub, s.Message)
		commitInput := append(append([]byte{}, packPolyVec(wj)...), tau...)
		recomputed := transcriptHash32(tagV03R1, commitInput)
		if !ctEqual32(recomputed, m.Commit) {
			return nil, nil, ErrAlgebraicRound2CommitBad
		}
	}

	// w = Σ w_j (coefficient form).
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

	w1, _ := decomposeVec(w, gamma2)
	w1Packed := packW1Vec(w1, gamma2, K)

	// μ = SHAKE-256(tr || M', 64) where M' = 0x00 || |ctx| || ctx || M
	// per FIPS 204 §5.4 step 2. ctx = "" (empty) → prefix is 0x00 0x00.
	// Threshold path treats ctx as empty; ctx-aware threshold sign is
	// a v0.4 deliverable (Pulsar.SignCtx threshold equivalent).
	var mu [64]byte
	{
		h := sha3.NewShake256()
		_, _ = h.Write(s.Setup.Tr[:])
		_, _ = h.Write([]byte{0x00, 0x00})
		_, _ = h.Write(s.Message)
		_, _ = h.Read(mu[:])
	}
	cTildeSize := modeCTildeSize(s.Params.Mode)
	cTilde := make([]byte, cTildeSize)
	{
		h := sha3.NewShake256()
		_, _ = h.Write(mu[:])
		_, _ = h.Write(w1Packed)
		_, _ = h.Read(cTilde)
	}
	tau, _, _, _ := modeTauOmega(s.Params.Mode)
	var c poly
	polyDeriveUniformBall(&c, cTilde, tau)

	// c · λ_i in coefficient form (c[j] ∈ {0, ±1}, λ_i ∈ [0, q)).
	lambdaQ := uint64(s.lambda)
	var cLambda poly
	for j := 0; j < mldsaN; j++ {
		cLambda[j] = uint32((uint64(c[j]) * lambdaQ) % uint64(mldsaQ))
	}
	cLambdaHat := cLambda
	cLambdaHat.ntt()

	z := make(polyVec, L)
	for i := 0; i < L; i++ {
		s1iHat := s.Share.S1[i]
		s1iHat.ntt()
		var tmp poly
		tmp.mulHat(&cLambdaHat, &s1iHat)
		tmp.invNTT()
		tmp.normalize()
		yi := s.myY[i]
		z[i].add(&yi, &tmp)
		z[i].normalize()
	}

	cs2 := make(polyVec, K)
	for i := 0; i < K; i++ {
		s2iHat := s.Share.S2[i]
		s2iHat.ntt()
		var tmp poly
		tmp.mulHat(&cLambdaHat, &s2iHat)
		tmp.invNTT()
		cs2[i] = tmp
		cs2[i].normalize()
	}

	ct0 := make(polyVec, K)
	for i := 0; i < K; i++ {
		t0iHat := s.Share.T0[i]
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

	tau2 := algV03TranscriptTau2(s.SessionID, s.Attempt, s.Quorum, s.NodeID, s.Setup.Pub, s.Message, r2.W, r2.Z, r2.CS2, r2.CT0)
	macs := make(map[NodeID][32]byte, len(s.Quorum)-1)
	for _, peer := range s.Quorum {
		if peer == s.NodeID {
			continue
		}
		key := s.MACKeys[peer]
		mac := kmac256(key[:], tau2, 32, tagV03R2MAC)
		var macArr [32]byte
		copy(macArr[:], mac)
		macs[peer] = macArr
	}
	r2.MACs = macs

	return r2, nil, nil
}

// AlgebraicAggregate produces a FIPS 204 ML-DSA signature from the
// quorum's per-party (Z, CS2, CT0) contributions. PUBLIC-BFT-SAFE.
//
// NO master sk is materialised at any point in this function. The
// signature is emitted from pure algebraic sums followed by the FIPS
// 204 §6.2 rejection-check sequence and §7 sigEncode.
//
// Function signature contract (load-bearing):
//   - NO *PrivateKey parameter
//   - NO SkBytes []byte parameter
//   - NO seed [32]byte parameter
//   - groupPubkey is PUBLIC material
//   - setup is *AlgebraicSetup which has NO sk-bearing field
//   - The per-party messages carry ONLY public algebraic contributions
//
// Returns:
//   - (sig, nil)               on success — sig.Bytes verifies under
//     unmodified mldsa.Verify
//   - (nil, ErrAlgebraicRestart) when global FIPS 204 norm bounds reject;
//     caller restarts at κ+1
//   - (nil, other)             on tamper/invalid-input
func AlgebraicAggregate(
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
		return nil, ErrAlgebraicNoSetup
	}
	if setup.Mode != params.Mode {
		return nil, ErrModeMismatch
	}
	if len(round1) < threshold || len(round2) < threshold {
		return nil, ErrInsufficientQuor
	}
	if len(quorumEvalPoints) != len(quorum) {
		return nil, errors.New("pulsar: v0.3 quorum eval-points count mismatch")
	}

	K, L, _ := modeShape(params.Mode)
	tau, omega, gamma1Bits, gamma2 := modeTauOmega(params.Mode)
	gamma1 := uint32(1) << gamma1Bits
	beta := uint32(tau) * uint32(params.Eta)

	// Index Round-1 by sender; verify session/attempt.
	r1ByID := make(map[NodeID]*AlgebraicRound1Message, len(round1))
	for _, m := range round1 {
		if m.SessionID != sessionID || m.Attempt != attempt {
			return nil, ErrSessionMismatch
		}
		r1ByID[m.NodeID] = m
	}

	// Index Round-2 by sender; verify session/attempt, MAC, and commit-bind.
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
		tau1 := algV03TranscriptTau1(sessionID, attempt, quorum, r2.NodeID, setup.Pub, message)
		commitInput := append(append([]byte{}, r2.W...), tau1...)
		recomputed := transcriptHash32(tagV03R1, commitInput)
		if !ctEqual32(recomputed, r1.Commit) {
			return nil, ErrAlgebraicRound2CommitBad
		}
		// Verify Round-2 MAC (aggregator = quorum[0]).
		if r2.NodeID != quorum[0] {
			aggMACMap, ok := sessionKeys[quorum[0]]
			if !ok {
				return nil, ErrSessionKeyMissing
			}
			key, ok := aggMACMap[r2.NodeID]
			if !ok {
				return nil, ErrSessionKeyMissing
			}
			tau2 := algV03TranscriptTau2(sessionID, attempt, quorum, r2.NodeID, setup.Pub, message, r2.W, r2.Z, r2.CS2, r2.CT0)
			expected := kmac256(key[:], tau2, 32, tagV03R2MAC)
			got, gotOK := r2.MACs[quorum[0]]
			if !gotOK {
				return nil, ErrAlgebraicRound2MACBad
			}
			if !ctEqualSlice(expected, got[:]) {
				return nil, ErrAlgebraicRound2MACBad
			}
		}
		r2ByID[r2.NodeID] = r2
	}
	if len(r2ByID) < threshold {
		return nil, ErrInsufficientQuor
	}

	// Decode every R2 payload and sum.
	//
	// w = Σ w_j         (K polys; standard form)
	// z = Σ z_j         (L polys; standard form ≡ y_total + c·s_1)
	// cs2 = Σ cs2_j     (K polys; standard form ≡ c·s_2)
	// ct0 = Σ ct0_j     (K polys; standard form ≡ c·t_0)
	w := make(polyVec, K)
	z := make(polyVec, L)
	cs2 := make(polyVec, K)
	ct0 := make(polyVec, K)

	taken := 0
	for _, r2 := range round2 {
		if _, ok := r2ByID[r2.NodeID]; !ok {
			continue
		}
		wj := unpackPolyVec(r2.W, K)
		zj := unpackPolyVec(r2.Z, L)
		cs2j := unpackPolyVec(r2.CS2, K)
		ct0j := unpackPolyVec(r2.CT0, K)
		for k := 0; k < K; k++ {
			w[k].add(&w[k], &wj[k])
		}
		for l := 0; l < L; l++ {
			z[l].add(&z[l], &zj[l])
		}
		for k := 0; k < K; k++ {
			cs2[k].add(&cs2[k], &cs2j[k])
		}
		for k := 0; k < K; k++ {
			ct0[k].add(&ct0[k], &ct0j[k])
		}
		taken++
		if taken == threshold {
			break
		}
	}
	// Normalise each sum.
	for k := 0; k < K; k++ {
		w[k].normalize()
		cs2[k].normalize()
		ct0[k].normalize()
	}
	for l := 0; l < L; l++ {
		z[l].normalize()
	}

	// Compute (w_1, w_0+q) := Decompose(w). decomposeVec returns
	// (high, lowPlusQ) so high = w_1 and lowPlusQ = w_0+q (FIPS 204
	// §4.5 naming).
	w1, w0PlusQ := decomposeVec(w, gamma2)

	// Re-derive c̃ from (μ, w_1). Must match what each party computed
	// in Round 2Sign so that c = SampleInBall(c̃) yields the same c the
	// parties used.
	w1Packed := packW1Vec(w1, gamma2, K)
	// μ = SHAKE-256(tr || M', 64) where M' = 0x00 || |ctx| || ctx || M
	// per FIPS 204 §5.4 step 2. Must match Round-2 mu derivation.
	var mu [64]byte
	{
		h := sha3.NewShake256()
		_, _ = h.Write(setup.Tr[:])
		_, _ = h.Write([]byte{0x00, 0x00})
		_, _ = h.Write(message)
		_, _ = h.Read(mu[:])
	}
	cTildeSize := modeCTildeSize(params.Mode)
	cTilde := make([]byte, cTildeSize)
	{
		h := sha3.NewShake256()
		_, _ = h.Write(mu[:])
		_, _ = h.Write(w1Packed)
		_, _ = h.Read(cTilde)
	}

	// FIPS 204 sign-side rejection-check sequence (circl SignTo lines
	// 413-466 verbatim, with our algebraic (z, cs2, ct0) replacing the
	// single-party sk-derived (z, c·s_2, c·t_0)).
	//
	// (1) ||w_0 - c·s_2||_∞ < γ_2 - β  ?
	//
	// In circl: w0_mcs2 = w0 - c·s_2, normalize. Note w_0 is stored as
	// w_0+q (per FIPS 204 decompose convention); subtracting c·s_2
	// while in standard form means w0PlusQ - cs2 in [0, 2q) and then
	// normalise.
	w0_mcs2 := make(polyVec, K)
	for k := 0; k < K; k++ {
		w0_mcs2[k].sub(&w0PlusQ[k], &cs2[k])
		w0_mcs2[k].normalize()
	}
	if polyVecExceeds(w0_mcs2, gamma2-beta) {
		return nil, ErrAlgebraicRestart
	}

	// (2) ||z||_∞ < γ_1 - β ?
	if polyVecExceeds(z, gamma1-beta) {
		return nil, ErrAlgebraicRestart
	}

	// (3) ||c·t_0||_∞ < γ_2 ?
	if polyVecExceeds(ct0, gamma2) {
		return nil, ErrAlgebraicRestart
	}

	// (4) Hint h := MakeHint(w0_mcs2 + c·t_0, w_1).
	w0_mcs2_pct0 := make(polyVec, K)
	for k := 0; k < K; k++ {
		w0_mcs2_pct0[k].add(&w0_mcs2[k], &ct0[k])
		w0_mcs2_pct0[k].normalizeAssumingLe2Q()
	}
	hint := make(polyVec, K)
	var pop uint32
	for k := 0; k < K; k++ {
		pop += hint[k].makeHint(&w0_mcs2_pct0[k], &w1[k], gamma2)
	}
	if pop > uint32(omega) {
		return nil, ErrAlgebraicRestart
	}

	// (5) sigEncode(c̃, z, hint) per FIPS 204 Algorithm 28.
	sigBytes := make([]byte, params.SignatureSize)
	copy(sigBytes[:cTildeSize], cTilde)
	off := cTildeSize
	polyLeGamma1Size := int((uint32(gamma1Bits) + 1) * mldsaN / 8)
	for l := 0; l < L; l++ {
		polyPackLeGamma1(&z[l], sigBytes[off:off+polyLeGamma1Size], uint32(gamma1Bits))
		off += polyLeGamma1Size
	}
	// Hint encoding: ω + K bytes per FIPS 204 §7.2.
	polyVecPackHint(hint, sigBytes[off:off+omega+K], omega)

	return &Signature{Mode: params.Mode, Bytes: sigBytes}, nil
}

// polyVecExceeds returns true if any polynomial in v has a coefficient
// whose central-rep absolute value is ≥ bound.
//
// Assumes every coefficient of every polynomial in v is normalised
// in [0, q).
func polyVecExceeds(v polyVec, bound uint32) bool {
	for i := range v {
		if v[i].exceeds(bound) {
			return true
		}
	}
	return false
}

// algV03TranscriptTau1 builds the Round-1 transcript τ_1 for v0.3.
// Distinct from algTranscriptTau1 (v0.2) so a cross-version replay
// fails at the transcript hash. The "V03" string is bound into parts[0].
func algV03TranscriptTau1(sid [16]byte, attempt uint32, quorum []NodeID, sender NodeID, pk *PublicKey, message []byte) []byte {
	var attemptBE [4]byte
	binary.BigEndian.PutUint32(attemptBE[:], attempt)
	parts := make([][]byte, 0, 4+len(quorum)+2)
	parts = append(parts, []byte("V03"), sid[:], attemptBE[:])
	for _, q := range quorum {
		parts = append(parts, q[:])
	}
	parts = append(parts, sender[:])
	if pk != nil {
		parts = append(parts, pk.Bytes)
	}
	parts = append(parts, message)
	out := append([]byte{}, leftEncode(uint64(len(parts)))...)
	for _, p := range parts {
		out = append(out, encodeString(p)...)
	}
	return out
}

// algV03TranscriptTau2 builds the Round-2 transcript binding the full
// per-party payload. MAC is taken over this transcript so any tamper
// in (W, Z, CS2, CT0) flips the MAC.
func algV03TranscriptTau2(sid [16]byte, attempt uint32, quorum []NodeID, sender NodeID, pk *PublicKey, message, w, z, cs2, ct0 []byte) []byte {
	var attemptBE [4]byte
	binary.BigEndian.PutUint32(attemptBE[:], attempt)
	parts := make([][]byte, 0, 8+len(quorum)+1)
	parts = append(parts, []byte("V03-R2"), sid[:], attemptBE[:])
	for _, q := range quorum {
		parts = append(parts, q[:])
	}
	parts = append(parts, sender[:])
	if pk != nil {
		parts = append(parts, pk.Bytes)
	}
	parts = append(parts, message, w, z, cs2, ct0)
	out := append([]byte{}, leftEncode(uint64(len(parts)))...)
	for _, p := range parts {
		out = append(out, encodeString(p)...)
	}
	return out
}

// V03QuorumEvalPoints helper: given a slice of AlgebraicKeyShares
// whose NodeIDs match the quorum (in any order), returns the EvalPoint
// vector in the SAME canonical-sorted order as the quorum.
func V03QuorumEvalPoints(quorum []NodeID, shares []*AlgebraicKeyShare) ([]uint32, error) {
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
