// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package dkg2 implements a Pedersen-style verifiable-secret-sharing-based
// distributed key generation over the Pulsar polynomial ring
// R_q = Z_q[X]/(X^256 + 1).
//
// dkg2 is the production parallel-track keygen for Pulsar. It replaces the
// pseudoinverse-recoverable Feldman commit C_k = A · NTT(c_k) of the
// upstream Ringtail DKG with a Pedersen commit
//
//	C_{i,k} = A · NTT(c_{i,k}) + B · NTT(r_{i,k})           (R_q^M, NTT-Mont)
//
// where A, B are independent uniform public matrices derived deterministically
// from nothing-up-my-sleeve domain-separation tags. Hiding holds under
// decisional MLWE on B; binding holds under MSIS on the wide concatenation
// [A | B]. Formal statements live in
// papers/lp-073-pulsar/sections/07-pedersen-dkg.tex; Lean theorem references
// are in proofs/lean/Crypto/Pulsar/dkg2.lean.
//
// # Round structure
//
//	Round 1   Each party samples Gaussian f_i, g_i in R_q^Nvec[x]_{deg<t},
//	          broadcasts {C_{i,k}}_{k=0..t-1}, sends (share_{i→j}, blind_{i→j})
//	          privately to each recipient j over an authenticated p2p channel.
//
//	Round 1.5 Every party broadcasts H_i = HashSuite.TranscriptHash(serialize
//	          (C_{i,0}) || ... || serialize(C_{i,t-1})). Recipients compare
//	          digests received from each sender across the cohort. Mismatch
//	          → equivocation → signed Complaint (ComplaintEquivocation) →
//	          sender disqualified.
//
//	Round 2   Each recipient j verifies, for every sender i,
//	            A · NTT(share_{i→j}) + B · NTT(blind_{i→j})
//	              ?= Σ_{k=0..t-1} (j+1)^k · C_{i,k}        (mod q)
//	          Verification is exact: both sides are Z_q-linear and NTT is
//	          bijective. Comparison is constant-time across all M·N_vec slots
//	          (subtle.ConstantTimeCompare). On mismatch, recipient emits a
//	          signed Complaint (ComplaintBadDelivery) naming the sender and
//	          carrying (share, blind, commits) as evidence.
//
//	          Aggregation: s_j = Σ_i share_{i→j}, u_j = Σ_i blind_{i→j},
//	          b_ped = Round_Xi(IMForm + INTT(Σ_i C_{i,0})).
//
// # Hash suite
//
// dkg2 routes every cohort-bound digest through the canonical
// hash.HashSuite (Pulsar-SHA3 in production; Pulsar-BLAKE3 retained for
// byte-equality with pre-cutover KATs). NewDKGSession accepts a HashSuite;
// nil resolves to the production default. Matrix derivation (A, B) uses a
// dedicated, version-pinned BLAKE3 path to keep KAT bytes stable across
// the SHA3 cutover — the matrix derivation is structural, not transcript-
// bound, so it has its own version tag (pulsar.dkg2.A.v1 / .B.v1). The
// Round 1.5 commit digest, by contrast, is HashSuite-bound and uses the
// PULSAR-TRANSCRIPT-v1 customization of the active suite.
//
// # Identifiable abort
//
// Round1.5 and Round 2 produce signed Complaint records (Ed25519, mirroring
// reshare.Complaint). Aggregating any DisqualificationThreshold complaints
// against the same sender disqualifies that sender deterministically; every
// honest party that processes the same complaint set computes the same
// disqualified set (FilterQualifiedQuorum).
//
// # File-level invariants
//
//   - All ring arithmetic uses sign.Q (the Pulsar 48-bit prime).
//   - Sampler parameters reuse sign.SigmaE / sign.BoundE for both c_{i,k}
//     and r_{i,k}, mirroring the Pulsar secret distribution.
//   - A is derived from the 16-byte tag b"pulsar.dkg2.A.v1" via BLAKE3-XOF
//     (KAT-pinned).
//   - B is derived from the 16-byte tag b"pulsar.dkg2.B.v1" via BLAKE3-XOF
//     (KAT-pinned).
//   - Commits are stored in NTT-Montgomery form (matches A, B).
//   - Shares are stored in standard coefficient form (NTT=false, mont=false).
//   - Round 2 verifier comparison is constant-time across the M-element LHS/
//     RHS pair (constant-time AND across all M coefficient blobs).
//
// # KAT contract
//
// Round1WithSeed pins every byte of the protocol output for byte-equal C++
// porting. See cmd/dkg2_oracle for the canonical generator and
// luxcpp/crypto/pulsar/dkg2/test/kat/dkg2_kat.json for the 4 reference
// entries (2-of-3, 3-of-5, 5-of-7, 7-of-11).
package dkg2

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/luxfi/pulsar/hash"
	"github.com/luxfi/pulsar/sign"
	"github.com/luxfi/pulsar/utils"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/sampling"
	"github.com/luxfi/lattice/v7/utils/structs"

	"github.com/zeebo/blake3"
)

// Domain-separation tags used to derive the public matrices A, B.
//
// The bytes themselves are nothing-up-my-sleeve: an ASCII string identifying
// the matrix and a version suffix. Changing either tag invalidates every
// KAT and every group public key derived in dkg2 — bump the version when
// breaking compatibility.
//
// Matrix derivation is BLAKE3 directly, NOT the active HashSuite. This keeps
// public-matrix bytes stable across the Pulsar-SHA3 cutover (the matrices
// are structural, not transcript-bound; their version tag covers any future
// rotation).
var (
	tagA = []byte("pulsar.dkg2.A.v1")
	tagB = []byte("pulsar.dkg2.B.v1")
)

// Customization tag bound into the Round 1.5 commit-digest under the active
// HashSuite. The suite ID is bound into the digest input as well so two
// suites can never produce a colliding digest for the same commit vector.
const tagCommitDigest = "PULSAR-DKG2-COMMIT-DIGEST-v1"

var (
	ErrInvalidThreshold  = errors.New("dkg2: threshold must be > 0 and < total parties")
	ErrInvalidPartyCount = errors.New("dkg2: need at least 2 parties")
	ErrInvalidPartyID    = errors.New("dkg2: party ID out of range")
	ErrShareVerification = errors.New("dkg2: share verification failed")
	ErrMissingData       = errors.New("dkg2: missing share, blind, or commitment data")
	ErrCommitMismatch    = errors.New("dkg2: cross-party commitment digest mismatch")
	ErrMalformedCommit   = errors.New("dkg2: commit vector malformed")
	ErrSerialization     = errors.New("dkg2: commit serialization failed")
)

// Params holds ring parameters for the DKG protocol.
//
// Identical to dkg.Params; reused so existing code paths (sign.Q-derived
// rings) match without per-package divergence.
type Params struct {
	R   *ring.Ring
	RXi *ring.Ring
}

// NewParams creates ring parameters for dkg2.
//
// Mirrors dkg.NewParams: the RXi ring is the post-rounding modulus
// (Xi = 30 bits, sign.QXi = 0x40000 = 2^18) — not prime, but that's the
// canonical Pulsar layout used by sign.Gen and the Round2 b_ped output.
// ring.NewRing returns a non-prime-modulus error here that we deliberately
// ignore (matches dkg/dkg.go:53), and the constructor remains usable
// because RoundVector only needs the ring as a coefficient container.
func NewParams() (*Params, error) {
	r, err := ring.NewRing(1<<sign.LogN, []uint64{sign.Q})
	if err != nil {
		return nil, err
	}
	rXi, _ := ring.NewRing(1<<sign.LogN, []uint64{sign.QXi})
	return &Params{R: r, RXi: rXi}, nil
}

// derivePublicMatrix builds an M×Nvec uniform matrix in R_q from a
// nothing-up-my-sleeve tag using BLAKE3 → KeyedPRNG → UniformSampler.
//
// Returned matrix is in NTT-Montgomery form (matches the convention used by
// the Sign Gen path at sign/sign.go:49). BLAKE3 is wired directly here —
// see the package-level documentation for why matrix derivation is
// deliberately suite-independent.
func derivePublicMatrix(r *ring.Ring, tag []byte) (structs.Matrix[ring.Poly], error) {
	h := blake3.New()
	if _, err := h.Write(tag); err != nil {
		return nil, fmt.Errorf("dkg2: derivePublicMatrix: %w", err)
	}
	seed := h.Sum(nil)[:sign.KeySize]
	prng, err := sampling.NewKeyedPRNG(seed)
	if err != nil {
		return nil, fmt.Errorf("dkg2: derivePublicMatrix: %w", err)
	}
	uniform := ring.NewUniformSampler(prng, r)
	return utils.SamplePolyMatrix(r, sign.M, sign.N, uniform, true, true), nil
}

// DeriveA returns the canonical Pedersen-DKG matrix A in NTT-Mont form.
func DeriveA(r *ring.Ring) structs.Matrix[ring.Poly] {
	m, err := derivePublicMatrix(r, tagA)
	if err != nil {
		// derivePublicMatrix failure means BLAKE3 / KeyedPRNG construction
		// failed under fully-controlled inputs — a deterministic crash here
		// is correct (cf. sign/local.go's startup posture).
		panic(err)
	}
	return m
}

// DeriveB returns the canonical Pedersen-DKG matrix B in NTT-Mont form.
func DeriveB(r *ring.Ring) structs.Matrix[ring.Poly] {
	m, err := derivePublicMatrix(r, tagB)
	if err != nil {
		panic(err)
	}
	return m
}

// Round1Output is one party's contribution to Round 1.
//
// Commits[k] is the public Pedersen commitment to (c_{i,k}, r_{i,k}); it is
// broadcast to every other party. Shares[j] and Blinds[j] are the secret
// share-pair sent privately to party j over an authenticated point-to-point
// channel.
type Round1Output struct {
	// Commits[k] = A * NTT(c_{i,k}) + B * NTT(r_{i,k}), length t.
	// Stored in NTT-Montgomery form.
	Commits []structs.Vector[ring.Poly]

	// Shares[j] = f_i(j+1), length n. Standard coefficient form.
	Shares map[int]structs.Vector[ring.Poly]

	// Blinds[j] = g_i(j+1), length n. Standard coefficient form.
	// Sent over the same private channel as Shares[j].
	Blinds map[int]structs.Vector[ring.Poly]
}

// SerializeCommits returns the canonical wire bytes of Commits. Used as the
// hashing pre-image for Round 1.5 digests, equivocation evidence, and KAT
// pinning. Errors on the underlying lattigo WriteTo are surfaced as
// ErrSerialization.
func (r *Round1Output) SerializeCommits() ([]byte, error) {
	var buf bytes.Buffer
	for _, v := range r.Commits {
		if _, err := v.WriteTo(&buf); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrSerialization, err)
		}
	}
	return buf.Bytes(), nil
}

// CommitDigest returns the Round 1.5 cross-party-consistency digest under
// the supplied HashSuite. Passing nil resolves to the production default
// (Pulsar-SHA3); pass hash.NewPulsarBLAKE3() for byte-equal replay against
// the canonical KATs.
//
// Format (suite-agnostic):
//
//	suite.TranscriptHash([]byte(tagCommitDigest), []byte(suite.ID()),
//	                     serialize(Commits[0]) || ... || serialize(Commits[t-1]))
//
// The suite ID is bound in so two suites can never collide on a single
// commit vector. Errors only on serialization failure.
func (r *Round1Output) CommitDigest(suite hash.HashSuite) ([32]byte, error) {
	s := hash.Resolve(suite)
	body, err := r.SerializeCommits()
	if err != nil {
		return [32]byte{}, err
	}
	return s.TranscriptHash([]byte(tagCommitDigest), []byte(s.ID()), body), nil
}

// CommitDigestBLAKE3 returns the legacy BLAKE3 commit digest used by the
// pre-SHA3-cutover KAT (pulsar/dkg2 oracle, luxcpp dkg2_kat.json). Format:
//
//	BLAKE3(serialize(Commits[0]) || ... || serialize(Commits[t-1]))[:32]
//
// Kept for byte-stable replay only — production code paths SHOULD use
// CommitDigest(hash.Default()).
func (r *Round1Output) CommitDigestBLAKE3() ([32]byte, error) {
	body, err := r.SerializeCommits()
	if err != nil {
		return [32]byte{}, err
	}
	h := blake3.New()
	if _, err := h.Write(body); err != nil {
		return [32]byte{}, fmt.Errorf("%w: %v", ErrSerialization, err)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil)[:32])
	return out, nil
}

// DKGSession tracks the state of one party in the dkg2 protocol.
type DKGSession struct {
	params  *Params
	partyID int
	n       int
	t       int
	suite   hash.HashSuite

	A structs.Matrix[ring.Poly] // public uniform M×Nvec, NTT-Mont
	B structs.Matrix[ring.Poly] // public uniform M×Nvec, NTT-Mont

	// Stashed across Round1 → Round2 for self-consistency checks.
	// Standard coefficient form (NTT=false, mont=false).
	cCoeffs []structs.Vector[ring.Poly] // f_i polynomial coeffs (length t)
	rCoeffs []structs.Vector[ring.Poly] // g_i polynomial coeffs (length t)
}

// NewDKGSession initializes a Pedersen DKG session for the given party.
//
// suite parameterizes the cohort-bound hash routines (Round 1.5 commit
// digest, complaint transcripts). nil resolves to the production default
// (Pulsar-SHA3). Public-matrix derivation is deliberately HashSuite-
// independent — it uses a dedicated BLAKE3 path so KAT bytes stay stable
// across the Pulsar-SHA3 cutover (see package documentation).
//
// Mirrors dkg.NewDKGSession exactly except that the matrices A, B are
// derived from public domain-separated tags via BLAKE3, removing the
// "all-zero seedKey" footgun present in dkg/dkg.go:99-105.
func NewDKGSession(params *Params, partyID, n, t int, suite hash.HashSuite) (*DKGSession, error) {
	if n < 2 {
		return nil, ErrInvalidPartyCount
	}
	if t < 1 || t >= n {
		return nil, ErrInvalidThreshold
	}
	if partyID < 0 || partyID >= n {
		return nil, ErrInvalidPartyID
	}

	// Set globals consumed by the Sign package (mirrors dkg/dkg.go).
	sign.K = n
	sign.Threshold = t

	A := DeriveA(params.R)
	B := DeriveB(params.R)

	return &DKGSession{
		params:  params,
		partyID: partyID,
		n:       n,
		t:       t,
		suite:   hash.Resolve(suite),
		A:       A,
		B:       B,
	}, nil
}

// APublic returns the public matrix A. Exposed for KAT pinning.
func (d *DKGSession) APublic() structs.Matrix[ring.Poly] { return d.A }

// BPublic returns the public matrix B. Exposed for KAT pinning.
func (d *DKGSession) BPublic() structs.Matrix[ring.Poly] { return d.B }

// PartyID returns the party ID for this session.
func (d *DKGSession) PartyID() int { return d.partyID }

// N returns the total party count.
func (d *DKGSession) N() int { return d.n }

// T returns the threshold.
func (d *DKGSession) T() int { return d.t }

// HashSuite returns the cohort-bound hash suite this session uses.
func (d *DKGSession) HashSuite() hash.HashSuite { return d.suite }

// Round1 generates the party's random polynomials f_i, g_i, computes
// commitments, and computes shares (and blinds) for all other parties.
//
// Uses crypto/rand for the per-party Gaussian PRNG seed. For deterministic
// testing / KAT generation, use Round1WithSeed.
func (d *DKGSession) Round1() (*Round1Output, error) {
	seed := make([]byte, sign.KeySize)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, fmt.Errorf("dkg2: random read: %w", err)
	}
	return d.Round1WithSeed(seed)
}

// Round1WithSeed is the deterministic variant of Round1. Same seed →
// byte-equal output for a given (partyID, n, t, A, B) tuple.
//
// Sampling order (BYTE-PINNED — must match the C++ port):
//
//	1. KeyedPRNG(seed) → Gaussian sampler (σ_E, β_E).
//	2. For k = 0..t-1:    sample c_{i,k} (Nvec polys, standard form).
//	3. For k = 0..t-1:    sample r_{i,k} (Nvec polys, standard form).
//	4. Compute commits[k] = A*NTT(c_k) + B*NTT(r_k).
//	5. Compute shares[j], blinds[j] via Horner over the (j+1) point.
//
// The two-pass sample order (all c's first, then all r's) matters for byte
// equality across the Go reference and the C++ port.
func (d *DKGSession) Round1WithSeed(seed []byte) (*Round1Output, error) {
	if len(seed) != sign.KeySize {
		return nil, fmt.Errorf("dkg2: Round1WithSeed: expected %d-byte seed, got %d", sign.KeySize, len(seed))
	}
	r := d.params.R

	prng, err := sampling.NewKeyedPRNG(seed)
	if err != nil {
		return nil, err
	}
	gauss := ring.NewGaussianSampler(prng, r,
		ring.DiscreteGaussian{Sigma: sign.SigmaE, Bound: sign.BoundE}, false)

	// Step 2: sample t coefficient vectors c_{i,k} in standard form.
	d.cCoeffs = make([]structs.Vector[ring.Poly], d.t)
	for k := 0; k < d.t; k++ {
		d.cCoeffs[k] = utils.SamplePolyVector(r, sign.N, gauss, false, false)
	}

	// Step 3: sample t coefficient vectors r_{i,k} in standard form.
	d.rCoeffs = make([]structs.Vector[ring.Poly], d.t)
	for k := 0; k < d.t; k++ {
		d.rCoeffs[k] = utils.SamplePolyVector(r, sign.N, gauss, false, false)
	}

	// Step 4: build Pedersen commits C_k = A·NTT(c_k) + B·NTT(r_k).
	commits := make([]structs.Vector[ring.Poly], d.t)
	for k := 0; k < d.t; k++ {
		// NTT-form copies of the secret coefficients.
		cNTT := make(structs.Vector[ring.Poly], sign.N)
		rNTT := make(structs.Vector[ring.Poly], sign.N)
		for i := 0; i < sign.N; i++ {
			cNTT[i] = *d.cCoeffs[k][i].CopyNew()
			r.NTT(cNTT[i], cNTT[i])
			rNTT[i] = *d.rCoeffs[k][i].CopyNew()
			r.NTT(rNTT[i], rNTT[i])
		}
		ac := utils.InitializeVector(r, sign.M)
		utils.MatrixVectorMul(r, d.A, cNTT, ac)
		br := utils.InitializeVector(r, sign.M)
		utils.MatrixVectorMul(r, d.B, rNTT, br)
		commits[k] = utils.InitializeVector(r, sign.M)
		utils.VectorAdd(r, ac, br, commits[k])
	}

	// Step 5: build shares and blinds via Horner over (j+1) for each j.
	q := new(big.Int).SetUint64(sign.Q)
	shares := make(map[int]structs.Vector[ring.Poly], d.n)
	blinds := make(map[int]structs.Vector[ring.Poly], d.n)
	for j := 0; j < d.n; j++ {
		x := big.NewInt(int64(j + 1))
		shares[j] = hornerEval(r, d.cCoeffs, x, q)
		blinds[j] = hornerEval(r, d.rCoeffs, x, q)
	}

	return &Round1Output{
		Commits: commits,
		Shares:  shares,
		Blinds:  blinds,
	}, nil
}

// hornerEval computes f(x) = Σ_k coeffs[k] * x^k in standard coefficient
// form over R_q^Nvec. Horner's method: f(x) = c_0 + x·(c_1 + x·(c_2 + …)).
//
// The arithmetic is performed by big.Int per coefficient mod q; the
// resulting Vector[Poly] is returned in standard coefficient form.
func hornerEval(r *ring.Ring, coeffs []structs.Vector[ring.Poly], x, q *big.Int) structs.Vector[ring.Poly] {
	t := len(coeffs)
	result := make(structs.Vector[ring.Poly], sign.N)
	for vi := 0; vi < sign.N; vi++ {
		result[vi] = r.NewPoly()
	}
	for k := t - 1; k >= 0; k-- {
		for vi := 0; vi < sign.N; vi++ {
			if k < t-1 {
				polyMulScalar(r, result[vi], x, q)
			}
			polyAddCoeffwise(r, result[vi], coeffs[k][vi], q)
		}
	}
	return result
}

// VerifyShareAgainstCommits checks the Pedersen identity
//
//	A · NTT(share) + B · NTT(blind)  ?=  Σ_{k=0..t-1} (recipientID+1)^k · commits[k]
//
// in NTT-Montgomery form (mod sign.Q). Returns (true, nil) on a valid pair,
// (false, ErrShareVerification) on a Pedersen mismatch, and a wrapped
// ErrMissingData / ErrMalformedCommit when inputs are absent or malformed.
//
// Comparison is constant-time across all M·N coefficient slots — no
// short-circuit on the first mismatched slot, which matches the response to
// Findings 5/6 of luxcpp/crypto/ringtail/RED-DKG-REVIEW.md.
//
// recipientID is 0-indexed (the (j+1) shift to the Lagrange evaluation
// point is applied internally).
func VerifyShareAgainstCommits(
	params *Params,
	A, B structs.Matrix[ring.Poly],
	share, blind structs.Vector[ring.Poly],
	commits []structs.Vector[ring.Poly],
	recipientID int,
	threshold int,
) (bool, error) {
	r := params.R
	if len(share) != sign.N || len(blind) != sign.N {
		return false, fmt.Errorf("%w: share/blind length mismatch", ErrMalformedCommit)
	}
	if len(commits) != threshold {
		return false, fmt.Errorf("%w: %d commits, expected %d", ErrMalformedCommit, len(commits), threshold)
	}
	for k, v := range commits {
		if len(v) != sign.M {
			return false, fmt.Errorf("%w: commit[%d] dim %d, expected %d", ErrMalformedCommit, k, len(v), sign.M)
		}
	}

	q := new(big.Int).SetUint64(sign.Q)

	// LHS_share = A · NTT(share)
	shareNTT := make(structs.Vector[ring.Poly], sign.N)
	for vi := 0; vi < sign.N; vi++ {
		shareNTT[vi] = *share[vi].CopyNew()
		r.NTT(shareNTT[vi], shareNTT[vi])
	}
	ash := utils.InitializeVector(r, sign.M)
	utils.MatrixVectorMul(r, A, shareNTT, ash)

	// LHS_blind = B · NTT(blind)
	blindNTT := make(structs.Vector[ring.Poly], sign.N)
	for vi := 0; vi < sign.N; vi++ {
		blindNTT[vi] = *blind[vi].CopyNew()
		r.NTT(blindNTT[vi], blindNTT[vi])
	}
	bbl := utils.InitializeVector(r, sign.M)
	utils.MatrixVectorMul(r, B, blindNTT, bbl)

	lhs := utils.InitializeVector(r, sign.M)
	utils.VectorAdd(r, ash, bbl, lhs)

	// RHS = Σ_k (recipientID+1)^k · commits[k] via Horner in NTT domain.
	x := big.NewInt(int64(recipientID + 1))
	rhs := utils.InitializeVector(r, sign.M)
	for k := threshold - 1; k >= 0; k-- {
		if k < threshold-1 {
			for ri := 0; ri < sign.M; ri++ {
				polyMulScalarNTT(r, rhs[ri], x, q)
			}
		}
		utils.VectorAdd(r, rhs, commits[k], rhs)
	}

	// Constant-time compare across all M slots, all coefficient levels.
	// subtle.ConstantTimeCompare returns 1 iff equal; AND across slots.
	eq := 1
	for ri := 0; ri < sign.M; ri++ {
		eq &= constTimePolyEqual(lhs[ri], rhs[ri])
	}
	if eq != 1 {
		return false, ErrShareVerification
	}
	return true, nil
}

// constTimePolyEqual returns 1 iff a and b have identical coefficient
// arrays at every level, 0 otherwise. The comparison runs in time
// independent of how many coefficients differ — a full scan is always
// performed (no early return).
//
// This is the dkg2 response to Findings 5/6 of
// luxcpp/crypto/ringtail/RED-DKG-REVIEW.md, which note that the Round 2
// share-comparison loop in the upstream dkg/ package short-circuits on the
// first slot mismatch and so leaks the location of any planted divergence
// to a network observer measuring response timing.
func constTimePolyEqual(a, b ring.Poly) int {
	if len(a.Coeffs) != len(b.Coeffs) {
		return 0
	}
	eq := 1
	for level := range a.Coeffs {
		al := a.Coeffs[level]
		bl := b.Coeffs[level]
		if len(al) != len(bl) {
			eq = 0
			continue
		}
		// Reinterpret each Coeffs[level] as a byte buffer and feed it
		// to subtle.ConstantTimeCompare. uint64 little-endian coefficient
		// layout is byte-stable on every supported target (amd64, arm64).
		ab := uint64SliceToBytes(al)
		bb := uint64SliceToBytes(bl)
		eq &= subtle.ConstantTimeCompare(ab, bb)
	}
	return eq
}

// uint64SliceToBytes returns a little-endian byte view of a []uint64. The
// caller must not retain the result past the lifetime of the input.
func uint64SliceToBytes(s []uint64) []byte {
	b := make([]byte, 8*len(s))
	for i, v := range s {
		binary.LittleEndian.PutUint64(b[8*i:8*i+8], v)
	}
	return b
}

// Round2 verifies received shares (and blinds) against commitments, then
// aggregates to (s_j, u_j) plus the Pedersen-shaped group public key.
//
// On a verification failure Round2 returns the global ErrShareVerification
// without identifying the offending sender. For identifiable abort use
// Round2Identify, which returns the failing sender ID and produces a
// signed Complaint suitable for slashing evidence.
//
//	receivedShares  maps sender i → share i computed for THIS party (j).
//	receivedBlinds  maps sender i → blind i computed for THIS party (j).
//	receivedCommits maps sender i → that sender's t-element commit vector.
//
// Returns (s_j, u_j, b_ped) on success.
//
//	s_j   = Σ_i share_{i→j}    (Pulsar secret share)
//	u_j   = Σ_i blind_{i→j}    (private; discarded by Pulsar Sign callers)
//	b_ped = Σ_i C_{i,0}        (rounded to Xi, Pedersen-shaped pk)
//
// b_ped has shape Round_Xi(A·s + B·t_master). Pulsar Sign verification
// running in 2-secret mode (path (b)) takes (A, B, b_ped) jointly; see
// papers/lp-073-pulsar/sections/07-pedersen-dkg.tex §Mapping for the
// integration recipe.
func (d *DKGSession) Round2(
	receivedShares map[int]structs.Vector[ring.Poly],
	receivedBlinds map[int]structs.Vector[ring.Poly],
	receivedCommits map[int][]structs.Vector[ring.Poly],
) (structs.Vector[ring.Poly], structs.Vector[ring.Poly], structs.Vector[ring.Poly], error) {
	s, u, b, _, err := d.round2Internal(receivedShares, receivedBlinds, receivedCommits, false)
	return s, u, b, err
}

// Round2Identify is the identifiable-abort variant of Round2. On success
// returns (s_j, u_j, b_ped, -1, nil). On a Pedersen-mismatch failure
// returns (nil, nil, nil, senderID, wrapped ErrShareVerification) where
// senderID is the first sender in iteration order whose share/blind
// fails the verification. The caller may immediately produce a signed
// ComplaintBadDelivery for that sender via NewBadDeliveryComplaint.
//
// On a missing-input failure returns (nil, nil, nil, senderID,
// wrapped ErrMissingData) where senderID names the absent sender.
func (d *DKGSession) Round2Identify(
	receivedShares map[int]structs.Vector[ring.Poly],
	receivedBlinds map[int]structs.Vector[ring.Poly],
	receivedCommits map[int][]structs.Vector[ring.Poly],
) (structs.Vector[ring.Poly], structs.Vector[ring.Poly], structs.Vector[ring.Poly], int, error) {
	return d.round2Internal(receivedShares, receivedBlinds, receivedCommits, true)
}

// round2Internal is the shared implementation behind Round2 and
// Round2Identify. When identify=true the senderID return value names the
// first failing sender on error; otherwise it returns -1.
func (d *DKGSession) round2Internal(
	receivedShares map[int]structs.Vector[ring.Poly],
	receivedBlinds map[int]structs.Vector[ring.Poly],
	receivedCommits map[int][]structs.Vector[ring.Poly],
	identify bool,
) (structs.Vector[ring.Poly], structs.Vector[ring.Poly], structs.Vector[ring.Poly], int, error) {
	r := d.params.R

	// Sanity: every party 0..n-1 must contribute share, blind, commits.
	for i := 0; i < d.n; i++ {
		if _, ok := receivedShares[i]; !ok {
			id := -1
			if identify {
				id = i
			}
			return nil, nil, nil, id, fmt.Errorf("%w: missing share from party %d", ErrMissingData, i)
		}
		if _, ok := receivedBlinds[i]; !ok {
			id := -1
			if identify {
				id = i
			}
			return nil, nil, nil, id, fmt.Errorf("%w: missing blind from party %d", ErrMissingData, i)
		}
		if _, ok := receivedCommits[i]; !ok {
			id := -1
			if identify {
				id = i
			}
			return nil, nil, nil, id, fmt.Errorf("%w: missing commitment from party %d", ErrMissingData, i)
		}
	}

	q := new(big.Int).SetUint64(sign.Q)

	// Verification: A·NTT(share_i) + B·NTT(blind_i) ?= Σ_k (j+1)^k · C_{i,k}
	for i := 0; i < d.n; i++ {
		ok, err := VerifyShareAgainstCommits(
			d.params, d.A, d.B,
			receivedShares[i], receivedBlinds[i], receivedCommits[i],
			d.partyID, d.t,
		)
		if err != nil {
			id := -1
			if identify {
				id = i
			}
			if errors.Is(err, ErrMalformedCommit) {
				return nil, nil, nil, id, fmt.Errorf("party %d commit malformed: %w", i, err)
			}
			return nil, nil, nil, id, fmt.Errorf("%w: party %d share/blind do not match commitment", ErrShareVerification, i)
		}
		if !ok {
			// Defensive: VerifyShareAgainstCommits returns (false, err) in
			// lockstep, so this branch is unreachable. Keep for clarity.
			id := -1
			if identify {
				id = i
			}
			return nil, nil, nil, id, fmt.Errorf("%w: party %d", ErrShareVerification, i)
		}
	}

	// Aggregate s_j = Σ_i share_{i→j} (coefficient-domain add).
	s := make(structs.Vector[ring.Poly], sign.N)
	for vi := 0; vi < sign.N; vi++ {
		s[vi] = r.NewPoly()
	}
	for i := 0; i < d.n; i++ {
		for vi := 0; vi < sign.N; vi++ {
			polyAddCoeffwise(r, s[vi], receivedShares[i][vi], q)
		}
	}

	// Aggregate u_j = Σ_i blind_{i→j} (coefficient-domain add).
	u := make(structs.Vector[ring.Poly], sign.N)
	for vi := 0; vi < sign.N; vi++ {
		u[vi] = r.NewPoly()
	}
	for i := 0; i < d.n; i++ {
		for vi := 0; vi < sign.N; vi++ {
			polyAddCoeffwise(r, u[vi], receivedBlinds[i][vi], q)
		}
	}

	// Public key: b_ped = Round_Xi(IMForm + INTT(Σ_i C_{i,0})).
	pkNTT := utils.InitializeVector(r, sign.M)
	for i := 0; i < d.n; i++ {
		utils.VectorAdd(r, pkNTT, receivedCommits[i][0], pkNTT)
	}
	utils.ConvertVectorFromNTT(r, pkNTT)
	bPed := utils.RoundVector(r, d.params.RXi, pkNTT, sign.Xi)

	return s, u, bPed, -1, nil
}

// AggregateUnroundedCommit returns Σ_i C_{i,0} in NTT-Mont form (no
// rounding, no IMForm/INTT). Used by sign-after-DKG path (b) integration
// where the verifier needs the *unrounded* Pedersen commitment to recompute
// the verification equation.
func AggregateUnroundedCommit(
	params *Params,
	commits map[int][]structs.Vector[ring.Poly],
	n int,
) (structs.Vector[ring.Poly], error) {
	r := params.R
	for i := 0; i < n; i++ {
		if _, ok := commits[i]; !ok {
			return nil, fmt.Errorf("%w: missing commitment from party %d", ErrMissingData, i)
		}
	}
	pkNTT := utils.InitializeVector(r, sign.M)
	for i := 0; i < n; i++ {
		utils.VectorAdd(r, pkNTT, commits[i][0], pkNTT)
	}
	return pkNTT, nil
}

// polyMulScalar multiplies each coefficient of p by scalar s mod q
// (coefficient domain). Mirrors dkg.polyMulScalar.
func polyMulScalar(r *ring.Ring, p ring.Poly, s, q *big.Int) {
	degree := r.N()
	for i := 0; i < degree; i++ {
		if p.Coeffs[0] == nil {
			return
		}
		val := new(big.Int).SetUint64(p.Coeffs[0][i])
		val.Mul(val, s)
		val.Mod(val, q)
		p.Coeffs[0][i] = val.Uint64()
	}
}

// polyAddCoeffwise adds b into a coefficient-wise mod q (coefficient domain).
func polyAddCoeffwise(r *ring.Ring, a, b ring.Poly, q *big.Int) {
	degree := r.N()
	if a.Coeffs[0] == nil {
		a.Coeffs[0] = make([]uint64, degree)
	}
	bCoeffs := b.Coeffs[0]
	if bCoeffs == nil {
		return
	}
	for i := 0; i < degree; i++ {
		val := new(big.Int).SetUint64(a.Coeffs[0][i])
		val.Add(val, new(big.Int).SetUint64(bCoeffs[i]))
		val.Mod(val, q)
		a.Coeffs[0][i] = val.Uint64()
	}
}

// polyMulScalarNTT multiplies each NTT coefficient of p by scalar s mod q.
// Mirrors dkg.polyMulScalarNTT.
func polyMulScalarNTT(r *ring.Ring, p ring.Poly, s, q *big.Int) {
	degree := r.N()
	for level := range p.Coeffs {
		for i := 0; i < degree; i++ {
			val := new(big.Int).SetUint64(p.Coeffs[level][i])
			val.Mul(val, s)
			val.Mod(val, q)
			p.Coeffs[level][i] = val.Uint64()
		}
	}
}

// EncodeUint32BE writes x in big-endian into a 4-byte slice. Used by the
// KAT oracle; declared here so the C++ port can match seed-derivation
// without depending on the oracle binary.
func EncodeUint32BE(x uint32) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], x)
	return buf[:]
}
