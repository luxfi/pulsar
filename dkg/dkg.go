// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package dkg implements Feldman's Verifiable Secret Sharing (VSS)
// based distributed key generation over the polynomial ring R_q.
//
// Protocol:
//  1. Each party i generates random polynomial f_i(x) of degree t-1 over R_q
//  2. Each party i computes share f_i(j) for every party j
//  3. Each party i broadcasts commitment C_i = A * f_i(0) (public)
//  4. Each party j verifies received shares against commitments
//  5. Final secret share: s_j = sum(f_i(j)) for all i
//  6. Public key: bTilde = sum(C_i) for all i
package dkg

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/luxfi/pulsar/primitives"
	"github.com/luxfi/pulsar/sign"
	"github.com/luxfi/pulsar/utils"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/sampling"
	"github.com/luxfi/lattice/v7/utils/structs"
)

var (
	ErrInvalidThreshold  = errors.New("dkg: threshold must be > 0 and < total parties")
	ErrInvalidPartyCount = errors.New("dkg: need at least 2 parties")
	ErrInvalidPartyID    = errors.New("dkg: party ID out of range")
	ErrShareVerification = errors.New("dkg: share verification failed")
	ErrMissingData       = errors.New("dkg: missing share or commitment data")
)

// Params holds ring parameters for the DKG protocol.
type Params struct {
	R   *ring.Ring
	RXi *ring.Ring
}

// NewParams creates ring parameters for DKG.
func NewParams() (*Params, error) {
	r, err := ring.NewRing(1<<sign.LogN, []uint64{sign.Q})
	if err != nil {
		return nil, err
	}
	rXi, _ := ring.NewRing(1<<sign.LogN, []uint64{sign.QXi})
	return &Params{R: r, RXi: rXi}, nil
}

// Round1Output is the data a party produces in Round 1.
type Round1Output struct {
	// Commits are the public commitments C_i,k = A * f_i_coeff_k for k = 0..t-1
	// Commits[0] is the main commitment for f_i(0).
	Commits []structs.Vector[ring.Poly]

	// Shares maps party index j -> f_i(j), the secret share for party j.
	Shares map[int]structs.Vector[ring.Poly]
}

// DKGSession tracks the state of the DKG protocol for one party.
type DKGSession struct {
	params  *Params
	partyID int
	n       int // total parties
	t       int // threshold

	// A is the shared public matrix (agreed upon before DKG starts).
	A structs.Matrix[ring.Poly]

	// Secret polynomial coefficients: f_i(x) = coeff[0] + coeff[1]*x + ... + coeff[t-1]*x^{t-1}
	// Each coeff[k] is a vector of ring.Poly (same dimension as secret key).
	coeffs []structs.Vector[ring.Poly]
}

// NewDKGSession initializes a DKG session for the given party.
func NewDKGSession(params *Params, partyID, n, t int) (*DKGSession, error) {
	if n < 2 {
		return nil, ErrInvalidPartyCount
	}
	if t < 1 || t >= n {
		return nil, ErrInvalidThreshold
	}
	if partyID < 0 || partyID >= n {
		return nil, ErrInvalidPartyID
	}

	// Set global params used by sign package
	sign.K = n
	sign.Threshold = t

	// Generate shared public matrix A (deterministic from a fixed seed so all parties agree).
	// In practice A is distributed out-of-band. Here we derive from a fixed seed.
	seedKey := make([]byte, sign.KeySize)
	prng, err := sampling.NewKeyedPRNG(seedKey)
	if err != nil {
		return nil, err
	}
	uniformSampler := ring.NewUniformSampler(prng, params.R)
	A := utils.SamplePolyMatrix(params.R, sign.M, sign.N, uniformSampler, true, true)

	return &DKGSession{
		params:  params,
		partyID: partyID,
		n:       n,
		t:       t,
		A:       A,
	}, nil
}

// Round1 generates the party's random polynomial f_i(x) of degree t-1,
// computes commitments and shares for all other parties.
//
// Uses crypto/rand for the per-party Gaussian PRNG seed. For deterministic
// testing / KAT generation, use Round1WithSeed.
func (d *DKGSession) Round1() (*Round1Output, error) {
	randKey := make([]byte, sign.KeySize)
	if _, err := io.ReadFull(rand.Reader, randKey); err != nil {
		return nil, fmt.Errorf("dkg: random read: %w", err)
	}
	return d.Round1WithSeed(randKey)
}

// Round1WithSeed is the deterministic variant of Round1: the caller supplies
// the 32-byte seed used to key the Gaussian PRNG. Same seed → same Round1Output
// for a given (partyID, n, t, A) tuple. Used by the KAT oracle to pin every
// Round1 byte stream.
func (d *DKGSession) Round1WithSeed(seed []byte) (*Round1Output, error) {
	if len(seed) != sign.KeySize {
		return nil, fmt.Errorf("dkg: Round1WithSeed: expected %d-byte seed, got %d", sign.KeySize, len(seed))
	}
	r := d.params.R

	// Sample random polynomial coefficients: f_i(x) = c0 + c1*x + ... + c_{t-1}*x^{t-1}
	// Each coefficient is a vector in R_q^N (same shape as a secret key share).
	d.coeffs = make([]structs.Vector[ring.Poly], d.t)

	prng, err := sampling.NewKeyedPRNG(seed)
	if err != nil {
		return nil, err
	}
	gaussianParams := ring.DiscreteGaussian{Sigma: sign.SigmaE, Bound: sign.BoundE}
	gaussianSampler := ring.NewGaussianSampler(prng, r, gaussianParams, false)

	for k := 0; k < d.t; k++ {
		d.coeffs[k] = utils.SamplePolyVector(r, sign.N, gaussianSampler, false, false)
	}

	// Compute commitments: C_k = A * coeff[k] for each polynomial coefficient
	commits := make([]structs.Vector[ring.Poly], d.t)
	for k := 0; k < d.t; k++ {
		// Convert coefficient to NTT for multiplication
		coeffNTT := make(structs.Vector[ring.Poly], sign.N)
		for i := 0; i < sign.N; i++ {
			coeffNTT[i] = *d.coeffs[k][i].CopyNew()
			r.NTT(coeffNTT[i], coeffNTT[i])
		}
		commits[k] = utils.InitializeVector(r, sign.M)
		utils.MatrixVectorMul(r, d.A, coeffNTT, commits[k])
	}

	// Compute shares: f_i(j) for each party j
	// f_i(j) = coeff[0] + coeff[1]*(j+1) + coeff[2]*(j+1)^2 + ...
	// Evaluate in coefficient domain (not NTT) then convert result.
	q := new(big.Int).SetUint64(sign.Q)
	shares := make(map[int]structs.Vector[ring.Poly], d.n)

	for j := 0; j < d.n; j++ {
		x := big.NewInt(int64(j + 1)) // evaluation point (1-indexed)
		share := make(structs.Vector[ring.Poly], sign.N)
		for vecIdx := 0; vecIdx < sign.N; vecIdx++ {
			share[vecIdx] = r.NewPoly()
		}

		// Horner's method: f(x) = c0 + x*(c1 + x*(c2 + ...))
		// Start from highest degree
		for k := d.t - 1; k >= 0; k-- {
			for vecIdx := 0; vecIdx < sign.N; vecIdx++ {
				if k < d.t-1 {
					// share[vecIdx] *= x
					polyMulScalar(r, share[vecIdx], x, q)
				}
				// share[vecIdx] += coeff[k][vecIdx]
				polyAddCoeffwise(r, share[vecIdx], d.coeffs[k][vecIdx], q)
			}
		}

		shares[j] = share
	}

	return &Round1Output{
		Commits: commits,
		Shares:  shares,
	}, nil
}

// Round2 verifies received shares against commitments and computes the final secret share and public key.
//
// receivedShares maps sender party index -> the share that sender computed for this party.
// receivedCommits maps sender party index -> that sender's commitment vector.
func (d *DKGSession) Round2(
	receivedShares map[int]structs.Vector[ring.Poly],
	receivedCommits map[int][]structs.Vector[ring.Poly],
) (structs.Vector[ring.Poly], structs.Vector[ring.Poly], error) {
	r := d.params.R

	// Verify we have data from all parties
	for i := 0; i < d.n; i++ {
		if _, ok := receivedShares[i]; !ok {
			return nil, nil, fmt.Errorf("%w: missing share from party %d", ErrMissingData, i)
		}
		if _, ok := receivedCommits[i]; !ok {
			return nil, nil, fmt.Errorf("%w: missing commitment from party %d", ErrMissingData, i)
		}
	}

	q := new(big.Int).SetUint64(sign.Q)

	// Verify each received share against the sender's commitments using Feldman's VSS:
	// A * f_i(j) should equal C_{i,0} + (j+1)*C_{i,1} + (j+1)^2*C_{i,2} + ...
	for i := 0; i < d.n; i++ {
		share := receivedShares[i]
		commits := receivedCommits[i]

		if len(commits) != d.t {
			return nil, nil, fmt.Errorf("%w: party %d sent %d commits, expected %d", ErrShareVerification, i, len(commits), d.t)
		}

		// LHS: A * share_i_j (in NTT domain)
		shareNTT := make(structs.Vector[ring.Poly], sign.N)
		for idx := 0; idx < sign.N; idx++ {
			shareNTT[idx] = *share[idx].CopyNew()
			r.NTT(shareNTT[idx], shareNTT[idx])
		}
		lhs := utils.InitializeVector(r, sign.M)
		utils.MatrixVectorMul(r, d.A, shareNTT, lhs)

		// RHS: sum over k of (j+1)^k * C_{i,k} using Horner's method
		x := big.NewInt(int64(d.partyID + 1))
		rhs := utils.InitializeVector(r, sign.M)
		for k := d.t - 1; k >= 0; k-- {
			if k < d.t-1 {
				for idx := 0; idx < sign.M; idx++ {
					polyMulScalarNTT(r, rhs[idx], x, q)
				}
			}
			utils.VectorAdd(r, rhs, commits[k], rhs)
		}

		// Compare LHS == RHS
		for idx := 0; idx < sign.M; idx++ {
			if !r.Equal(lhs[idx], rhs[idx]) {
				return nil, nil, fmt.Errorf("%w: party %d share does not match commitment at index %d", ErrShareVerification, i, idx)
			}
		}
	}

	// Aggregate secret shares: s_j = sum of f_i(j) for all i
	secretShare := make(structs.Vector[ring.Poly], sign.N)
	for idx := 0; idx < sign.N; idx++ {
		secretShare[idx] = r.NewPoly()
	}
	for i := 0; i < d.n; i++ {
		for idx := 0; idx < sign.N; idx++ {
			polyAddCoeffwise(r, secretShare[idx], receivedShares[i][idx], q)
		}
	}

	// Aggregate public key: bTilde = sum of C_{i,0} for all i
	// Then round for the threshold scheme
	pubKeyNTT := utils.InitializeVector(r, sign.M)
	for i := 0; i < d.n; i++ {
		utils.VectorAdd(r, pubKeyNTT, receivedCommits[i][0], pubKeyNTT)
	}

	// Round the public key (convert from NTT, round, like in threshold.go)
	utils.ConvertVectorFromNTT(r, pubKeyNTT)
	bTilde := utils.RoundVector(r, d.params.RXi, pubKeyNTT, sign.Xi)

	return secretShare, bTilde, nil
}

// polyMulScalar multiplies each coefficient of p by scalar s modulo q (coefficient domain).
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

// polyAddCoeffwise adds b into a coefficient-wise modulo q (coefficient domain).
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

// polyMulScalarNTT multiplies each NTT coefficient of p by scalar s modulo q.
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

// ComputeLagrangeCoefficients re-exports the primitives function for convenience.
func ComputeLagrangeCoefficients(r *ring.Ring, T []int, modulus *big.Int) []ring.Poly {
	return primitives.ComputeLagrangeCoefficients(r, T, modulus)
}
