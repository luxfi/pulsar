// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package reshare

// Pedersen-style polynomial commitments for VSR.
//
// The Reshare kernel in reshare.go gives the arithmetic core of Desmedt-
// Jajodia '97. To make Reshare verifiable in a permissionless setting we
// also commit each old party i's resharing polynomial g_i(X) and let the
// new committee verify the values g_i(β_j) it receives against the
// commitment. The same commitment scheme covers Refresh's z_i(X).
//
// Public commitment to f_i(X) = c_{i,0} + c_{i,1}·X + ... + c_{i,t-1}·X^{t-1}:
//
//	C_{i,k} = A_R · NTT(c_{i,k}) + B_R · NTT(r_{i,k})
//
// The matrices A, B are derived from nothing-up-my-sleeve domain-separated
// tags via the canonical Pulsar HashSuite XOF (cSHAKE256 under Pulsar-SHA3,
// BLAKE3 under the legacy suite).

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"github.com/luxfi/pulsar/hash"
	"github.com/luxfi/pulsar/sign"
	"github.com/luxfi/pulsar/utils"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/sampling"
	"github.com/luxfi/lattice/v7/utils/structs"
)

// Domain-separation tags for the reshare commitment matrices. Distinct
// from dkg2's tags so a DKG commit cannot be repurposed as a reshare
// commit (and vice versa).
var (
	tagReshareA = []byte("pulsar.reshare.A.v1")
	tagReshareB = []byte("pulsar.reshare.B.v1")
)

// CommitParams holds the public matrices used to commit to and verify
// resharing polynomials.
type CommitParams struct {
	R   *ring.Ring
	RXi *ring.Ring
	A   structs.Matrix[ring.Poly]
	B   structs.Matrix[ring.Poly]
}

// NewCommitParams derives the commitment matrices from the canonical
// tags using the supplied HashSuite. suite=nil resolves to the
// production default (Pulsar-SHA3). Two suites with distinct IDs derive
// distinct matrices, so legacy BLAKE3 KATs cannot be replayed as
// Pulsar-SHA3 transcripts.
func NewCommitParams(suite hash.HashSuite) (*CommitParams, error) {
	s := hash.Resolve(suite)
	r, err := ring.NewRing(1<<sign.LogN, []uint64{sign.Q})
	if err != nil {
		return nil, err
	}
	rXi, _ := ring.NewRing(1<<sign.LogN, []uint64{sign.QXi})

	derive := func(tag []byte) structs.Matrix[ring.Poly] {
		seed := s.Hu(tag, sign.KeySize)
		prng, _ := sampling.NewKeyedPRNG(seed)
		uniform := ring.NewUniformSampler(prng, r)
		return utils.SamplePolyMatrix(r, sign.M, sign.N, uniform, true, true)
	}
	return &CommitParams{
		R: r, RXi: rXi,
		A: derive(tagReshareA),
		B: derive(tagReshareB),
	}, nil
}

// Errors specific to commitment verification.
var (
	ErrCommitMismatch      = errors.New("reshare: commitment verification failed")
	ErrCommitWrongLength   = errors.New("reshare: commit vector has wrong length")
	ErrInconsistentDigests = errors.New("reshare: cross-recipient commit digest mismatch")
)

// CommitToPoly produces the t Pedersen commitments to the secret-polynomial
// coefficients c_k together with the matching blinding-polynomial
// coefficients r_k.
func CommitToPoly(
	params *CommitParams,
	secretCoeffs []structs.Vector[ring.Poly],
	blindCoeffs []structs.Vector[ring.Poly],
) ([]structs.Vector[ring.Poly], error) {
	if len(secretCoeffs) != len(blindCoeffs) {
		return nil, fmt.Errorf("CommitToPoly: secret/blind length mismatch: %d vs %d",
			len(secretCoeffs), len(blindCoeffs))
	}
	r := params.R
	t := len(secretCoeffs)
	commits := make([]structs.Vector[ring.Poly], t)
	for k := 0; k < t; k++ {
		cNTT := make(structs.Vector[ring.Poly], sign.N)
		rNTT := make(structs.Vector[ring.Poly], sign.N)
		for i := 0; i < sign.N; i++ {
			cNTT[i] = *secretCoeffs[k][i].CopyNew()
			r.NTT(cNTT[i], cNTT[i])
			rNTT[i] = *blindCoeffs[k][i].CopyNew()
			r.NTT(rNTT[i], rNTT[i])
		}
		ac := utils.InitializeVector(r, sign.M)
		utils.MatrixVectorMul(r, params.A, cNTT, ac)
		br := utils.InitializeVector(r, sign.M)
		utils.MatrixVectorMul(r, params.B, rNTT, br)
		commits[k] = utils.InitializeVector(r, sign.M)
		utils.VectorAdd(r, ac, br, commits[k])
	}
	return commits, nil
}

// VerifyShareAgainstCommits checks the recipient-side equation
//
//	A_R · NTT(share) + B_R · NTT(blind) ?= Σ_{k=0..t-1} β_j^k · commits[k]
func VerifyShareAgainstCommits(
	params *CommitParams,
	share structs.Vector[ring.Poly],
	blind structs.Vector[ring.Poly],
	commits []structs.Vector[ring.Poly],
	betaJ int,
) error {
	r := params.R
	t := len(commits)
	if t == 0 {
		return ErrCommitWrongLength
	}
	q := new(big.Int).SetUint64(sign.Q)

	shareNTT := make(structs.Vector[ring.Poly], sign.N)
	for vi := 0; vi < sign.N; vi++ {
		shareNTT[vi] = *share[vi].CopyNew()
		r.NTT(shareNTT[vi], shareNTT[vi])
	}
	ash := utils.InitializeVector(r, sign.M)
	utils.MatrixVectorMul(r, params.A, shareNTT, ash)

	blindNTT := make(structs.Vector[ring.Poly], sign.N)
	for vi := 0; vi < sign.N; vi++ {
		blindNTT[vi] = *blind[vi].CopyNew()
		r.NTT(blindNTT[vi], blindNTT[vi])
	}
	bbl := utils.InitializeVector(r, sign.M)
	utils.MatrixVectorMul(r, params.B, blindNTT, bbl)

	lhs := utils.InitializeVector(r, sign.M)
	utils.VectorAdd(r, ash, bbl, lhs)

	x := big.NewInt(int64(betaJ))
	rhs := utils.InitializeVector(r, sign.M)
	for k := t - 1; k >= 0; k-- {
		if k < t-1 {
			for ri := 0; ri < sign.M; ri++ {
				polyMulScalarNTTOnly(r, rhs[ri], x, q)
			}
		}
		utils.VectorAdd(r, rhs, commits[k], rhs)
	}

	for ri := 0; ri < sign.M; ri++ {
		if !r.Equal(lhs[ri], rhs[ri]) {
			return fmt.Errorf("%w: mismatch at coordinate %d", ErrCommitMismatch, ri)
		}
	}
	return nil
}

// polyMulScalarNTTOnly multiplies each NTT coefficient of p by scalar s
// mod q.
func polyMulScalarNTTOnly(r *ring.Ring, p ring.Poly, s, q *big.Int) {
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

// CommitDigest returns the canonical 32-byte digest over a commit
// vector under the supplied HashSuite. suite=nil resolves to the
// production default (Pulsar-SHA3).
func CommitDigest(commits []structs.Vector[ring.Poly], suite hash.HashSuite) [32]byte {
	s := hash.Resolve(suite)
	parts := make([][]byte, 0, 1+len(commits))
	parts = append(parts, []byte("pulsar.reshare.commit-digest.v1"))
	for _, v := range commits {
		var buf bytes.Buffer
		_, _ = v.WriteTo(&buf)
		parts = append(parts, buf.Bytes())
	}
	return s.TranscriptHash(parts...)
}
