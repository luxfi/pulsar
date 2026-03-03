// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package ringtail provides post-quantum threshold signatures using Ring-LWE.
//
// Signing is a 2-round protocol:
//   - Round 1: Each party broadcasts D matrix + MACs
//   - Round 2: Each party broadcasts z share
//   - Finalize: Any party aggregates into final signature
//
// Fresh keygen runs each epoch when validator set changes.
package threshold

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"

	"github.com/luxfi/pulsar/primitives"
	"github.com/luxfi/pulsar/sign"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/sampling"
	"github.com/luxfi/lattice/v7/utils/structs"
)

var (
	ErrInvalidThreshold  = errors.New("threshold must be > 0 and < total parties")
	ErrInvalidPartyCount = errors.New("need at least 2 parties")
	ErrInvalidPartyIndex = errors.New("party index out of range")
	ErrMACVerifyFailed   = errors.New("MAC verification failed")
	ErrFullRankFailed    = errors.New("full rank check failed")
	ErrInsufficientData  = errors.New("insufficient round data")
)

// Params holds ring parameters for the protocol.
type Params struct {
	R   *ring.Ring // Main ring with prime Q
	RXi *ring.Ring // Rounding ring with QXi
	RNu *ring.Ring // Rounding ring with QNu
}

// NewParams creates ring parameters.
func NewParams() (*Params, error) {
	r, err := ring.NewRing(1<<sign.LogN, []uint64{sign.Q})
	if err != nil {
		return nil, err
	}
	// QXi and QNu are powers of 2 for rounding, ignore ring errors
	rXi, _ := ring.NewRing(1<<sign.LogN, []uint64{sign.QXi})
	rNu, _ := ring.NewRing(1<<sign.LogN, []uint64{sign.QNu})
	return &Params{R: r, RXi: rXi, RNu: rNu}, nil
}

// GroupKey holds the public parameters for the threshold group.
type GroupKey struct {
	A      structs.Matrix[ring.Poly] // Public matrix
	BTilde structs.Vector[ring.Poly] // Rounded public key
	Params *Params
}

// Bytes returns a serialized representation of the group key.
// Note: This is a simplified serialization for compatibility.
func (gk *GroupKey) Bytes() []byte {
	if gk == nil || gk.BTilde == nil {
		return nil
	}
	// Return size info as a simple representation
	return []byte{byte(len(gk.A)), byte(len(gk.BTilde))}
}

// KeyShare holds a party's secret share data.
type KeyShare struct {
	Index    int
	SkShare  structs.Vector[ring.Poly]
	Seeds    map[int][][]byte
	MACKeys  map[int][]byte
	Lambda   ring.Poly // Lagrange coefficient
	GroupKey *GroupKey
}

// Round1Data holds a party's Round 1 output.
type Round1Data struct {
	PartyID int
	D       structs.Matrix[ring.Poly]
	MACs    map[int][]byte
}

// Round2Data holds a party's Round 2 output.
type Round2Data struct {
	PartyID int
	Z       structs.Vector[ring.Poly]
}

// Signature holds the final threshold signature.
type Signature struct {
	C     ring.Poly
	Z     structs.Vector[ring.Poly]
	Delta structs.Vector[ring.Poly]
}

// GenerateKeys generates threshold key shares for n parties with threshold t.
// This runs once per epoch when the validator set changes.
func GenerateKeys(t, n int, randSource io.Reader) ([]*KeyShare, *GroupKey, error) {
	if n < 2 {
		return nil, nil, ErrInvalidPartyCount
	}
	if t < 1 || t >= n {
		return nil, nil, ErrInvalidThreshold
	}

	// Set global params (required by sign package)
	sign.K = n
	sign.Threshold = t

	params, err := NewParams()
	if err != nil {
		return nil, nil, err
	}

	// Generate trusted dealer key
	trustedDealerKey := make([]byte, sign.KeySize)
	if randSource == nil {
		randSource = rand.Reader
	}
	if _, err := io.ReadFull(randSource, trustedDealerKey); err != nil {
		return nil, nil, err
	}

	prng, err := sampling.NewKeyedPRNG(trustedDealerKey)
	if err != nil {
		return nil, nil, err
	}
	uniformSampler := ring.NewUniformSampler(prng, params.R)

	// Compute Lagrange coefficients for all parties
	T := make([]int, n)
	for i := range T {
		T[i] = i
	}
	lagrangeCoeffs := primitives.ComputeLagrangeCoefficients(params.R, T, big.NewInt(int64(sign.Q)))

	// Generate shares
	A, skShares, seeds, macKeys, bTilde := sign.Gen(params.R, params.RXi, uniformSampler, trustedDealerKey, lagrangeCoeffs)

	groupKey := &GroupKey{
		A:      A,
		BTilde: bTilde,
		Params: params,
	}

	shares := make([]*KeyShare, n)
	for i := 0; i < n; i++ {
		// Convert Lagrange coefficient to NTT form
		lambda := params.R.NewPoly()
		lambda.Copy(lagrangeCoeffs[i])
		params.R.NTT(lambda, lambda)
		params.R.MForm(lambda, lambda)

		shares[i] = &KeyShare{
			Index:    i,
			SkShare:  skShares[i],
			Seeds:    seeds,
			MACKeys:  macKeys[i],
			Lambda:   lambda,
			GroupKey: groupKey,
		}
	}

	return shares, groupKey, nil
}

// Signer handles threshold signing for a single party.
type Signer struct {
	share  *KeyShare
	party  *sign.Party
	params *Params
}

// NewSigner creates a signer from a key share.
func NewSigner(share *KeyShare) *Signer {
	params := share.GroupKey.Params
	prng, _ := sampling.NewKeyedPRNG(make([]byte, sign.KeySize))
	uniformSampler := ring.NewUniformSampler(prng, params.R)

	party := sign.NewParty(share.Index, params.R, params.RXi, params.RNu, uniformSampler)
	party.SkShare = share.SkShare
	party.Seed = share.Seeds
	party.MACKeys = share.MACKeys
	party.Lambda = share.Lambda

	return &Signer{
		share:  share,
		party:  party,
		params: params,
	}
}

// Round1 performs signing round 1. Returns D matrix and MACs to broadcast.
func (s *Signer) Round1(sessionID int, prfKey []byte, signers []int) *Round1Data {
	D, MACs := s.party.SignRound1(s.share.GroupKey.A, sessionID, prfKey, signers)
	return &Round1Data{
		PartyID: s.share.Index,
		D:       D,
		MACs:    MACs,
	}
}

// Round2 performs signing round 2. Returns z share to broadcast.
// round1Data is the collected Round 1 data from all signers.
func (s *Signer) Round2(sessionID int, message string, prfKey []byte, signers []int, round1Data map[int]*Round1Data) (*Round2Data, error) {
	if len(round1Data) < len(signers) {
		return nil, ErrInsufficientData
	}

	// Collect D matrices and MACs
	D := make(map[int]structs.Matrix[ring.Poly])
	MACs := make(map[int]map[int][]byte)
	for _, data := range round1Data {
		D[data.PartyID] = data.D
		MACs[data.PartyID] = data.MACs
	}

	// Preprocess: verify MACs and compute aggregated D
	valid, DSum, hash := s.party.SignRound2Preprocess(
		s.share.GroupKey.A,
		s.share.GroupKey.BTilde,
		D,
		MACs,
		sessionID,
		signers,
	)
	if !valid {
		return nil, ErrMACVerifyFailed
	}

	// Compute z share
	z := s.party.SignRound2(
		s.share.GroupKey.A,
		s.share.GroupKey.BTilde,
		DSum,
		sessionID,
		message,
		signers,
		prfKey,
		hash,
	)

	return &Round2Data{
		PartyID: s.share.Index,
		Z:       z,
	}, nil
}

// Finalize aggregates z shares into the final signature.
// Any party can call this with the collected Round 2 data.
func (s *Signer) Finalize(round2Data map[int]*Round2Data) (*Signature, error) {
	if len(round2Data) == 0 {
		return nil, ErrInsufficientData
	}

	// Collect z vectors
	z := make(map[int]structs.Vector[ring.Poly])
	for _, data := range round2Data {
		z[data.PartyID] = data.Z
	}

	c, zSum, delta := s.party.SignFinalize(z, s.share.GroupKey.A, s.share.GroupKey.BTilde)
	return &Signature{
		C:     c,
		Z:     zSum,
		Delta: delta,
	}, nil
}

// Verify checks if a signature is valid for the given message.
func Verify(groupKey *GroupKey, message string, sig *Signature) bool {
	if groupKey == nil || sig == nil {
		return false
	}
	return sign.Verify(
		groupKey.Params.R,
		groupKey.Params.RXi,
		groupKey.Params.RNu,
		sig.Z,
		groupKey.A,
		message,
		groupKey.BTilde,
		sig.C,
		sig.Delta,
	)
}
