// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package reshare

// KeyShare regeneration for Ringtail / Pulsar integration.
//
// The Reshare and Refresh kernels operate on bare Shamir shares — the
// SkShare field of the production-grade
// `github.com/luxfi/ringtail/threshold.KeyShare` struct. A KeyShare is
// MORE than just SkShare; it carries:
//
//	type KeyShare struct {
//	    Index    int
//	    SkShare  structs.Vector[ring.Poly]
//	    Seeds    map[int][][]byte
//	    MACKeys  map[int][]byte
//	    Lambda   ring.Poly
//	    GroupKey *GroupKey
//	}
//
// All KDF derivations use the canonical Pulsar HashSuite (KMAC256
// under Pulsar-SHA3, keyed BLAKE3 under the legacy suite). Domain-
// separation tags:
//
//	"pulsar.reshare.prf-seed.v1"   — for Seeds
//	"pulsar.reshare.mac-key.v1"    — for MACKeys
//	"pulsar.reshare.lambda-bind.v1" — bound into Lambda derivation when
//	                                  the committee computes Lambdas
//	                                  from a shared transcript hash.

import (
	"fmt"
	"math/big"

	"github.com/luxfi/pulsar/hash"
	"github.com/luxfi/pulsar/primitives"
	"github.com/luxfi/pulsar/sign"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/structs"
)

// PartyKeyShare is the Pulsar-internal mirror of
// ringtail/threshold.KeyShare.
type PartyKeyShare struct {
	Index    int
	SkShare  structs.Vector[ring.Poly]
	Seeds    map[int][][]byte
	MACKeys  map[int][]byte
	Lambda   ring.Poly
	GroupKey *PartyGroupKey
}

// PartyGroupKey mirrors ringtail/threshold.GroupKey.
type PartyGroupKey struct {
	A      structs.Matrix[ring.Poly]
	BTilde structs.Vector[ring.Poly]
}

// PartyKeyShareFromShare wraps a bare Shamir share into a complete
// PartyKeyShare instance, given the committee context.
func PartyKeyShareFromShare(
	r *ring.Ring,
	share Share,
	partyID1Indexed int,
	newCommittee []int,
	pairwiseSeeds map[[2]int][]byte,
	pairwiseMACs map[[2]int][]byte,
	groupKey *PartyGroupKey,
) (*PartyKeyShare, error) {
	myIdx := -1
	for i, id := range newCommittee {
		if id == partyID1Indexed {
			myIdx = i
			break
		}
	}
	if myIdx < 0 {
		return nil, fmt.Errorf("reshare: party %d not in new committee", partyID1Indexed)
	}

	K := len(newCommittee)
	lagrangeInputs := make([]int, K)
	for i, id := range newCommittee {
		lagrangeInputs[i] = id - 1
	}
	lagrange := primitives.ComputeLagrangeCoefficients(
		r, lagrangeInputs, big.NewInt(int64(sign.Q)),
	)
	lambdaCopy := r.NewPoly()
	lambdaCopy.Copy(lagrange[myIdx])
	r.NTT(lambdaCopy, lambdaCopy)
	r.MForm(lambdaCopy, lambdaCopy)

	seeds := make(map[int][][]byte, K)
	for i := 0; i < K; i++ {
		seeds[i] = make([][]byte, K)
		for j := 0; j < K; j++ {
			seeds[i][j] = pairwiseSeeds[canonicalPair(i, j)]
		}
	}
	macKeys := make(map[int][]byte, K)
	for k := 0; k < K; k++ {
		if k == myIdx {
			continue
		}
		macKeys[k] = pairwiseMACs[canonicalPair(myIdx, k)]
	}

	return &PartyKeyShare{
		Index:    myIdx,
		SkShare:  share,
		Seeds:    seeds,
		MACKeys:  macKeys,
		Lambda:   lambdaCopy,
		GroupKey: groupKey,
	}, nil
}

// KDFOutput derives a fixed-length output from a keying material under
// the supplied HashSuite's pairwise KDF. suite=nil resolves to the
// production default (Pulsar-SHA3).
//
// The tag is folded into the chainID label with a `|` separator so two
// callers with distinct tags but the same remaining inputs always
// produce distinct bytes — required because the production suite uses
// a single KMAC256 customization for all pairwise calls.
func KDFOutput(
	suite hash.HashSuite,
	tag string,
	authKex []byte,
	chainID, groupID []byte,
	eraID, generation uint64,
	partyI, partyJ int,
	outLen int,
) []byte {
	s := hash.Resolve(suite)
	labelledChain := make([]byte, 0, len(tag)+1+len(chainID))
	labelledChain = append(labelledChain, []byte(tag)...)
	labelledChain = append(labelledChain, '|')
	labelledChain = append(labelledChain, chainID...)
	return s.DerivePairwise(authKex, labelledChain, groupID, eraID, generation, partyI, partyJ, outLen)
}

// canonicalPair returns the (i, j) tuple in canonical (smaller-first)
// order. Used as a map key for pairwise material.
func canonicalPair(i, j int) [2]int {
	if i > j {
		return [2]int{j, i}
	}
	return [2]int{i, j}
}

// EraseShare overwrites the SkShare field with zero bytes. After
// activation, every old share MUST be erased — failure to do so
// undermines the proactive-security guarantee.
func EraseShare(s Share) {
	for _, p := range s {
		if p.Coeffs == nil {
			continue
		}
		for level := range p.Coeffs {
			coeffs := p.Coeffs[level]
			for k := range coeffs {
				coeffs[k] = 0
			}
		}
	}
}
