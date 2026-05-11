// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsarm

// large_dkg.go -- GF(q) distributed key generation. The parallel of
// dkg.go's DKGSession for the wide-committee regime.
//
// Same three-round structure (commit-and-deal, equivocation-gate,
// aggregate-and-derive) as the small-committee path; the only
// differences are (i) Shamir is over GF(q), (ii) envelope shares are
// 128 bytes wide, (iii) the cap is TargetCommitteeSize=1,111,111.
// The output is byte-identical to what small-committee DKG would
// produce on the same master seed -- the field choice does not
// propagate past the per-committee boundary.

import (
	"crypto/rand"
	"io"
	"sort"
)

// LargeDKGSession holds one party's state for one GF(q) DKG ceremony.
type LargeDKGSession struct {
	Params    *Params
	Committee []NodeID
	Threshold int
	MyID      NodeID
	myIndex   int

	rng io.Reader

	myContribution [SeedSize]byte
	myBlind        [32]byte
	myCommit       [32]byte
	myShares       []shamirShareQ
	round1Cache    []*LargeDKGRound1Msg
	myDigest       [32]byte

	aggregateShare shamirShareQ
	masterPubkey   *PublicKey
	transcript     [48]byte
}

// NewLargeDKGSession constructs a new GF(q) DKG session.
//
// The committee is canonicalised (byte-ascending NodeID sort). The
// cap TargetCommitteeSize = 1,111,111 is enforced here; any larger
// committee returns ErrCommitteeAboveCap. The smaller GF(q) limit
// of MaxCommitteeQ (q - 1 ≈ 8.38M) would in principle support more,
// but the canonical reference target is 1.111M (see params.go).
func NewLargeDKGSession(params *Params, committee []NodeID, threshold int, myID NodeID, rng io.Reader) (*LargeDKGSession, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if len(committee) == 0 {
		return nil, ErrCommitteeEmpty
	}
	if threshold < 1 || len(committee) < threshold {
		return nil, ErrInvalidThreshold
	}
	if len(committee) > TargetCommitteeSize {
		return nil, ErrCommitteeAboveCap
	}

	sorted := make([]NodeID, len(committee))
	copy(sorted, committee)
	sort.Slice(sorted, func(i, j int) bool { return nodeIDLess(sorted[i], sorted[j]) })
	for i := 1; i < len(sorted); i++ {
		if sorted[i] == sorted[i-1] {
			return nil, ErrCommitteeDuplicate
		}
	}

	myIdx := -1
	for i := range sorted {
		if sorted[i] == myID {
			myIdx = i
			break
		}
	}
	if myIdx < 0 {
		return nil, ErrNotInCommittee
	}

	if rng == nil {
		rng = rand.Reader
	}
	return &LargeDKGSession{
		Params:    params,
		Committee: sorted,
		Threshold: threshold,
		MyID:      myID,
		myIndex:   myIdx + 1,
		rng:       rng,
	}, nil
}

// Round1 samples this party's contribution, GF(q)-Shamir-shares it
// byte-wise, computes the RO-binding commit, and emits the Round-1
// broadcast.
func (s *LargeDKGSession) Round1() (*LargeDKGRound1Msg, error) {
	if _, err := io.ReadFull(s.rng, s.myContribution[:]); err != nil {
		return nil, ErrShortRand
	}
	if _, err := io.ReadFull(s.rng, s.myBlind[:]); err != nil {
		return nil, ErrShortRand
	}

	commitInput := append(append([]byte{}, s.myContribution[:]...), s.myBlind[:]...)
	s.myCommit = transcriptHash32(tagDKGCommit, commitInput)

	committeeRoot := s.commitCommitteeRoot()
	keyMaterial := []byte{}
	keyMaterial = append(keyMaterial, []byte("PULSAR-DKG-DEALER-V1")...)
	keyMaterial = append(keyMaterial, committeeRoot[:]...)
	keyMaterial = append(keyMaterial, byte(s.myIndex>>8), byte(s.myIndex))
	keyMaterial = append(keyMaterial, s.myBlind[:]...)
	streamLen := (s.Threshold - 1) * SeedSize * 4
	if streamLen < 4 {
		streamLen = 4
	}
	stream := cshake256(keyMaterial, streamLen, tagSeedShare)

	shares, err := shamirDealRandomQ(s.myContribution, len(s.Committee), s.Threshold, stream)
	if err != nil {
		return nil, err
	}
	s.myShares = shares

	envelopes := make(map[NodeID]LargeDKGShareEnvelope, len(s.Committee))
	for posIdx, recipient := range s.Committee {
		shareBytes := shareToBytesQ(shares[posIdx])
		blindMask := cshake256(
			append(append([]byte{}, s.myBlind[:]...), recipient[:]...),
			shareWireSizeQ,
			"PULSAR-DKG-BLINDMASK-V1",
		)
		var envShare [shareWireSizeQ]byte
		copy(envShare[:], shareBytes[:])
		var envBlind [shareWireSizeQ]byte
		copy(envBlind[:], blindMask)
		envelopes[recipient] = LargeDKGShareEnvelope{
			Share: envShare,
			Blind: envBlind,
		}
	}

	return &LargeDKGRound1Msg{
		NodeID:    s.MyID,
		Commits:   [][]byte{s.myCommit[:]},
		Envelopes: envelopes,
	}, nil
}

// Round2 ingests all Round-1 messages and emits the digest broadcast.
func (s *LargeDKGSession) Round2(round1 []*LargeDKGRound1Msg) (*LargeDKGRound2Msg, error) {
	if len(round1) != len(s.Committee) {
		return nil, ErrTooFewRound1
	}
	ordered, err := s.orderRound1ByCommittee(round1)
	if err != nil {
		return nil, err
	}
	s.round1Cache = ordered

	s.myDigest = s.computeRound2Digest(ordered)
	return &LargeDKGRound2Msg{
		NodeID: s.MyID,
		Digest: s.myDigest,
	}, nil
}

// Round3 verifies digest agreement and aggregates the local share.
func (s *LargeDKGSession) Round3(round1 []*LargeDKGRound1Msg, round2 []*LargeDKGRound2Msg) (*LargeDKGOutput, error) {
	if len(round1) != len(s.Committee) {
		return nil, ErrTooFewRound1
	}
	if len(round2) != len(s.Committee) {
		return nil, ErrTooFewRound2
	}
	ordered, err := s.orderRound1ByCommittee(round1)
	if err != nil {
		return nil, err
	}

	expected := s.computeRound2Digest(ordered)
	for _, r2 := range round2 {
		if !ctEqual32(r2.Digest, expected) {
			return &LargeDKGOutput{
				AbortEvidence: &AbortEvidence{
					Kind:    ComplaintEquivocation,
					Accuser: s.MyID,
					Accused: r2.NodeID,
				},
			}, nil
		}
	}

	var aggY [SeedSize]uint32
	for _, m := range ordered {
		env, ok := m.Envelopes[s.MyID]
		if !ok {
			return &LargeDKGOutput{
				AbortEvidence: &AbortEvidence{
					Kind:    ComplaintBadDelivery,
					Accuser: s.MyID,
					Accused: m.NodeID,
				},
			}, nil
		}
		var senderShareBuf [shareWireSizeQ]byte
		copy(senderShareBuf[:], env.Share[:])
		senderShare := shareFromBytesQ(uint32(s.myIndex), senderShareBuf)
		for b := 0; b < SeedSize; b++ {
			aggY[b] = uint32((uint64(aggY[b]) + uint64(senderShare.Y[b])) % shamirPrimeQ)
		}
	}
	s.aggregateShare = shamirShareQ{
		X: uint32(s.myIndex),
		Y: aggY,
	}

	masterByteSum, err := s.reconstructByteSum(ordered)
	if err != nil {
		return nil, err
	}
	committeeRoot := s.commitCommitteeRoot()
	mixInput := append(append([]byte{}, masterByteSum...), committeeRoot[:]...)
	var masterSeed [SeedSize]byte
	copy(masterSeed[:], cshake256(mixInput, SeedSize, tagSeedShare))

	sk, err := KeyFromSeed(s.Params, masterSeed)
	if err != nil {
		return nil, err
	}
	s.masterPubkey = sk.Pub

	s.transcript = transcriptHash(tagDKGTranscript,
		committeeRoot[:],
		expected[:],
		sk.Pub.Bytes,
	)

	shareWire := shareToBytesQ(s.aggregateShare)
	return &LargeDKGOutput{
		GroupPubkey: sk.Pub,
		SecretShare: &LargeKeyShare{
			NodeID:    s.MyID,
			EvalPoint: uint32(s.myIndex),
			Share:     shareWire,
			Pub:       sk.Pub,
			Mode:      s.Params.Mode,
		},
		TranscriptHash: s.transcript,
		AbortEvidence:  nil,
	}, nil
}

// reconstructByteSum Lagrange-interpolates the aggregated shares at
// the first t committee positions to recover the GF(q) byte-sum.
// Each slot is encoded as 4 big-endian bytes (matching shareWireSizeQ).
func (s *LargeDKGSession) reconstructByteSum(ordered []*LargeDKGRound1Msg) ([]byte, error) {
	aggregates := make([]shamirShareQ, s.Threshold)
	for j := 0; j < s.Threshold; j++ {
		aggregates[j].X = uint32(j + 1)
		recipient := s.Committee[j]
		for _, m := range ordered {
			env, ok := m.Envelopes[recipient]
			if !ok {
				return nil, ErrEnvelopeMissing
			}
			var buf [shareWireSizeQ]byte
			copy(buf[:], env.Share[:])
			senderShare := shareFromBytesQ(uint32(j+1), buf)
			for b := 0; b < SeedSize; b++ {
				aggregates[j].Y[b] = uint32((uint64(aggregates[j].Y[b]) + uint64(senderShare.Y[b])) % shamirPrimeQ)
			}
		}
	}
	gf, err := shamirReconstructGFQ(aggregates)
	if err != nil {
		return nil, err
	}
	out := make([]byte, SeedSize*4)
	for b := 0; b < SeedSize; b++ {
		out[4*b] = byte(gf[b] >> 24)
		out[4*b+1] = byte(gf[b] >> 16)
		out[4*b+2] = byte(gf[b] >> 8)
		out[4*b+3] = byte(gf[b])
	}
	return out, nil
}

func (s *LargeDKGSession) computeRound2Digest(ordered []*LargeDKGRound1Msg) [32]byte {
	parts := [][]byte{}
	for _, m := range ordered {
		parts = append(parts, m.NodeID[:])
		for _, c := range m.Commits {
			parts = append(parts, c)
		}
		recipKeys := make([]NodeID, 0, len(m.Envelopes))
		for k := range m.Envelopes {
			recipKeys = append(recipKeys, k)
		}
		sort.Slice(recipKeys, func(i, j int) bool { return nodeIDLess(recipKeys[i], recipKeys[j]) })
		for _, k := range recipKeys {
			env := m.Envelopes[k]
			parts = append(parts, k[:])
			parts = append(parts, env.Share[:])
			parts = append(parts, env.Blind[:])
		}
	}
	return transcriptHash32(tagDKGCommit, parts...)
}

func (s *LargeDKGSession) commitCommitteeRoot() [32]byte {
	parts := make([][]byte, 0, len(s.Committee)+1)
	parts = append(parts, []byte("PULSAR-COMMITTEE-V1"))
	for _, id := range s.Committee {
		parts = append(parts, id[:])
	}
	return transcriptHash32(tagDKGCommit, parts...)
}

func (s *LargeDKGSession) orderRound1ByCommittee(round1 []*LargeDKGRound1Msg) ([]*LargeDKGRound1Msg, error) {
	byID := make(map[NodeID]*LargeDKGRound1Msg, len(round1))
	for _, m := range round1 {
		if _, dup := byID[m.NodeID]; dup {
			return nil, ErrCommitteeDuplicate
		}
		byID[m.NodeID] = m
	}
	ordered := make([]*LargeDKGRound1Msg, 0, len(s.Committee))
	for _, id := range s.Committee {
		m, ok := byID[id]
		if !ok {
			return nil, ErrTooFewRound1
		}
		ordered = append(ordered, m)
	}
	return ordered, nil
}

// committeeRootFromLargeShares mirrors committeeRootFromShares for
// the GF(q) path. Used by LargeCombine to bind a recovered byte-sum
// to the canonical committee identity.
func committeeRootFromLargeShares(shares []*LargeKeyShare) [32]byte {
	ids := make([]NodeID, 0, len(shares))
	for _, s := range shares {
		ids = append(ids, s.NodeID)
	}
	for i := 1; i < len(ids); i++ {
		for j := i; j > 0 && nodeIDLess(ids[j], ids[j-1]); j-- {
			ids[j], ids[j-1] = ids[j-1], ids[j]
		}
	}
	parts := make([][]byte, 0, len(ids)+1)
	parts = append(parts, []byte("PULSAR-COMMITTEE-V1"))
	for _, id := range ids {
		parts = append(parts, id[:])
	}
	return transcriptHash32(tagDKGCommit, parts...)
}
