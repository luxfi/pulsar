// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsarm

// large_reshare.go -- GF(q) proactive resharing. The parallel of
// reshare.go's ReshareSession for the wide-committee regime, with
// HJKY97-style rotation and beacon-randomised quorum selection.
//
// As with large_dkg.go and large_threshold.go, the canonical Lux
// deployment uses the small-committee path at (T, N) = (2, 3) per
// sortitioned group; this Large* path handles the alternative
// single-large-committee deployment.

import (
	"crypto/rand"
	"io"
	"sort"
)

// LargeReshareSession holds one party's state for one GF(q) reshare
// ceremony.
type LargeReshareSession struct {
	Params       *Params
	OldCommittee []NodeID
	OldThreshold int
	NewCommittee []NodeID
	NewThreshold int

	MyID       NodeID
	MyOldShare *LargeKeyShare

	Beacon []byte

	rng io.Reader

	myIdxInOld    int
	reshareQuorum []NodeID
	myShares      []shamirShareQ
	round1Cache   []*LargeDKGRound1Msg
}

// NewLargeReshareSession constructs a new GF(q) reshare session. The
// new committee size is capped at TargetCommitteeSize.
func NewLargeReshareSession(params *Params,
	oldCommittee []NodeID, oldThreshold int,
	newCommittee []NodeID, newThreshold int,
	myID NodeID, myOldShare *LargeKeyShare,
	beacon []byte, rng io.Reader) (*LargeReshareSession, error) {

	if err := params.Validate(); err != nil {
		return nil, err
	}
	if len(oldCommittee) == 0 {
		return nil, ErrOldCommitteeEmpty
	}
	if len(newCommittee) == 0 {
		return nil, ErrNewCommitteeEmpty
	}
	if oldThreshold < 1 || len(oldCommittee) < oldThreshold {
		return nil, ErrOldThresholdSmall
	}
	if newThreshold < 1 || len(newCommittee) < newThreshold {
		return nil, ErrNewThresholdSmall
	}
	if len(oldCommittee) > TargetCommitteeSize || len(newCommittee) > TargetCommitteeSize {
		return nil, ErrCommitteeAboveCap
	}

	oldSorted := append([]NodeID(nil), oldCommittee...)
	sort.Slice(oldSorted, func(i, j int) bool { return nodeIDLess(oldSorted[i], oldSorted[j]) })
	newSorted := append([]NodeID(nil), newCommittee...)
	sort.Slice(newSorted, func(i, j int) bool { return nodeIDLess(newSorted[i], newSorted[j]) })

	quorum := selectReshareQuorum(oldSorted, oldThreshold, beacon)

	myIdxInOld := -1
	for i, id := range oldSorted {
		if id == myID {
			myIdxInOld = i
			break
		}
	}

	if rng == nil {
		rng = rand.Reader
	}
	return &LargeReshareSession{
		Params:        params,
		OldCommittee:  oldSorted,
		OldThreshold:  oldThreshold,
		NewCommittee:  newSorted,
		NewThreshold:  newThreshold,
		MyID:          myID,
		MyOldShare:    myOldShare,
		Beacon:        beacon,
		rng:           rng,
		myIdxInOld:    myIdxInOld,
		reshareQuorum: quorum,
	}, nil
}

// InReshareQuorum reports whether this party is in the reshare quorum.
func (s *LargeReshareSession) InReshareQuorum() bool {
	for _, q := range s.reshareQuorum {
		if q == s.MyID {
			return true
		}
	}
	return false
}

// Round1 emits a Round-1 broadcast carrying this party's GF(q)
// contribution. Only quorum members produce Round-1 messages.
func (s *LargeReshareSession) Round1() (*LargeDKGRound1Msg, error) {
	if !s.InReshareQuorum() {
		return nil, ErrNotInCommittee
	}
	if s.MyOldShare == nil {
		return nil, ErrNilKey
	}

	myEval := s.MyOldShare.EvalPoint
	lambda := LagrangeAtZeroQ(myEval, s.reshareQuorumEvalPoints())

	var oldShareBuf [shareWireSizeQ]byte
	copy(oldShareBuf[:], s.MyOldShare.Share[:])
	oldShare := shareFromBytesQ(myEval, oldShareBuf)
	var contribution [SeedSize]byte
	var contributionGF [SeedSize]uint32
	for b := 0; b < SeedSize; b++ {
		v := uint32((uint64(lambda) * uint64(oldShare.Y[b])) % shamirPrimeQ)
		contributionGF[b] = v
		contribution[b] = byte(v & 0xff) // only used for the secret-byte-summary; actual sharing uses contributionGF
	}

	var blind [32]byte
	if _, err := io.ReadFull(s.rng, blind[:]); err != nil {
		return nil, ErrShortRand
	}
	contribBytes := make([]byte, SeedSize*4)
	for b := 0; b < SeedSize; b++ {
		contribBytes[4*b] = byte(contributionGF[b] >> 24)
		contribBytes[4*b+1] = byte(contributionGF[b] >> 16)
		contribBytes[4*b+2] = byte(contributionGF[b] >> 8)
		contribBytes[4*b+3] = byte(contributionGF[b])
	}
	commitInput := append(append([]byte{}, contribBytes...), blind[:]...)
	myCommit := transcriptHash32(tagReshareCommit, commitInput)

	keyMaterial := []byte{}
	keyMaterial = append(keyMaterial, []byte("PULSAR-RESHARE-DEALER-V1")...)
	keyMaterial = append(keyMaterial, s.commitOldCommitteeRoot()...)
	keyMaterial = append(keyMaterial, s.commitNewCommitteeRoot()...)
	keyMaterial = append(keyMaterial, blind[:]...)
	streamLen := (s.NewThreshold - 1) * SeedSize * 4
	if streamLen < 4 {
		streamLen = 4
	}
	stream := cshake256(keyMaterial, streamLen, tagSeedShare)
	shares, err := shamirDealRandomQGF(contributionGF, len(s.NewCommittee), s.NewThreshold, stream)
	if err != nil {
		return nil, err
	}
	s.myShares = shares

	envelopes := make(map[NodeID]LargeDKGShareEnvelope, len(s.NewCommittee))
	for posIdx, recipient := range s.NewCommittee {
		shareBytes := shareToBytesQ(shares[posIdx])
		blindMask := cshake256(
			append(append([]byte{}, blind[:]...), recipient[:]...),
			shareWireSizeQ,
			"PULSAR-RESHARE-BLINDMASK-V1",
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

	_ = contribution // placeholder to remind us the byte-secret is unused on this path

	return &LargeDKGRound1Msg{
		NodeID:    s.MyID,
		Commits:   [][]byte{myCommit[:]},
		Envelopes: envelopes,
	}, nil
}

// Round2 ingests reshare-quorum Round-1 broadcasts and emits the
// digest acknowledgement.
func (s *LargeReshareSession) Round2(round1 []*LargeDKGRound1Msg) (*LargeDKGRound2Msg, error) {
	if len(round1) != len(s.reshareQuorum) {
		return nil, ErrTooFewRound1
	}
	ordered, err := s.orderRound1ByReshareQuorum(round1)
	if err != nil {
		return nil, err
	}
	s.round1Cache = ordered

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
	digest := transcriptHash32(tagReshareCommit, parts...)
	return &LargeDKGRound2Msg{
		NodeID: s.MyID,
		Digest: digest,
	}, nil
}

// Round3 verifies digest agreement and aggregates the new share.
func (s *LargeReshareSession) Round3(round1 []*LargeDKGRound1Msg, round2 []*LargeDKGRound2Msg) (*LargeKeyShare, *AbortEvidence, error) {
	if len(round1) != len(s.reshareQuorum) {
		return nil, nil, ErrTooFewRound1
	}
	if len(round2) != len(s.reshareQuorum) {
		return nil, nil, ErrTooFewRound2
	}
	ordered, err := s.orderRound1ByReshareQuorum(round1)
	if err != nil {
		return nil, nil, err
	}

	myNewIdx := -1
	for i, id := range s.NewCommittee {
		if id == s.MyID {
			myNewIdx = i
			break
		}
	}
	if myNewIdx < 0 {
		return nil, nil, ErrNotInCommittee
	}

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
	expected := transcriptHash32(tagReshareCommit, parts...)
	for _, r2 := range round2 {
		if !ctEqual32(r2.Digest, expected) {
			return nil, &AbortEvidence{
				Kind:    ComplaintEquivocation,
				Accuser: s.MyID,
				Accused: r2.NodeID,
			}, ErrEquivocation
		}
	}

	newEval := uint32(myNewIdx + 1)
	var aggY [SeedSize]uint32
	for _, m := range ordered {
		env, ok := m.Envelopes[s.MyID]
		if !ok {
			return nil, &AbortEvidence{
				Kind:    ComplaintBadDelivery,
				Accuser: s.MyID,
				Accused: m.NodeID,
			}, ErrEnvelopeMissing
		}
		var buf [shareWireSizeQ]byte
		copy(buf[:], env.Share[:])
		senderShare := shareFromBytesQ(newEval, buf)
		for b := 0; b < SeedSize; b++ {
			aggY[b] = uint32((uint64(aggY[b]) + uint64(senderShare.Y[b])) % shamirPrimeQ)
		}
	}
	aggregate := shamirShareQ{X: newEval, Y: aggY}
	shareWire := shareToBytesQ(aggregate)

	var pub *PublicKey
	if s.MyOldShare != nil {
		pub = s.MyOldShare.Pub
	}
	return &LargeKeyShare{
		NodeID:    s.MyID,
		EvalPoint: newEval,
		Share:     shareWire,
		Pub:       pub,
		Mode:      s.Params.Mode,
	}, nil, nil
}

func (s *LargeReshareSession) reshareQuorumEvalPoints() []uint32 {
	out := make([]uint32, 0, len(s.reshareQuorum))
	idxByID := make(map[NodeID]uint32)
	for i, id := range s.OldCommittee {
		idxByID[id] = uint32(i + 1)
	}
	for _, q := range s.reshareQuorum {
		out = append(out, idxByID[q])
	}
	return out
}

func (s *LargeReshareSession) commitOldCommitteeRoot() []byte {
	parts := make([][]byte, 0, len(s.OldCommittee)+1)
	parts = append(parts, []byte("PULSAR-COMMITTEE-V1"))
	for _, id := range s.OldCommittee {
		parts = append(parts, id[:])
	}
	h := transcriptHash32(tagDKGCommit, parts...)
	return h[:]
}

func (s *LargeReshareSession) commitNewCommitteeRoot() []byte {
	parts := make([][]byte, 0, len(s.NewCommittee)+1)
	parts = append(parts, []byte("PULSAR-COMMITTEE-V1"))
	for _, id := range s.NewCommittee {
		parts = append(parts, id[:])
	}
	h := transcriptHash32(tagDKGCommit, parts...)
	return h[:]
}

func (s *LargeReshareSession) orderRound1ByReshareQuorum(round1 []*LargeDKGRound1Msg) ([]*LargeDKGRound1Msg, error) {
	byID := make(map[NodeID]*LargeDKGRound1Msg, len(round1))
	for _, m := range round1 {
		if _, dup := byID[m.NodeID]; dup {
			return nil, ErrCommitteeDuplicate
		}
		byID[m.NodeID] = m
	}
	ordered := make([]*LargeDKGRound1Msg, 0, len(s.reshareQuorum))
	for _, id := range s.reshareQuorum {
		m, ok := byID[id]
		if !ok {
			return nil, ErrTooFewRound1
		}
		ordered = append(ordered, m)
	}
	return ordered, nil
}

// shamirDealRandomQGF shares a 32-element GF(q) secret vector (where
// each lane is already a value in [0, q)) across n parties with
// threshold t. Counterpart of shamir.go::shamirDealRandomGF for the
// wide-field path; used by LargeReshareSession.Round1 where the
// contribution is λ_i · share_i mod q (not necessarily a byte value).
func shamirDealRandomQGF(secret [SeedSize]uint32, n, t int, coeffStream []byte) ([]shamirShareQ, error) {
	if t < 1 || n < t {
		return nil, ErrInvalidThreshold
	}
	if uint64(n) > uint64(MaxCommitteeQ) {
		return nil, ErrCommitteeTooLargeQ
	}
	needed := (t - 1) * SeedSize * 4
	if needed < 4 {
		needed = 4
	}
	if len(coeffStream) < needed {
		coeffStream = cshake256(coeffStream, needed, tagSeedShare)
	}
	coeffs := make([][SeedSize]uint32, t)
	for b := 0; b < SeedSize; b++ {
		coeffs[0][b] = secret[b] % uint32(shamirPrimeQ)
	}
	off := 0
	for d := 1; d < t; d++ {
		for b := 0; b < SeedSize; b++ {
			r := uint32(coeffStream[off])<<24 | uint32(coeffStream[off+1])<<16 | uint32(coeffStream[off+2])<<8 | uint32(coeffStream[off+3])
			off += 4
			coeffs[d][b] = uint32(uint64(r) % shamirPrimeQ)
		}
	}
	shares := make([]shamirShareQ, n)
	for i := 1; i <= n; i++ {
		shares[i-1].X = uint32(i)
		x := uint64(i)
		for b := 0; b < SeedSize; b++ {
			acc := uint64(coeffs[t-1][b])
			for d := t - 2; d >= 0; d-- {
				acc = (acc*x + uint64(coeffs[d][b])) % shamirPrimeQ
			}
			shares[i-1].Y[b] = uint32(acc)
		}
	}
	return shares, nil
}
