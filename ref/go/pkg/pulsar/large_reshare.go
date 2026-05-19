// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// large_reshare.go -- GF(q) proactive resharing. The parallel of
// reshare.go's ReshareSession for the wide-committee regime, with
// HJKY97-style rotation and beacon-randomised quorum selection.
//
// As with large_dkg.go and large_threshold.go, the canonical Lux
// deployment uses the small-committee path at (T, N) = (2, 3) per
// sortitioned group; this Large* path handles the alternative
// single-large-committee deployment.
//
// CR-6/7/8 closure (2026-05-18): per-recipient envelopes are now
// KEM-wrapped under each new-committee member's long-term ML-KEM-768
// identity public key, the vestigial Round-1 commit field is dropped,
// and the prior-pubkey resolution path mirrors the small-committee
// SetPriorGroupPubkey discipline so new-committee-only joiners can
// pin the prior group pubkey deterministically.

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

	// MyIdentity is this party's long-term ML-KEM-768 + ML-DSA-65
	// keypair, used to (a) seal outgoing envelopes if in the reshare
	// quorum and (b) open incoming envelopes if in the new committee.
	MyIdentity *IdentityKey

	// NewDirectory carries the published identity public key for
	// every new-committee member. The reshare quorum uses this to
	// KEM-wrap outgoing envelopes.
	NewDirectory IdentityDirectory

	Beacon []byte

	// priorGroupPubkey is the master public key from BEFORE this
	// reshare. Set via SetPriorGroupPubkey before Round3 by new-
	// committee-only parties; for parties also in the old committee
	// (MyOldShare != nil) the pubkey is auto-populated from
	// MyOldShare.Pub.
	priorGroupPubkey *PublicKey

	rng io.Reader

	myIdxInOld    int
	reshareQuorum []NodeID
	myShares      []shamirShareQ
	round1Cache   []*LargeDKGRound1Msg
}

// SetPriorGroupPubkey records the master public key from BEFORE
// this reshare. New-committee-only parties (those without an old
// share) MUST call this before Round3; the reshare driver injects
// the pinned prior pubkey here so Round3 can stamp it into the
// new LargeKeyShare deterministically rather than emitting Pub: nil
// for the driver to overwrite. When BOTH MyOldShare and the pinned
// prior pubkey are set, Round3 verifies they agree.
func (s *LargeReshareSession) SetPriorGroupPubkey(pk *PublicKey) {
	s.priorGroupPubkey = pk
}

// NewLargeReshareSession constructs a new GF(q) reshare session. The
// new committee size is capped at TargetCommitteeSize.
//
// myIdentity is this party's long-term ML-KEM-768 + ML-DSA-65
// keypair. newDirectory must contain a published IdentityPublicKey
// for every new-committee member; the reshare quorum uses these keys
// to KEM-wrap outgoing envelopes (BLOCKERS.md CR-8).
func NewLargeReshareSession(params *Params,
	oldCommittee []NodeID, oldThreshold int,
	newCommittee []NodeID, newThreshold int,
	myID NodeID, myOldShare *LargeKeyShare,
	myIdentity *IdentityKey, newDirectory IdentityDirectory,
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
	if myIdentity == nil {
		return nil, ErrIdentityKeyMissing
	}
	if newDirectory == nil {
		return nil, ErrDirectoryIncomplete
	}

	oldSorted := append([]NodeID(nil), oldCommittee...)
	sort.Slice(oldSorted, func(i, j int) bool { return nodeIDLess(oldSorted[i], oldSorted[j]) })
	newSorted := append([]NodeID(nil), newCommittee...)
	sort.Slice(newSorted, func(i, j int) bool { return nodeIDLess(newSorted[i], newSorted[j]) })

	// Directory must cover every new committee member.
	for _, id := range newSorted {
		if newDirectory[id] == nil {
			return nil, ErrDirectoryIncomplete
		}
	}

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
		MyIdentity:    myIdentity,
		NewDirectory:  newDirectory,
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
//
// CR-6 path A: no separate commit field. CR-8: per-recipient
// envelopes are ML-KEM-768 sealed against the recipient's published
// identity public key.
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
	var contributionGF [SeedSize]uint32
	for b := 0; b < SeedSize; b++ {
		contributionGF[b] = uint32((uint64(lambda) * uint64(oldShare.Y[b])) % shamirPrimeQ)
	}
	// Per-byte representation of the GF(q) contribution as a 32-byte
	// value (one byte per lane, least-significant byte). Bound into
	// the envelope auth tag for incremental defense in depth; Round3
	// ignores it (the share alone suffices to aggregate the new share
	// at the recipient's new evaluation point). Lossy truncation
	// matches the small-path pattern; the protocol does not rely on
	// recovering the full GF(q) contribution from the envelope.
	var contribBytes [SeedSize]byte
	for b := 0; b < SeedSize; b++ {
		contribBytes[b] = byte(contributionGF[b] & 0xff)
	}

	// Per-session non-secret blind for per-recipient KEM encapseed
	// derivation. Independent of the secret contribution.
	var blind [SeedSize]byte
	if _, err := io.ReadFull(s.rng, blind[:]); err != nil {
		return nil, ErrShortRand
	}

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

	// committeeRoot for the envelope auth-tag binding uses the NEW
	// committee root (recipient-side context).
	var newRoot [32]byte
	copy(newRoot[:], s.commitNewCommitteeRoot())

	envelopes := make(map[NodeID]DKGShareEnvelope, len(s.NewCommittee))
	for posIdx, recipient := range s.NewCommittee {
		shareBytes := shareToBytesQ(shares[posIdx])
		// Per-recipient deterministic encapsulation seed.
		encapBlind := cshake256(
			append(append(append([]byte{}, blind[:]...),
				s.MyID[:]...), recipient[:]...),
			64,
			"PULSAR-RESHARE-ENCAPSEED-V1",
		)
		encapSeed := hashForEncapSeed(newRoot, s.MyID, recipient, encapBlind)

		recipientIPK := s.NewDirectory[recipient]
		if recipientIPK == nil {
			return nil, ErrDirectoryIncomplete
		}
		env, err := sealEnvelope(
			s.MyID,
			recipient,
			newRoot,
			shareBytes[:],
			contribBytes,
			recipientIPK.KEMPub,
			encapSeed[:],
		)
		if err != nil {
			return nil, err
		}
		envelopes[recipient] = env
	}

	return &LargeDKGRound1Msg{
		NodeID:    s.MyID,
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

	digest := s.computeReshareDigest(ordered)
	return &LargeDKGRound2Msg{
		NodeID: s.MyID,
		Digest: digest,
	}, nil
}

// computeReshareDigest binds the dealer NodeID and every recipient's
// KEM-wrapped envelope (ciphertext + sealed payload) into a single
// 32-byte digest. Equivalent to LargeDKGSession.computeRound2Digest
// but over the reshare tag.
func (s *LargeReshareSession) computeReshareDigest(ordered []*LargeDKGRound1Msg) [32]byte {
	parts := [][]byte{}
	for _, m := range ordered {
		parts = append(parts, m.NodeID[:])
		recipKeys := make([]NodeID, 0, len(m.Envelopes))
		for k := range m.Envelopes {
			recipKeys = append(recipKeys, k)
		}
		sort.Slice(recipKeys, func(i, j int) bool { return nodeIDLess(recipKeys[i], recipKeys[j]) })
		for _, k := range recipKeys {
			env := m.Envelopes[k]
			parts = append(parts, k[:])
			parts = append(parts, env.KEMCiphertext)
			parts = append(parts, env.Sealed)
		}
	}
	return transcriptHash32(tagReshareCommit, parts...)
}

// Round3 verifies digest agreement and aggregates the new share.
//
// The calling party must be in the new committee; non-new-committee
// parties have no Round-3 output.
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

	expected := s.computeReshareDigest(ordered)
	for _, r2 := range round2 {
		if !ctEqual32(r2.Digest, expected) {
			return nil, &AbortEvidence{
				Kind:    ComplaintEquivocation,
				Accuser: s.MyID,
				Accused: r2.NodeID,
			}, ErrEquivocation
		}
	}

	var newRoot [32]byte
	copy(newRoot[:], s.commitNewCommitteeRoot())
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
		senderShareBytes, _, openErr := sealOpenEnvelope(
			m.NodeID, s.MyID, newRoot, env, shareWireSizeQ, s.MyIdentity,
		)
		if openErr != nil {
			return nil, &AbortEvidence{
				Kind:    ComplaintBadDelivery,
				Accuser: s.MyID,
				Accused: m.NodeID,
			}, openErr
		}
		var shareArr [shareWireSizeQ]byte
		copy(shareArr[:], senderShareBytes)
		senderShare := shareFromBytesQ(newEval, shareArr)
		for b := 0; b < SeedSize; b++ {
			aggY[b] = uint32((uint64(aggY[b]) + uint64(senderShare.Y[b])) % shamirPrimeQ)
		}
	}
	aggregate := shamirShareQ{X: newEval, Y: aggY}
	shareWire := shareToBytesQ(aggregate)

	// Determine the prior group public key -- the master pubkey from
	// BEFORE this reshare. Resolution order:
	//   1. s.priorGroupPubkey (set by SetPriorGroupPubkey)
	//   2. s.MyOldShare.Pub (if the party is in the old committee too)
	//
	// New-committee-only parties (no MyOldShare) MUST have called
	// SetPriorGroupPubkey before Round3, otherwise we'd be emitting
	// a LargeKeyShare with Pub: nil and trusting the reshare driver
	// to overwrite it with the right value. When both sources are set,
	// they must agree.
	var pub *PublicKey
	switch {
	case s.priorGroupPubkey != nil && s.MyOldShare != nil:
		if !s.priorGroupPubkey.Equal(s.MyOldShare.Pub) {
			return nil, nil, ErrPriorPubkeyMismatch
		}
		pub = s.priorGroupPubkey
	case s.priorGroupPubkey != nil:
		pub = s.priorGroupPubkey
	case s.MyOldShare != nil:
		pub = s.MyOldShare.Pub
	default:
		return nil, nil, ErrPriorPubkeyUnknown
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
