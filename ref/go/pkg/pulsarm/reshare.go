// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsarm

// reshare.go — proactive resharing. HJKY97-style: rotate the share
// distribution from an old committee to a new committee without
// changing the master public key, and without reconstructing the
// master secret in any party's memory.
//
// Three rounds, structurally similar to DKG except the constant
// terms are pre-multiplied by the old-committee Lagrange coefficients
// (so the sum of fresh polynomials evaluates to the master secret at
// x=0 by construction). Beacon-randomised quorum selection per
// pulsar-m.tex §4.4 mitigates mobile-adversary corruption-set
// gaming.
//
// v0.1 instantiation: the reshare quorum is the FIRST k members of
// the old committee in canonical order, with k = threshold(old).
// The beacon-randomised selection in pulsar-m.tex §4.4 is implemented
// as a configurable knob (BeaconQuorum) — pass the beacon bytes and
// the routine permutes the old committee deterministically before
// selecting the first k. Without a beacon, the deterministic
// canonical-order selection is used (acceptable for single-shot
// reshares; mobile-adversary deployments MUST pass a beacon).

import (
	"crypto/rand"
	"errors"
	"io"
	"sort"
)

// Errors returned by Reshare.
var (
	ErrOldCommitteeEmpty = errors.New("pulsarm: old committee is empty")
	ErrNewCommitteeEmpty = errors.New("pulsarm: new committee is empty")
	ErrOldThresholdSmall = errors.New("pulsarm: old committee smaller than old threshold")
	ErrNewThresholdSmall = errors.New("pulsarm: new committee smaller than new threshold")
	ErrShareCount        = errors.New("pulsarm: insufficient old-committee shares for reshare")
)

// ReshareSession holds one party's state for a single reshare
// ceremony.
type ReshareSession struct {
	Params       *Params
	OldCommittee []NodeID
	OldThreshold int
	NewCommittee []NodeID
	NewThreshold int

	// MyID identifies the calling party. The party may be in the old
	// committee, the new committee, or both.
	MyID NodeID

	// MyOldShare is the calling party's share from the previous DKG.
	// Only required if the party is in the reshare quorum (a subset
	// of the old committee).
	MyOldShare *KeyShare

	// Beacon is the chain randomness used to permute the old
	// committee before quorum selection. Pass nil to use canonical
	// ordering (acceptable for single-shot reshares; mobile-adversary
	// deployments MUST pass a beacon).
	Beacon []byte

	rng io.Reader

	// Internal state.
	myIdxInOld    int
	reshareQuorum []NodeID
	myShares      []shamirShare // f_i(j) for each new committee position
	round1Cache   []*DKGRound1Msg
}

// NewReshareSession constructs a new reshare session.
//
// myOldShare may be nil if the calling party is not in the reshare
// quorum (i.e. is a new-committee-only party that only receives
// shares). If myOldShare is non-nil, it must be a share from the
// most recent DKG/Reshare against the same group public key.
func NewReshareSession(params *Params,
	oldCommittee []NodeID, oldThreshold int,
	newCommittee []NodeID, newThreshold int,
	myID NodeID, myOldShare *KeyShare,
	beacon []byte, rng io.Reader) (*ReshareSession, error) {

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

	// Canonicalise committees.
	oldSorted := append([]NodeID(nil), oldCommittee...)
	sort.Slice(oldSorted, func(i, j int) bool { return nodeIDLess(oldSorted[i], oldSorted[j]) })
	newSorted := append([]NodeID(nil), newCommittee...)
	sort.Slice(newSorted, func(i, j int) bool { return nodeIDLess(newSorted[i], newSorted[j]) })

	// Beacon-permuted reshare-quorum selection.
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
	return &ReshareSession{
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

// InReshareQuorum reports whether this party is in the reshare quorum
// (i.e. will broadcast Round-1 messages during this reshare). Parties
// not in the quorum only receive shares.
func (s *ReshareSession) InReshareQuorum() bool {
	for _, q := range s.reshareQuorum {
		if q == s.MyID {
			return true
		}
	}
	return false
}

// Round1 emits a Round-1 broadcast carrying this party's contribution
// to the reshare. Only quorum members produce Round-1 messages;
// non-quorum parties skip Round 1 and only ingest at Round 3.
//
// The contribution constant term is λ_i^Q · share_i where λ_i^Q is
// this party's Lagrange coefficient in the reshare-quorum Q. This
// guarantees that the sum of all Round-1 contributions, evaluated at
// x=0, equals the master secret (by Lagrange interpolation of the
// old quorum).
//
// The implementation derives λ_i^Q at the byte level over GF(257),
// matching the byte-wise share format installed by DKG.
func (s *ReshareSession) Round1() (*DKGRound1Msg, error) {
	if !s.InReshareQuorum() {
		return nil, ErrNotInCommittee
	}
	if s.MyOldShare == nil {
		return nil, ErrNilKey
	}

	// Lagrange coefficient at x=0 for THIS party in the reshare quorum.
	myEval := s.MyOldShare.EvalPoint
	lambda := lagrangeAtZero(myEval, s.reshareQuorumEvalPoints())

	// Compute the contribution constant term in GF(257) per slot:
	//     contribution[b] = λ · old_share[b] mod 257
	// This is the HJKY97 dealer contribution that, when summed
	// across the reshare quorum, evaluates at x=0 to the master
	// byte-sum (by Lagrange interpolation in GF(257)).
	var oldShareBuf [shareWireSize]byte
	copy(oldShareBuf[:], s.MyOldShare.Share[:])
	oldShare := shareFromBytes(myEval, oldShareBuf)
	var contribution [SeedSize]uint16
	for b := 0; b < SeedSize; b++ {
		contribution[b] = uint16((uint32(lambda) * uint32(oldShare.Y[b])) % shamirPrime)
	}

	// Sample blinding for the RO commit.
	var blind [32]byte
	if _, err := io.ReadFull(s.rng, blind[:]); err != nil {
		return nil, ErrShortRand
	}
	// Commit binds the contribution as 2 bytes per GF(257) slot
	// (big-endian) so the 257-th value is faithfully represented.
	contribBytes := make([]byte, SeedSize*2)
	for b := 0; b < SeedSize; b++ {
		contribBytes[2*b] = byte(contribution[b] >> 8)
		contribBytes[2*b+1] = byte(contribution[b])
	}
	commitInput := append(append([]byte{}, contribBytes...), blind[:]...)
	myCommit := transcriptHash32(tagReshareCommit, commitInput)

	// Shamir-share the contribution at threshold newT to the new committee.
	keyMaterial := []byte{}
	keyMaterial = append(keyMaterial, []byte("PULSAR-RESHARE-DEALER-V1")...)
	keyMaterial = append(keyMaterial, s.commitOldCommitteeRoot()...)
	keyMaterial = append(keyMaterial, s.commitNewCommitteeRoot()...)
	keyMaterial = append(keyMaterial, blind[:]...)
	streamLen := (s.NewThreshold - 1) * SeedSize * 2
	if streamLen < 2 {
		streamLen = 2
	}
	stream := cshake256(keyMaterial, streamLen, tagSeedShare)
	shares, err := shamirDealRandomGF(contribution, len(s.NewCommittee), s.NewThreshold, stream)
	if err != nil {
		return nil, err
	}
	s.myShares = shares

	envelopes := make(map[NodeID]DKGShareEnvelope, len(s.NewCommittee))
	for posIdx, recipient := range s.NewCommittee {
		shareBytes := shareToBytes(shares[posIdx])
		blindMask := cshake256(
			append(append([]byte{}, blind[:]...), recipient[:]...),
			shareWireSize,
			"PULSAR-RESHARE-BLINDMASK-V1",
		)
		var envShare [64]byte
		copy(envShare[:], shareBytes[:])
		var envBlind [64]byte
		copy(envBlind[:], blindMask)
		envelopes[recipient] = DKGShareEnvelope{
			Share: envShare,
			Blind: envBlind,
		}
	}

	return &DKGRound1Msg{
		NodeID:    s.MyID,
		Commits:   [][]byte{myCommit[:]},
		Envelopes: envelopes,
	}, nil
}

// Round2 ingests reshare-quorum Round-1 broadcasts and emits the
// digest acknowledgement. Identical structure to DKG.Round2.
func (s *ReshareSession) Round2(round1 []*DKGRound1Msg) (*DKGRound2Msg, error) {
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
	return &DKGRound2Msg{
		NodeID: s.MyID,
		Digest: digest,
	}, nil
}

// Round3 verifies the digest agreement and aggregates the calling
// party's new share. Returns the new KeyShare on success.
//
// The calling party must be in the new committee; non-new-committee
// parties have no Round-3 output.
func (s *ReshareSession) Round3(round1 []*DKGRound1Msg, round2 []*DKGRound2Msg) (*KeyShare, *AbortEvidence, error) {
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

	// Locate my position in the NEW committee. If not present, this
	// party has no new share to receive (e.g. retiring validator).
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

	// Recompute and verify the canonical digest.
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

	// Aggregate the new share: sum the per-dealer envelope shares for
	// this party's NEW evaluation point.
	newEval := uint32(myNewIdx + 1)
	var aggY [SeedSize]uint16
	for _, m := range ordered {
		env, ok := m.Envelopes[s.MyID]
		if !ok {
			return nil, &AbortEvidence{
				Kind:    ComplaintBadDelivery,
				Accuser: s.MyID,
				Accused: m.NodeID,
			}, ErrEnvelopeMissing
		}
		var buf [shareWireSize]byte
		copy(buf[:], env.Share[:])
		senderShare := shareFromBytes(newEval, buf)
		for b := 0; b < SeedSize; b++ {
			aggY[b] = uint16((uint32(aggY[b]) + uint32(senderShare.Y[b])) % shamirPrime)
		}
	}
	aggregate := shamirShare{X: newEval, Y: aggY}
	shareWire := shareToBytes(aggregate)

	// The new share recovers the SAME byte-sum at x=0 as the old
	// shares did (Theorem reshare-pkinv): pk is invariant. The pub
	// is carried via the calling party's old share if available; new-
	// committee-only parties get pub injected via the reshare driver
	// (it is a public artifact already pinned on-chain).
	var pub *PublicKey
	if s.MyOldShare != nil {
		pub = s.MyOldShare.Pub
	}
	return &KeyShare{
		NodeID:    s.MyID,
		EvalPoint: newEval,
		Share:     shareWire,
		Pub:       pub,
		Mode:      s.Params.Mode,
	}, nil, nil
}

// selectReshareQuorum picks the reshare quorum from the old committee.
//
// If beacon is non-nil, the old committee is permuted by sorting
// under cSHAKE256(committee_root || beacon) — this is the
// beacon-randomised selection of pulsar-m.tex §4.4. Without a beacon,
// the canonical-order first-k selection is used.
func selectReshareQuorum(oldSorted []NodeID, oldThreshold int, beacon []byte) []NodeID {
	if beacon == nil {
		return append([]NodeID(nil), oldSorted[:oldThreshold]...)
	}
	// Beacon permutation: derive a per-node 8-byte sort key.
	type keyedID struct {
		key uint64
		id  NodeID
	}
	keyed := make([]keyedID, len(oldSorted))
	for i, id := range oldSorted {
		input := append(append([]byte{}, beacon...), id[:]...)
		digest := cshake256(input, 8, tagReshareBeacon)
		k := uint64(digest[0])<<56 | uint64(digest[1])<<48 |
			uint64(digest[2])<<40 | uint64(digest[3])<<32 |
			uint64(digest[4])<<24 | uint64(digest[5])<<16 |
			uint64(digest[6])<<8 | uint64(digest[7])
		keyed[i] = keyedID{key: k, id: id}
	}
	sort.Slice(keyed, func(i, j int) bool { return keyed[i].key < keyed[j].key })
	out := make([]NodeID, oldThreshold)
	for i := 0; i < oldThreshold; i++ {
		out[i] = keyed[i].id
	}
	// Canonicalise order so the round drivers see a stable list.
	sort.Slice(out, func(i, j int) bool { return nodeIDLess(out[i], out[j]) })
	return out
}

// reshareQuorumEvalPoints returns the GF(257) Shamir evaluation
// points for the reshare quorum, in canonical NodeID order.
func (s *ReshareSession) reshareQuorumEvalPoints() []uint32 {
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

// commitOldCommitteeRoot returns the canonical 32-byte digest of the
// old committee.
func (s *ReshareSession) commitOldCommitteeRoot() []byte {
	parts := make([][]byte, 0, len(s.OldCommittee)+1)
	parts = append(parts, []byte("PULSAR-COMMITTEE-V1"))
	for _, id := range s.OldCommittee {
		parts = append(parts, id[:])
	}
	h := transcriptHash32(tagDKGCommit, parts...)
	return h[:]
}

// commitNewCommitteeRoot returns the canonical 32-byte digest of the
// new committee.
func (s *ReshareSession) commitNewCommitteeRoot() []byte {
	parts := make([][]byte, 0, len(s.NewCommittee)+1)
	parts = append(parts, []byte("PULSAR-COMMITTEE-V1"))
	for _, id := range s.NewCommittee {
		parts = append(parts, id[:])
	}
	h := transcriptHash32(tagDKGCommit, parts...)
	return h[:]
}

// orderRound1ByReshareQuorum returns Round-1 messages in canonical
// reshare-quorum order.
func (s *ReshareSession) orderRound1ByReshareQuorum(round1 []*DKGRound1Msg) ([]*DKGRound1Msg, error) {
	byID := make(map[NodeID]*DKGRound1Msg, len(round1))
	for _, m := range round1 {
		if _, dup := byID[m.NodeID]; dup {
			return nil, ErrCommitteeDuplicate
		}
		byID[m.NodeID] = m
	}
	ordered := make([]*DKGRound1Msg, 0, len(s.reshareQuorum))
	for _, id := range s.reshareQuorum {
		m, ok := byID[id]
		if !ok {
			return nil, ErrTooFewRound1
		}
		ordered = append(ordered, m)
	}
	return ordered, nil
}

// lagrangeAtZero returns the Lagrange coefficient at x=0 for the
// party at evaluation point myX in the quorum whose points are
// allEvals. Computed in GF(257).
func lagrangeAtZero(myX uint32, allEvals []uint32) uint16 {
	num := uint32(1)
	den := uint32(1)
	for _, xj := range allEvals {
		if xj == myX {
			continue
		}
		negXj := shamirPrime - (xj % shamirPrime)
		num = (num * negXj) % shamirPrime
		diff := (shamirPrime + myX - xj) % shamirPrime
		den = (den * diff) % shamirPrime
	}
	denInv := modInvSmall(den, shamirPrime)
	return uint16((num * denInv) % shamirPrime)
}
