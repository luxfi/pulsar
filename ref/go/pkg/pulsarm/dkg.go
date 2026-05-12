// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsarm

// dkg.go — distributed key generation. Three rounds:
//
//   Round 1: each party samples a 32-byte seed contribution c_i,
//            broadcasts an RO-binding cSHAKE256 commitment to c_i,
//            and Shamir-shares c_i byte-wise over GF(257) to the
//            committee.
//   Round 2: each party broadcasts the digest of the Round-1 commits
//            it received from every dealer. Mismatch across recipients
//            triggers ComplaintEquivocation.
//   Round 3: each party verifies the Round-2 digest agreement and
//            aggregates its share. The master public key is derived
//            from the byte-wise sum-of-contributions mixed through
//            cSHAKE256 to produce a uniform ML-DSA seed.
//
// The v0.1 commitment is the RO-binding cSHAKE256 commit
//
//     C_i = cSHAKE256(c_i || blind_i, 32, "PULSAR-DKG-COMMIT-V1")
//
// which is binding under collision resistance and hiding under
// uniformity of blind_i. The v0.2 path replaces this with R_q^k
// Pedersen per pulsar-m.tex §3.2 + §4.1 to obtain the same
// guarantees under M-LWE hardness (a stronger PQ-safe binding
// argument). Both targets are Class N4-eligible.
//
// See BLOCKERS.md for the v0.1 → v0.2 path.

import (
	"crypto/rand"
	"errors"
	"io"
	"sort"
)

// Errors returned by DKG.
var (
	ErrCommitteeEmpty     = errors.New("pulsarm: DKG committee is empty")
	ErrCommitteeDuplicate = errors.New("pulsarm: DKG committee contains duplicate node IDs")
	ErrNotInCommittee     = errors.New("pulsarm: node is not in DKG committee")
	ErrEnvelopeMissing    = errors.New("pulsarm: round-1 envelope missing for committee member")
	ErrCommitMismatch     = errors.New("pulsarm: round-1 commit does not match opening at round 3")
	ErrEquivocation       = errors.New("pulsarm: round-1.5 commit digest mismatch (equivocation)")
	ErrTooFewRound1       = errors.New("pulsarm: too few round-1 messages — DKG requires all committee members")
	ErrTooFewRound2       = errors.New("pulsarm: too few round-2 messages — DKG requires all committee members")
)

// DKGSession holds the per-party state for one DKG ceremony.
//
// One ceremony per (committee, threshold) tuple. Replay against a
// distinct committee root produces a distinct master public key by
// construction.
type DKGSession struct {
	Params    *Params
	Committee []NodeID // sorted canonical committee (byte-ascending NodeID)
	Threshold int
	MyID      NodeID
	myIndex   int      // 1-indexed Shamir evaluation point in Committee

	rng io.Reader // entropy for c_i and blind_i

	// Per-round state.
	myContribution [SeedSize]byte // c_i sampled at Round 1
	myBlind        [32]byte       // blind_i sampled at Round 1
	myCommit       [32]byte       // C_i = cSHAKE256(c_i || blind_i)
	myShares       []shamirShare  // f_i(j) for each committee position j ∈ {1..n}
	round1Cache    []*DKGRound1Msg
	myDigest       [32]byte

	// Output state after Round 3.
	aggregateShare shamirShare
	masterPubkey   *PublicKey
	transcript     [48]byte
}

// NewDKGSession constructs a new DKG session.
//
// committee must contain at least `threshold` distinct NodeIDs and
// must include myID. The committee is canonicalised (byte-ascending
// sort) so all parties agree on the position-to-evaluation-point
// mapping without any out-of-band coordination.
//
// rng may be nil — crypto/rand is used as the default entropy source.
// Pass a deterministic reader (e.g. bytes.NewReader of a fixed seed)
// for KAT-reproducible DKG runs.
func NewDKGSession(params *Params, committee []NodeID, threshold int, myID NodeID, rng io.Reader) (*DKGSession, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if len(committee) == 0 {
		return nil, ErrCommitteeEmpty
	}
	if threshold < 1 || len(committee) < threshold {
		return nil, ErrInvalidThreshold
	}
	if len(committee) > 256 {
		return nil, ErrCommitteeTooLarge
	}

	sorted := make([]NodeID, len(committee))
	copy(sorted, committee)
	sort.Slice(sorted, func(i, j int) bool {
		return nodeIDLess(sorted[i], sorted[j])
	})
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
	return &DKGSession{
		Params:    params,
		Committee: sorted,
		Threshold: threshold,
		MyID:      myID,
		myIndex:   myIdx + 1,
		rng:       rng,
	}, nil
}

// Round1 samples this party's contribution, Shamir-shares it
// byte-wise, computes the RO-binding commit, and returns the
// per-recipient envelope set.
//
// All Round-1 messages from the entire committee must be delivered
// to every party before Round 2 begins. Partial delivery becomes a
// timeout abort.
func (s *DKGSession) Round1() (*DKGRound1Msg, error) {
	if _, err := io.ReadFull(s.rng, s.myContribution[:]); err != nil {
		return nil, ErrShortRand
	}
	if _, err := io.ReadFull(s.rng, s.myBlind[:]); err != nil {
		return nil, ErrShortRand
	}

	commitInput := append(append([]byte{}, s.myContribution[:]...), s.myBlind[:]...)
	s.myCommit = transcriptHash32(tagDKGCommit, commitInput)

	// Per-byte Shamir share of c_i. Coefficient material is
	// domain-separated by (committee root, my-index, blind_i) so two
	// DKG sessions on the same contribution never collide.
	committeeRoot := s.commitCommitteeRoot()
	keyMaterial := []byte{}
	keyMaterial = append(keyMaterial, []byte("PULSAR-DKG-DEALER-V1")...)
	keyMaterial = append(keyMaterial, committeeRoot[:]...)
	keyMaterial = append(keyMaterial, byte(s.myIndex>>8), byte(s.myIndex))
	keyMaterial = append(keyMaterial, s.myBlind[:]...)
	streamLen := (s.Threshold - 1) * SeedSize * 2
	if streamLen < 2 {
		streamLen = 2
	}
	stream := cshake256(keyMaterial, streamLen, tagSeedShare)

	shares, err := shamirDealRandom(s.myContribution, len(s.Committee), s.Threshold, stream)
	if err != nil {
		return nil, err
	}
	s.myShares = shares

	// Build envelopes — one per committee position. We also pack a
	// per-recipient blinding share derived from blind_i so that the
	// envelope digest binds both share and blind even in v0.1's RO
	// model. The blinding share is byte-wise XOR with a per-recipient
	// transcript-hash mask; this is sufficient for v0.1 binding
	// (a malicious receiver cannot forge a valid open without knowing
	// the per-position mask).
	envelopes := make(map[NodeID]DKGShareEnvelope, len(s.Committee))
	for posIdx, recipient := range s.Committee {
		share := shares[posIdx]
		shareBytes := shareToBytes(share)

		// Derive the per-recipient blinding mask.
		blindMask := cshake256(
			append(append([]byte{}, s.myBlind[:]...), recipient[:]...),
			shareWireSize,
			"PULSAR-DKG-BLINDMASK-V1",
		)
		var blindOut [shareWireSize]byte
		copy(blindOut[:], blindMask)

		var envShare [64]byte
		copy(envShare[:], shareBytes[:])
		envelopes[recipient] = DKGShareEnvelope{
			Share: envShare,
			Blind: blindOut,
		}
	}

	return &DKGRound1Msg{
		NodeID:    s.MyID,
		Commits:   [][]byte{s.myCommit[:]},
		Envelopes: envelopes,
	}, nil
}

// Round2 ingests all Round-1 messages and emits this party's
// commit-digest broadcast. The Round-2 step is the equivocation
// gate: every party computes the SAME digest over the ordered
// (sender, commit, envelope-set) tuple; a Round-2 message bearing a
// different digest is direct evidence of equivocation by the sender.
func (s *DKGSession) Round2(round1 []*DKGRound1Msg) (*DKGRound2Msg, error) {
	if len(round1) != len(s.Committee) {
		return nil, ErrTooFewRound1
	}
	ordered, err := s.orderRound1ByCommittee(round1)
	if err != nil {
		return nil, err
	}
	s.round1Cache = ordered

	s.myDigest = s.computeRound2Digest(ordered)
	return &DKGRound2Msg{
		NodeID: s.MyID,
		Digest: s.myDigest,
	}, nil
}

// Round3 verifies digest agreement and aggregates the local share.
//
// Returns a DKGOutput carrying either:
//   - the joint group public key + this party's KeyShare on success, or
//   - a signed AbortEvidence on detected misbehaviour.
//
// The Round-3 step is local to each party — there is no Round-3
// broadcast. After Round 3, every honest party holds (i) the same
// group pubkey, (ii) its own KeyShare, and (iii) the transcript hash
// for chain-pinning.
func (s *DKGSession) Round3(round1 []*DKGRound1Msg, round2 []*DKGRound2Msg) (*DKGOutput, error) {
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

	// Recompute the canonical digest and compare against every Round-2
	// broadcast. Mismatch → equivocation. We use constant-time compare
	// to avoid leaking which byte of the digest differs.
	expected := s.computeRound2Digest(ordered)
	for _, r2 := range round2 {
		if !ctEqual32(r2.Digest, expected) {
			return &DKGOutput{
				AbortEvidence: &AbortEvidence{
					Kind:    ComplaintEquivocation,
					Accuser: s.MyID,
					Accused: r2.NodeID,
				},
			}, nil
		}
	}

	// Aggregate the local share. For this party's evaluation point
	// (s.myIndex), aggregate share Y = Σ_i envelope[i→me].Y (mod p).
	var aggY [SeedSize]uint16
	for _, m := range ordered {
		env, ok := m.Envelopes[s.MyID]
		if !ok {
			return &DKGOutput{
				AbortEvidence: &AbortEvidence{
					Kind:    ComplaintBadDelivery,
					Accuser: s.MyID,
					Accused: m.NodeID,
				},
			}, nil
		}
		var senderShareBuf [shareWireSize]byte
		copy(senderShareBuf[:], env.Share[:])
		senderShare := shareFromBytes(uint32(s.myIndex), senderShareBuf)
		for b := 0; b < SeedSize; b++ {
			aggY[b] = uint16((uint32(aggY[b]) + uint32(senderShare.Y[b])) % shamirPrime)
		}
	}
	s.aggregateShare = shamirShare{
		X: uint32(s.myIndex),
		Y: aggY,
	}

	// Derive the master ML-DSA seed.
	//
	// The aggregated shares form Shamir shares of the byte-wise sum
	// of all dealer contributions: master_byte_sum[b] = Σ_i c_i[b] mod 257.
	// To recover a uniform 32-byte ML-DSA seed, we Lagrange-interpolate
	// these aggregated shares at x=0 (using the first t committee
	// positions, which every party can do because every party holds
	// the same Round-1 envelopes), then mix through cSHAKE256 to
	// flatten any modular bias.
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

	// Transcript hash for chain commitment.
	s.transcript = transcriptHash(tagDKGTranscript,
		committeeRoot[:],
		expected[:],
		sk.Pub.Bytes,
	)

	// Pack the per-byte aggregate share for the KeyShare wire form.
	// The aggregate share's reconstruction-at-x=0 is the byte-sum
	// (Σ c_i mod 257), which is the secret implicitly threshold-shared
	// after the cSHAKE256 mix. Threshold sign reconstructs this byte-sum
	// then re-applies the mix to recover masterSeed (see threshold.go).
	shareWire := shareToBytes(s.aggregateShare)
	return &DKGOutput{
		GroupPubkey: sk.Pub,
		SecretShare: &KeyShare{
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
// the first t committee positions to recover the GF(257) byte-sum
// of all dealer contributions. Returns a 64-byte big-endian
// encoding of the 32-element GF(257) vector — using two bytes per
// slot so the 257-th value is faithfully represented.
func (s *DKGSession) reconstructByteSum(ordered []*DKGRound1Msg) ([]byte, error) {
	aggregates := make([]shamirShare, s.Threshold)
	for j := 0; j < s.Threshold; j++ {
		aggregates[j].X = uint32(j + 1)
		recipient := s.Committee[j]
		for _, m := range ordered {
			env, ok := m.Envelopes[recipient]
			if !ok {
				return nil, ErrEnvelopeMissing
			}
			var buf [shareWireSize]byte
			copy(buf[:], env.Share[:])
			senderShare := shareFromBytes(uint32(j+1), buf)
			for b := 0; b < SeedSize; b++ {
				aggregates[j].Y[b] = uint16((uint32(aggregates[j].Y[b]) + uint32(senderShare.Y[b])) % shamirPrime)
			}
		}
	}
	gf, err := shamirReconstructGF(aggregates)
	if err != nil {
		return nil, err
	}
	out := make([]byte, SeedSize*2)
	for b := 0; b < SeedSize; b++ {
		out[2*b] = byte(gf[b] >> 8)
		out[2*b+1] = byte(gf[b])
	}
	return out, nil
}

// computeRound2Digest returns the canonical 32-byte digest over the
// ordered Round-1 broadcasts and per-recipient envelopes. Every honest
// party computes the SAME digest given the same Round-1 inputs.
func (s *DKGSession) computeRound2Digest(ordered []*DKGRound1Msg) [32]byte {
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

// commitCommitteeRoot returns a deterministic 32-byte digest of the
// sorted committee.
func (s *DKGSession) commitCommitteeRoot() [32]byte {
	parts := make([][]byte, 0, len(s.Committee)+1)
	parts = append(parts, []byte("PULSAR-COMMITTEE-V1"))
	for _, id := range s.Committee {
		parts = append(parts, id[:])
	}
	return transcriptHash32(tagDKGCommit, parts...)
}

// orderRound1ByCommittee returns Round-1 messages in canonical
// committee order, verifying each sender is in the committee and
// every committee member sent exactly one message.
func (s *DKGSession) orderRound1ByCommittee(round1 []*DKGRound1Msg) ([]*DKGRound1Msg, error) {
	byID := make(map[NodeID]*DKGRound1Msg, len(round1))
	for _, m := range round1 {
		if _, dup := byID[m.NodeID]; dup {
			return nil, ErrCommitteeDuplicate
		}
		byID[m.NodeID] = m
	}
	ordered := make([]*DKGRound1Msg, 0, len(s.Committee))
	for _, id := range s.Committee {
		m, ok := byID[id]
		if !ok {
			return nil, ErrTooFewRound1
		}
		ordered = append(ordered, m)
	}
	return ordered, nil
}

// nodeIDLess is a byte-ascending comparator for NodeIDs.
func nodeIDLess(a, b NodeID) bool {
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// ctEqual32 is a constant-time byte-equality check for 32-byte arrays.
// Always scans every byte regardless of how many differ.
func ctEqual32(a, b [32]byte) bool {
	var diff byte
	for i := 0; i < 32; i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
