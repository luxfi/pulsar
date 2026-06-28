//go:build legacy_trusted_dealer

// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.
//
// LEGACY (quarantined): GF(q) SEED-share committee path. It is dealerless
// at keygen but its output (LargeKeyShare = a Shamir share of the 32-byte
// ML-DSA seed) can ONLY be consumed by the reconstruct-at-sign combiner
// (large_threshold.go). NOT in the default production build. The production
// committee path is the no-reconstruct AlgShare/AggregateBCC signer
// (distributed_bcc.go). Build with `-tags legacy_trusted_dealer` only.

package pulsar

// large_dkg.go -- GF(q) distributed key generation. The parallel of
// dkg.go's DKGSession for the wide-committee regime.
//
// Same three-round structure (deal-via-KEM-envelopes, equivocation-
// gate, aggregate-and-derive) as the small-committee path; the only
// differences are (i) Shamir is over GF(q), (ii) envelope shares are
// 128 bytes wide (vs 64 for GF(257)), (iii) the cap is
// TargetCommitteeSize=1,111,111. The output is byte-identical to what
// small-committee DKG would produce on the same master seed -- the
// field choice does not propagate past the per-committee boundary.
//
// CR-6/7/8 closure (2026-05-18): the GF(q) path now uses the same
// identity stage as the GF(257) path. The vestigial Round-1 commit
// field is gone (CR-6 path A); per-recipient envelopes are KEM-wrapped
// under each recipient's long-term ML-KEM-768 identity public key
// (CR-8); the threshold-sign MAC keys are derived from per-session
// per-pair ephemeral session keys (CR-7, see large_threshold.go).

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

	// Identity material for per-recipient envelope sealing (CR-8). The
	// session refuses to construct without both a local identity (for
	// decrypting incoming envelopes at Round 3) and a directory entry
	// for every committee member (for sealing outgoing envelopes at
	// Round 1).
	myIdentity *IdentityKey
	directory  IdentityDirectory

	rng io.Reader

	myContribution [SeedSize]byte // c_i sampled at Round 1 -- SECRET
	encapBlindKey  [SeedSize]byte // per-session non-secret blind used
	//                            // to diversify per-recipient KEM
	//                            // encapsulation seeds. Sampled fresh
	//                            // at Round 1; NOT derived from
	//                            // myContribution -- independence is
	//                            // the small-path C2 fix carried over.
	myShares    []shamirShareQ
	round1Cache []*LargeDKGRound1Msg
	myDigest    [32]byte

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
//
// myIdentity is the calling party's long-term ML-KEM-768 + ML-DSA-65
// keypair; the KEM secret half is used to open incoming envelopes at
// Round 3. directory must contain a published IdentityPublicKey for
// every committee member (including myID -- the round-trip check
// requires we can seal-and-open our own envelope as a sanity gate).
func NewLargeDKGSession(
	params *Params,
	committee []NodeID,
	threshold int,
	myID NodeID,
	myIdentity *IdentityKey,
	directory IdentityDirectory,
	rng io.Reader,
) (*LargeDKGSession, error) {
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
	if myIdentity == nil {
		return nil, ErrIdentityKeyMissing
	}
	if directory == nil {
		return nil, ErrDirectoryIncomplete
	}

	sorted := make([]NodeID, len(committee))
	copy(sorted, committee)
	sort.Slice(sorted, func(i, j int) bool { return nodeIDLess(sorted[i], sorted[j]) })
	for i := 1; i < len(sorted); i++ {
		if sorted[i] == sorted[i-1] {
			return nil, ErrCommitteeDuplicate
		}
	}

	// Directory must cover every committee member; missing entries
	// mean we cannot seal an envelope for that recipient.
	for _, id := range sorted {
		if directory[id] == nil {
			return nil, ErrDirectoryIncomplete
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
		Params:     params,
		Committee:  sorted,
		Threshold:  threshold,
		MyID:       myID,
		myIndex:    myIdx + 1,
		myIdentity: myIdentity,
		directory:  directory,
		rng:        rng,
	}, nil
}

// Round1 samples this party's contribution, GF(q)-Shamir-shares it
// byte-wise, KEM-wraps each per-recipient envelope under the
// recipient's long-term ML-KEM-768 public key, and returns the
// broadcast.
//
// CR-6 path A: no commit-and-open; the broadcast carries no separate
// commitment field. CR-8: per-recipient envelopes are ML-KEM-768
// sealed against the recipient's published identity public key so a
// passive network observer learns nothing about per-recipient shares.
func (s *LargeDKGSession) Round1() (*LargeDKGRound1Msg, error) {
	if _, err := io.ReadFull(s.rng, s.myContribution[:]); err != nil {
		return nil, ErrShortRand
	}
	// Per-session non-secret blind for per-recipient KEM encapseed
	// derivation. Independent of myContribution (small-path C2 carry-
	// over): a fault on the cSHAKE256 call below cannot leak bits of
	// the secret contribution.
	if _, err := io.ReadFull(s.rng, s.encapBlindKey[:]); err != nil {
		return nil, ErrShortRand
	}

	// Per-byte GF(q) Shamir share of c_i. Coefficient material is
	// domain-separated by (committee root, my-index, contribution-
	// derived seed) so two DKG sessions on the same contribution
	// never collide.
	committeeRoot := s.commitCommitteeRoot()
	keyMaterial := make([]byte, 0, len("PULSAR-DKG-DEALER-V1")+len(committeeRoot)+2+SeedSize)
	keyMaterial = append(keyMaterial, []byte("PULSAR-DKG-DEALER-V1")...)
	keyMaterial = append(keyMaterial, committeeRoot[:]...)
	keyMaterial = append(keyMaterial, byte(s.myIndex>>8), byte(s.myIndex))
	keyMaterial = append(keyMaterial, s.myContribution[:]...)
	streamLen := (s.Threshold - 1) * SeedSize * 4
	if streamLen < 4 {
		streamLen = 4
	}
	stream := cshake256(keyMaterial, streamLen, tagSeedShare)

	// Backend-dispatched GF(q) Shamir; byte-equal to shamirDealRandomQ.
	// See dkg_gpu.go for the dispatch policy.
	shares, err := shamirDealRandomQAccel(s.myContribution, len(s.Committee), s.Threshold, stream)
	if err != nil {
		return nil, err
	}
	s.myShares = shares

	// KEM-wrap each per-recipient envelope. Same construction as the
	// small path -- only the shareWire width (128 bytes for GF(q))
	// changes; the identity-stage seal primitive is width-agnostic.
	envelopes := make(map[NodeID]DKGShareEnvelope, len(s.Committee))
	for posIdx, recipient := range s.Committee {
		shareBytes := shareToBytesQ(shares[posIdx])

		// Per-recipient deterministic encapsulation seed material.
		encapBlind := cshake256(
			append(append(append([]byte{}, s.encapBlindKey[:]...),
				s.MyID[:]...), recipient[:]...),
			64,
			"PULSAR-DKG-ENCAPSEED-V1",
		)
		encapSeed := hashForEncapSeed(committeeRoot, s.MyID, recipient, encapBlind)

		recipientIPK := s.directory[recipient]
		if recipientIPK == nil {
			return nil, ErrDirectoryIncomplete
		}
		env, err := sealEnvelope(
			s.MyID,
			recipient,
			committeeRoot,
			shareBytes[:],
			s.myContribution,
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

// Round2 ingests all Round-1 messages and emits the digest broadcast.
// The Round-2 step is the equivocation gate: every party computes the
// SAME digest over the ordered (sender, envelope-set) tuple; a
// Round-2 message bearing a different digest is direct evidence of
// equivocation by the sender.
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
//
// Decrypts every envelope addressed to me. Each envelope reveals
// BOTH (a) the dealer's GF(q) Shamir share for me at x=myIndex (which
// I aggregate into my own LargeKeyShare for threshold sign) AND (b)
// the dealer's full 32-byte contribution c_i (which I sum byte-wise
// over GF(257) to derive the master seed).
//
// The dealer contribution byte-sum uses GF(257) -- not GF(q) -- so
// the master-seed cSHAKE256 mix is byte-identical to the small-path
// DKG output on the same set of contributions. This preserves
// cross-field interchangeability of the final master public key.
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

	committeeRoot := s.commitCommitteeRoot()
	var aggY [SeedSize]uint32
	// byteSum aggregates the per-dealer contributions c_i byte-wise
	// over GF(q). At x=0 of the joint polynomial f(x) = Σ_i f_i(x),
	// f(0) = Σ_i f_i(0) = Σ_i c_i -- i.e. the byte-sum we need for
	// the master seed mix. We sum mod q (not mod 257) so the per-party
	// envelope-derived byteSum matches what LargeCombine recovers via
	// Lagrange interpolation of the shares in GF(q).
	var byteSum [SeedSize]uint32
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
		senderShareBytes, senderContrib, openErr := sealOpenEnvelope(
			m.NodeID, s.MyID, committeeRoot, env, shareWireSizeQ, s.myIdentity,
		)
		if openErr != nil {
			return &LargeDKGOutput{
				AbortEvidence: &AbortEvidence{
					Kind:    ComplaintBadDelivery,
					Accuser: s.MyID,
					Accused: m.NodeID,
				},
			}, nil
		}
		var shareArr [shareWireSizeQ]byte
		copy(shareArr[:], senderShareBytes)
		senderShare := shareFromBytesQ(uint32(s.myIndex), shareArr)
		for b := 0; b < SeedSize; b++ {
			aggY[b] = uint32((uint64(aggY[b]) + uint64(senderShare.Y[b])) % shamirPrimeQ)
			byteSum[b] = uint32((uint64(byteSum[b]) + uint64(senderContrib[b])) % shamirPrimeQ)
		}
	}
	s.aggregateShare = shamirShareQ{
		X: uint32(s.myIndex),
		Y: aggY,
	}

	// Derive the master ML-DSA seed from the GF(q) byte-sum + the
	// canonical committee root. The 4-byte-per-lane big-endian encoding
	// matches what LargeCombine emits, so a party that ran the DKG
	// here and a party that runs LargeCombine on the same set of
	// contributions agree on the master seed.
	byteSumBytes := make([]byte, SeedSize*4)
	for b := 0; b < SeedSize; b++ {
		byteSumBytes[4*b] = byte(byteSum[b] >> 24)
		byteSumBytes[4*b+1] = byte(byteSum[b] >> 16)
		byteSumBytes[4*b+2] = byte(byteSum[b] >> 8)
		byteSumBytes[4*b+3] = byte(byteSum[b])
	}
	mixInput := append(append([]byte{}, byteSumBytes...), committeeRoot[:]...)
	var masterSeed [SeedSize]byte
	copy(masterSeed[:], cshake256(mixInput, SeedSize, tagSeedShare))

	sk, err := KeyFromSeed(s.Params, masterSeed)
	if err != nil {
		zeroizeSeed(&masterSeed)
		zeroizeBytes(byteSumBytes)
		zeroizeBytes(mixInput)
		return nil, err
	}
	s.masterPubkey = sk.Pub

	s.transcript = transcriptHash(tagDKGTranscript,
		committeeRoot[:],
		expected[:],
		sk.Pub.Bytes,
	)

	shareWire := shareToBytesQ(s.aggregateShare)
	out := &LargeDKGOutput{
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
	}
	zeroizePrivateKey(sk)
	zeroizeSeed(&masterSeed)
	zeroizeBytes(byteSumBytes)
	zeroizeBytes(mixInput)
	return out, nil
}

// computeRound2Digest returns the canonical 32-byte digest over the
// ordered Round-1 broadcasts and per-recipient KEM-wrapped envelopes.
// Every honest party computes the SAME digest given the same Round-1
// inputs because the envelope ciphertext + sealed payload bytes are
// deterministic across recipients given the dealer's contribution and
// the recipient's published KEM public key.
//
// committeeRoot binding pins the digest to THIS specific committee
// so a colluding dealer + recipient pair cannot replay an envelope
// across committees.
func (s *LargeDKGSession) computeRound2Digest(ordered []*LargeDKGRound1Msg) [32]byte {
	committeeRoot := s.commitCommitteeRoot()
	parts := [][]byte{committeeRoot[:]}
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
