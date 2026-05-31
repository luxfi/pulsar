// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// dkg.go — distributed key generation. Three rounds:
//
//   Round 1: each party samples a 32-byte seed contribution c_i,
//            byte-wise Shamir-shares c_i over GF(257) to the
//            committee, KEM-wraps each per-recipient share envelope
//            under the recipient's long-term ML-KEM-768 identity
//            public key, and broadcasts the wrapped envelope map.
//   Round 2: each party broadcasts the digest of the Round-1
//            envelopes it received from every dealer. Mismatch across
//            recipients triggers ComplaintEquivocation.
//   Round 3: each party verifies the Round-2 digest agreement and
//            aggregates its share. The master public key is derived
//            from the byte-wise sum-of-contributions mixed through
//            cSHAKE256 to produce a uniform ML-DSA seed.
//
// Protocol shape (CR-6 path A — Shamir+sum, no commit-and-open).
// The legacy v0.1 broadcast carried `myCommit = cSHAKE(c_i || blind_i)`
// but `(c_i, blind_i)` were never transmitted in any later round, so
// the commit bound to nothing the protocol verified (BLOCKERS.md
// CR-6). Path A drops the commit entirely. Binding comes from
// Round-2 digest agreement over the ordered envelope set. The
// v0.2 path replaces this with R_q^k Pedersen per pulsar.tex §3.2
// + §4.1 for stronger PQ-safe binding under M-LWE hardness; that is
// orthogonal to CR-6 and remains the future work.
//
// Envelope confidentiality (CR-8): each per-recipient envelope is
// ML-KEM-768-sealed against the recipient's long-term identity public
// key so a passive network observer cannot read the per-recipient
// Shamir share from a single broadcast. The DKG ceremony now needs an
// IdentityKey per party (long-term ML-KEM-768 + ML-DSA-65) plus an
// IdentityDirectory of every committee member's published KEM public
// key. See identity.go.

import (
	"crypto/rand"
	"errors"
	"io"
	"sort"
)

// Errors returned by DKG.
var (
	ErrCommitteeEmpty      = errors.New("pulsar: DKG committee is empty")
	ErrCommitteeDuplicate  = errors.New("pulsar: DKG committee contains duplicate node IDs")
	ErrNotInCommittee      = errors.New("pulsar: node is not in DKG committee")
	ErrEnvelopeMissing     = errors.New("pulsar: round-1 envelope missing for committee member")
	ErrCommitMismatch      = errors.New("pulsar: round-1 commit does not match opening at round 3")
	ErrEquivocation        = errors.New("pulsar: round-1.5 envelope digest mismatch (equivocation)")
	ErrTooFewRound1        = errors.New("pulsar: too few round-1 messages — DKG requires all committee members")
	ErrTooFewRound2        = errors.New("pulsar: too few round-2 messages — DKG requires all committee members")
	ErrDirectoryIncomplete = errors.New("pulsar: identity directory missing entry for committee member")
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
	myIndex   int // 1-indexed Shamir evaluation point in Committee

	// Identity material for per-recipient envelope sealing
	// (BLOCKERS.md CR-8). The session refuses to construct without
	// both a local identity (for decrypting incoming envelopes at
	// Round 3) and a directory entry for every committee member (for
	// sealing outgoing envelopes at Round 1).
	myIdentity *IdentityKey
	directory  IdentityDirectory

	rng io.Reader // entropy for c_i

	// Per-round state.
	myContribution [SeedSize]byte // c_i sampled at Round 1 — SECRET
	encapBlindKey  [SeedSize]byte // per-session non-secret blind used
	//                             // to diversify per-recipient KEM
	//                             // encapsulation seeds. Sampled fresh
	//                             // at Round 1; NOT derived from
	//                             // myContribution (Agent 4 C2:
	//                             // earlier design fed myContribution
	//                             // into encapBlind, making KEM ct
	//                             // bytes a function of the secret).
	myShares    []shamirShare // f_i(j) for each committee position j ∈ {1..n}
	round1Cache []*DKGRound1Msg
	myDigest    [32]byte

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
// myIdentity is the calling party's long-term ML-KEM-768 + ML-DSA-65
// keypair; the KEM secret half is used to open incoming envelopes at
// Round 3. directory must contain a published IdentityPublicKey for
// every committee member (including myID — the round-trip check
// requires we can seal-and-open our own envelope as a sanity gate).
//
// rng may be nil — crypto/rand is used as the default entropy source.
// Pass a deterministic reader (e.g. bytes.NewReader of a fixed seed)
// for KAT-reproducible DKG runs.
func NewDKGSession(
	params *Params,
	committee []NodeID,
	threshold int,
	myID NodeID,
	myIdentity *IdentityKey,
	directory IdentityDirectory,
	rng io.Reader,
) (*DKGSession, error) {
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
	if myIdentity == nil {
		return nil, ErrIdentityKeyMissing
	}
	if directory == nil {
		return nil, ErrDirectoryIncomplete
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
	return &DKGSession{
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

// Round1 samples this party's contribution, byte-wise Shamir-shares
// it, KEM-wraps each per-recipient envelope under the recipient's
// long-term ML-KEM-768 public key, and returns the broadcast.
//
// All Round-1 messages from the entire committee must be delivered
// to every party before Round 2 begins. Partial delivery becomes a
// timeout abort.
//
// CR-6 path A: no commit-and-open; the broadcast carries no separate
// commitment field. CR-8: per-recipient envelopes are ML-KEM-768
// sealed against the recipient's published identity public key so a
// passive network observer learns nothing about per-recipient shares.
func (s *DKGSession) Round1() (*DKGRound1Msg, error) {
	if _, err := io.ReadFull(s.rng, s.myContribution[:]); err != nil {
		return nil, ErrShortRand
	}
	// Per-session non-secret blind for the per-recipient KEM
	// encapseed derivation (Agent 4 C2 fix). Sampled fresh from
	// the same RNG as myContribution; NOT fed into anything that
	// produces a secret value. Even if encapBlindKey leaks (e.g.
	// via a coredump after Round-1), no information about
	// myContribution is exposed because the two are
	// independently sampled.
	if _, err := io.ReadFull(s.rng, s.encapBlindKey[:]); err != nil {
		return nil, ErrShortRand
	}

	// Per-byte Shamir share of c_i. Coefficient material is
	// domain-separated by (committee root, my-index, contribution-
	// derived seed) so two DKG sessions on the same contribution
	// never collide. The seed-derived expansion replaces the v0.1
	// blind_i material which existed only to feed the dropped
	// commit-and-open layer.
	committeeRoot := s.commitCommitteeRoot()
	keyMaterial := []byte{}
	keyMaterial = append(keyMaterial, []byte("PULSAR-DKG-DEALER-V1")...)
	keyMaterial = append(keyMaterial, committeeRoot[:]...)
	keyMaterial = append(keyMaterial, byte(s.myIndex>>8), byte(s.myIndex))
	keyMaterial = append(keyMaterial, s.myContribution[:]...)
	streamLen := (s.Threshold - 1) * SeedSize * 2
	if streamLen < 2 {
		streamLen = 2
	}
	stream := cshake256(keyMaterial, streamLen, tagSeedShare)

	// Per-party polynomial evaluation runs through the backend-dispatched
	// path (dkg_gpu.go). Defaults to the byte-identical CPU path; switches
	// to a parallel byte-slot fan-out when the runtime resolves to GPU and
	// the input shape clears the dispatch threshold. Output is byte-equal
	// to the historical reference (proved by TestDKG_GPU_ByteEqual).
	var gf [SeedSize]uint16
	for b := 0; b < SeedSize; b++ {
		gf[b] = uint16(s.myContribution[b])
	}
	shares, err := shamirDealRandomGFAccel(gf, len(s.Committee), s.Threshold, stream)
	if err != nil {
		return nil, err
	}
	s.myShares = shares

	// KEM-wrap each per-recipient envelope. The encapsulation seed
	// is derived deterministically from (committee root, dealer,
	// recipient, per-session NON-SECRET encapBlindKey). KAT
	// regeneration is still byte-stable per-RNG-seed (the encapBlindKey
	// is sampled from the same rng); the security improvement vs
	// the v0.1 design is that encapBlindKey is INDEPENDENT of
	// myContribution, so a fault injection on the cSHAKE256 call
	// here cannot leak bits of the secret contribution.
	envelopes := make(map[NodeID]DKGShareEnvelope, len(s.Committee))
	for posIdx, recipient := range s.Committee {
		share := shares[posIdx]
		shareBytes := shareToBytes(share)

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

	return &DKGRound1Msg{
		NodeID:    s.MyID,
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

	// Decrypt every envelope addressed to me. Each envelope reveals
	// BOTH (a) the dealer's Shamir share for me at x=myIndex (which
	// I aggregate into my own KeyShare for threshold sign) AND (b)
	// the dealer's full contribution c_i (which I sum into the byte-
	// sum to derive the master public key).
	//
	// The per-recipient KEM-wrapping (CR-8) prevents passive network
	// observers from learning either component. The Shamir share at
	// other recipients' positions remains unknown to me — which is
	// exactly the v0.1 reconstruction-aggregator trust model: every
	// committee member learns the master secret (via c_i sum), but no
	// non-committee observer learns anything from the broadcast.
	committeeRoot := s.commitCommitteeRoot()
	var aggY [SeedSize]uint16
	// byteSum aggregates the per-dealer contributions c_i byte-wise
	// over GF(257). At x=0 of the joint polynomial f(x) = Σ_i f_i(x),
	// f(0) = Σ_i f_i(0) = Σ_i c_i — i.e. the byte-sum we need for the
	// master seed.
	var byteSum [SeedSize]uint16
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
		senderShareBytes, senderContrib, openErr := sealOpenEnvelope(
			m.NodeID, s.MyID, committeeRoot, env, shareWireSize, s.myIdentity,
		)
		if openErr != nil {
			return &DKGOutput{
				AbortEvidence: &AbortEvidence{
					Kind:    ComplaintBadDelivery,
					Accuser: s.MyID,
					Accused: m.NodeID,
				},
			}, nil
		}
		var shareArr [shareWireSize]byte
		copy(shareArr[:], senderShareBytes)
		senderShare := shareFromBytes(uint32(s.myIndex), shareArr)
		for b := 0; b < SeedSize; b++ {
			aggY[b] = uint16((uint32(aggY[b]) + uint32(senderShare.Y[b])) % shamirPrime)
			byteSum[b] = uint16((uint32(byteSum[b]) + uint32(senderContrib[b])) % shamirPrime)
		}
	}
	s.aggregateShare = shamirShare{
		X: uint32(s.myIndex),
		Y: aggY,
	}

	// Derive the master ML-DSA seed.
	//
	// masterByteSum is the byte-wise sum of all dealer contributions
	// over GF(257). The cSHAKE256 mix flattens any modular bias and
	// produces a uniform 32-byte ML-DSA seed.
	byteSumBytes := make([]byte, SeedSize*2)
	for b := 0; b < SeedSize; b++ {
		byteSumBytes[2*b] = byte(byteSum[b] >> 8)
		byteSumBytes[2*b+1] = byte(byteSum[b])
	}
	mixInput := append(append([]byte{}, byteSumBytes...), committeeRoot[:]...)
	var masterSeed [SeedSize]byte
	copy(masterSeed[:], cshake256(mixInput, SeedSize, tagSeedShare))

	sk, err := KeyFromSeed(s.Params, masterSeed)
	if err != nil {
		// Zeroize the reconstructed secret material before returning.
		// No defer: call-site-local cleanup keeps the secret lifetime
		// legible.
		zeroizeSeed(&masterSeed)
		zeroizeBytes(byteSumBytes)
		zeroizeBytes(mixInput)
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
	out := &DKGOutput{
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
	}
	// Wipe the reconstructed master SK + intermediate secret
	// material. The per-party SecretShare returned in `out` is the
	// caller's responsibility to manage; this scope's local copies
	// are wiped here.
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
// The digest binds the committee root, the dealer-NodeID, every
// recipient's NodeID, the recipient-specific KEM ciphertext, and the
// recipient-specific sealed payload. An equivocating dealer that
// ships different (ct, sealed) pairs to different recipients
// (relative to what they broadcast in this message) is caught by
// Round-3 digest comparison.
//
// committeeRoot binding (post-audit): without it, a colluding
// dealer + recipient pair sharing the same KEM ciphertext across
// committees could replay an envelope across DKG sessions; binding
// the committee root pins the digest to THIS specific committee.
func (s *DKGSession) computeRound2Digest(ordered []*DKGRound1Msg) [32]byte {
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
