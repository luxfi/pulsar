// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// large_threshold.go -- GF(q) two-round threshold signing. The
// parallel of threshold.go's ThresholdSigner / Combine for the
// wide-committee regime, with the same MAC + commit-and-reveal
// shape and the same cSHAKE256 mix to derive the master seed.
//
// Same caveat as large_dkg.go: the canonical Lux deployment runs
// the small-committee (GF(257)) path at (T, N) = (2, 3) per
// sortitioned group; this Large* path is the alternative big-
// committee deployment for permissioned consortium / audit-
// attestation scenarios where a single large committee is desired.

import (
	"crypto/rand"
	"io"
)

// LargeThresholdSigner holds one party's state for one GF(q) threshold
// sign ceremony.
type LargeThresholdSigner struct {
	Params      *Params
	NodeID      NodeID
	SecretShare *LargeKeyShare

	SessionID [16]byte
	Attempt   uint32

	Quorum  []NodeID
	Message []byte

	MACKeys map[NodeID][32]byte

	rng io.Reader

	myMask        [shareWireSizeQ]byte
	myMaskedShare [shareWireSizeQ]byte
	myCommit      [32]byte

	receivedR1 []*LargeRound1Message
}

// NewLargeThresholdSigner constructs a new GF(q) threshold signer.
// quorum is canonicalised (byte-ascending NodeID) and must include
// myShare.NodeID; quorum size is capped at TargetCommitteeSize.
func NewLargeThresholdSigner(params *Params, sessionID [16]byte, attempt uint32, quorum []NodeID, myShare *LargeKeyShare, message []byte, rng io.Reader) (*LargeThresholdSigner, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if myShare == nil {
		return nil, ErrNilKey
	}
	if myShare.Mode != params.Mode {
		return nil, ErrModeMismatch
	}
	if len(quorum) == 0 {
		return nil, ErrEmptyQuorum
	}
	if len(quorum) > TargetCommitteeSize {
		return nil, ErrCommitteeAboveCap
	}
	found := false
	for _, q := range quorum {
		if q == myShare.NodeID {
			found = true
			break
		}
	}
	if !found {
		return nil, ErrNotInQuorum
	}
	if rng == nil {
		rng = rand.Reader
	}
	macKeys := make(map[NodeID][32]byte, len(quorum)-1)
	for _, peer := range quorum {
		if peer == myShare.NodeID {
			continue
		}
		macKeys[peer] = deriveMACKey(myShare.NodeID, peer, myShare.Pub)
	}
	return &LargeThresholdSigner{
		Params:      params,
		NodeID:      myShare.NodeID,
		SecretShare: myShare,
		SessionID:   sessionID,
		Attempt:     attempt,
		Quorum:      quorum,
		Message:     append([]byte{}, message...),
		MACKeys:     macKeys,
		rng:         rng,
	}, nil
}

// Round1 samples the per-round mask, computes the commit, and emits
// the Round-1 broadcast.
func (s *LargeThresholdSigner) Round1(message []byte) (*LargeRound1Message, error) {
	if _, err := io.ReadFull(s.rng, s.myMask[:]); err != nil {
		return nil, ErrShortRand
	}
	for i := 0; i < shareWireSizeQ; i++ {
		s.myMaskedShare[i] = s.SecretShare.Share[i] ^ s.myMask[i]
	}
	tau := s.transcriptTau1()
	commitInput := append(append([]byte{}, s.myMask[:]...), s.myMaskedShare[:]...)
	commitInput = append(commitInput, tau...)
	s.myCommit = transcriptHash32(tagSignR1, commitInput)

	macs := make(map[NodeID][32]byte, len(s.Quorum)-1)
	for _, peer := range s.Quorum {
		if peer == s.NodeID {
			continue
		}
		key := s.MACKeys[peer]
		macInput := append(append([]byte{}, s.myCommit[:]...), tau...)
		mac := kmac256(key[:], macInput, 32, tagSignR1MAC)
		var macArr [32]byte
		copy(macArr[:], mac)
		macs[peer] = macArr
	}

	return &LargeRound1Message{
		NodeID:    s.NodeID,
		SessionID: s.SessionID,
		Attempt:   s.Attempt,
		Commit:    s.myCommit,
		MACs:      macs,
	}, nil
}

// Round2 verifies MACs and emits the (mask, masked_share) reveal.
func (s *LargeThresholdSigner) Round2(round1Msgs []*LargeRound1Message) (*LargeRound2Message, *AbortEvidence, error) {
	if len(round1Msgs) < 1 {
		return nil, nil, ErrEmptyQuorum
	}
	for _, m := range round1Msgs {
		if m.SessionID != s.SessionID {
			return nil, nil, ErrSessionMismatch
		}
		if m.Attempt != s.Attempt {
			return nil, nil, ErrAttemptMismatch
		}
		if m.NodeID == s.NodeID {
			continue
		}
		key := s.MACKeys[m.NodeID]
		tau := s.transcriptTau1ForSender(m.NodeID)
		macInput := append(append([]byte{}, m.Commit[:]...), tau...)
		expectedMAC := kmac256(key[:], macInput, 32, tagSignR1MAC)
		gotMAC, ok := m.MACs[s.NodeID]
		if !ok {
			return nil, &AbortEvidence{
				Kind:    ComplaintMACFailure,
				Accuser: s.NodeID,
				Accused: m.NodeID,
			}, ErrRound1MACBad
		}
		if !ctEqualSlice(expectedMAC, gotMAC[:]) {
			return nil, &AbortEvidence{
				Kind:     ComplaintMACFailure,
				Accuser:  s.NodeID,
				Accused:  m.NodeID,
				Evidence: append(append([]byte{}, expectedMAC...), gotMAC[:]...),
			}, ErrRound1MACBad
		}
	}
	s.receivedR1 = round1Msgs

	revealed := make([]byte, 0, 2*shareWireSizeQ)
	revealed = append(revealed, s.myMask[:]...)
	revealed = append(revealed, s.myMaskedShare[:]...)

	return &LargeRound2Message{
		NodeID:     s.NodeID,
		SessionID:  s.SessionID,
		Attempt:    s.Attempt,
		W1:         nil,
		PartialSig: revealed,
	}, nil, nil
}

// LargeCombine reconstructs the master seed from a quorum of GF(q)
// Round-2 reveals and emits a single FIPS 204 ML-DSA signature.
func LargeCombine(params *Params, groupPubkey *PublicKey, message []byte, ctx []byte, randomized bool, sessionID [16]byte, attempt uint32, quorum []NodeID, threshold int, round1 []*LargeRound1Message, round2 []*LargeRound2Message, allShares []*LargeKeyShare) (*Signature, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if groupPubkey == nil {
		return nil, ErrNilPublicKey
	}
	if len(round1) < threshold || len(round2) < threshold {
		return nil, ErrInsufficientQuor
	}

	r1ByID := make(map[NodeID]*LargeRound1Message, len(round1))
	for _, m := range round1 {
		if m.SessionID != sessionID || m.Attempt != attempt {
			return nil, ErrSessionMismatch
		}
		r1ByID[m.NodeID] = m
	}

	revealedShares := make(map[NodeID][shareWireSizeQ]byte, threshold)
	for _, r2 := range round2 {
		r1, ok := r1ByID[r2.NodeID]
		if !ok {
			continue
		}
		if r2.SessionID != sessionID || r2.Attempt != attempt {
			return nil, ErrSessionMismatch
		}
		if len(r2.PartialSig) != 2*shareWireSizeQ {
			return nil, ErrRound2CommitBad
		}
		var mask [shareWireSizeQ]byte
		var masked [shareWireSizeQ]byte
		copy(mask[:], r2.PartialSig[:shareWireSizeQ])
		copy(masked[:], r2.PartialSig[shareWireSizeQ:])

		tau := transcriptTau1Bytes(sessionID, attempt, quorum, r2.NodeID, groupPubkey, message)
		commitInput := append(append([]byte{}, mask[:]...), masked[:]...)
		commitInput = append(commitInput, tau...)
		recomputed := transcriptHash32(tagSignR1, commitInput)
		if !ctEqual32(recomputed, r1.Commit) {
			return nil, ErrRound2CommitBad
		}
		var share [shareWireSizeQ]byte
		for i := 0; i < shareWireSizeQ; i++ {
			share[i] = masked[i] ^ mask[i]
		}
		revealedShares[r2.NodeID] = share
	}

	if len(revealedShares) < threshold {
		return nil, ErrInsufficientQuor
	}

	keyShareByID := make(map[NodeID]*LargeKeyShare, len(allShares))
	for _, ks := range allShares {
		keyShareByID[ks.NodeID] = ks
	}

	shares := make([]shamirShareQ, 0, threshold)
	for id, sBytes := range revealedShares {
		ks, ok := keyShareByID[id]
		if !ok {
			return nil, ErrNotInQuorum
		}
		var buf [shareWireSizeQ]byte
		copy(buf[:], sBytes[:])
		shares = append(shares, shareFromBytesQ(ks.EvalPoint, buf))
		if len(shares) == threshold {
			break
		}
	}

	byteSum, err := shamirReconstructGFQ(shares)
	if err != nil {
		return nil, err
	}
	committeeRoot := committeeRootFromLargeShares(allShares)
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

	sk, err := KeyFromSeed(params, masterSeed)
	if err != nil {
		return nil, err
	}
	if !sk.Pub.Equal(groupPubkey) {
		return nil, ErrPubkeyMismatch
	}
	sigBytes, err := mldsaSign(params.Mode, sk.Bytes, message, ctx, randomized, rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Signature{Mode: params.Mode, Bytes: sigBytes}, nil
}

func (s *LargeThresholdSigner) transcriptTau1() []byte {
	return transcriptTau1Bytes(s.SessionID, s.Attempt, s.Quorum, s.NodeID, s.SecretShare.Pub, s.Message)
}

func (s *LargeThresholdSigner) transcriptTau1ForSender(sender NodeID) []byte {
	return transcriptTau1Bytes(s.SessionID, s.Attempt, s.Quorum, sender, s.SecretShare.Pub, s.Message)
}
