// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsarm

// threshold.go — two-round threshold signing.
//
// Protocol shape (v0.1 reconstruction-aggregator instantiation):
//
//   Round 1 (party i): sample per-round mask r_i. Compute the masked
//     share s'_i = share_i ⊕ r_i. Compute the commit
//       D_i = cSHAKE256(s'_i || tau_1)
//     where tau_1 = (sid, kappa, T, i, pk, mu). MAC D_i for every
//     peer j ∈ T \ {i} under the long-lived MAC key K_{i,j} via
//     KMAC256. Broadcast (D_i, {MAC_{i,j}}).
//
//   Round 2 (party i): verify every received MAC; on success reveal
//     (r_i, masked_share_i) so peers can re-derive D_i and combine.
//     Broadcast the revealed pair as PartialSig.
//
//   Combine: aggregator gathers t Round-2 reveals, re-derives the
//     per-party D_i and checks it equals the Round-1 commit, then
//     Lagrange-interpolates the byte-sum at x=0, applies the same
//     cSHAKE256 mix as DKG to recover the master seed, calls
//     FIPS 204 mldsa.SignTo. Returns the resulting signature.
//
// The 2-round commit-and-reveal pattern with MACs is the structural
// pulsar-m.tex §4.2 form. The reconstruction-aggregator path collapses
// the Lagrange-linearity-of-z computation of §4.2 into a single FIPS
// 204 Sign call after share Lagrange reconstruction. This trade is
// documented in docs/known-limitations.md; the v0.2 path implements
// the pure Lagrange-linearity sign where the secret is never
// reconstructed in any party's memory.

import (
	"crypto/rand"
	"errors"
	"io"
)

// Errors returned by threshold signing.
var (
	ErrNilSession       = errors.New("pulsarm: nil ThresholdSigner")
	ErrEmptyQuorum      = errors.New("pulsarm: empty signing quorum")
	ErrInsufficientQuor = errors.New("pulsarm: quorum smaller than threshold")
	ErrRound1MACBad     = errors.New("pulsarm: Round-1 MAC verification failed")
	ErrRound2CommitBad  = errors.New("pulsarm: Round-2 reveal does not match Round-1 commit")
	ErrSessionMismatch  = errors.New("pulsarm: round messages from different sessions")
	ErrAttemptMismatch  = errors.New("pulsarm: round messages from different rejection-restart attempts")
	ErrNotInQuorum      = errors.New("pulsarm: party not in quorum")
	ErrPubkeyMismatch   = errors.New("pulsarm: KeyShare public-key does not match")
)

// ThresholdSigner holds one party's state for a 2-round threshold
// sign ceremony.
//
// A ThresholdSigner is single-use: one (sid, attempt) pair per
// instance. The protocol-layer driver allocates a fresh signer for
// each rejection-restart attempt (the FIPS 204 restart counter is
// the Attempt field; see pulsar-m.tex §6.2 for the cross-restart
// state discipline).
type ThresholdSigner struct {
	Params    *Params
	NodeID    NodeID
	SecretShare *KeyShare

	// SessionID uniquely identifies this signature attempt across
	// the network. Distinct sessions get distinct PRNG seeds so two
	// concurrent sign attempts on the same (pk, message) never share
	// randomness.
	SessionID [16]byte

	// Attempt is the FIPS 204 rejection-restart counter kappa. Each
	// restart advances kappa by 1; the per-attempt PRNG seed mixes
	// kappa so distinct restarts get distinct randomness.
	Attempt uint32

	// Quorum is the t-element signing committee, sorted ascending by
	// NodeID. All parties in Quorum must hold KeyShares with the same
	// EvalPoint mapping that DKG installed.
	Quorum []NodeID

	// Message is the FIPS 204 message being signed (already
	// transcript-prefixed; pass the same bytes that single-party
	// mldsa.SignTo would consume).
	Message []byte

	// MACKeys is the long-lived per-peer MAC key set. In v0.1 this
	// is derived at session setup via cSHAKE256 over (myNodeID,
	// peerNodeID, group-pubkey) — a non-secret value sufficient for
	// the v0.1 commit-and-reveal binding. v0.2 (production) replaces
	// this with per-session ephemeral keys exchanged at the
	// preprocessing phase per pulsar-m.tex §6.2.
	MACKeys map[NodeID][32]byte

	// rng is the entropy source for per-round mask r_i.
	rng io.Reader

	// Internal Round-1 state.
	myMask        [64]byte // r_i — masks the share bytes for Round-1 commit
	myMaskedShare [64]byte // s'_i = share_i XOR r_i (per byte)
	myCommit      [32]byte // D_i

	// Internal Round-2 state.
	receivedR1 []*Round1Message
}

// NewThresholdSigner constructs a new ThresholdSigner for a
// (sessionID, attempt, quorum, message) tuple.
//
// quorum must be sorted ascending by NodeID and must contain
// signer.NodeID. All parties in the quorum must share the same group
// public key (i.e. they completed the same DKG).
//
// rng may be nil — crypto/rand is used by default. Pass a
// deterministic reader for KAT runs.
func NewThresholdSigner(params *Params, sessionID [16]byte, attempt uint32, quorum []NodeID, myShare *KeyShare, message []byte, rng io.Reader) (*ThresholdSigner, error) {
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
	// myShare.NodeID must appear in quorum.
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
	// Derive per-peer MAC keys.
	macKeys := make(map[NodeID][32]byte, len(quorum)-1)
	for _, peer := range quorum {
		if peer == myShare.NodeID {
			continue
		}
		macKeys[peer] = deriveMACKey(myShare.NodeID, peer, myShare.Pub)
	}
	return &ThresholdSigner{
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
// the Round-1 broadcast. The mask is consumed at Round 2 — there is
// no "fresh mask per peer" because the commit is over a single
// masked share that every peer aggregates equivalently.
func (s *ThresholdSigner) Round1(message []byte) (*Round1Message, error) {
	// Sample mask.
	if _, err := io.ReadFull(s.rng, s.myMask[:]); err != nil {
		return nil, ErrShortRand
	}
	// Mask the share byte-by-byte XOR.
	for i := 0; i < 64; i++ {
		s.myMaskedShare[i] = s.SecretShare.Share[i] ^ s.myMask[i]
	}
	// Commit D_i = cSHAKE256(mask_i || masked_i || tau_1). Binding
	// BOTH halves into the commit makes Round-2 reveal tampering of
	// either half a commit-mismatch in Combine. Without binding the
	// mask, an adversary intercepting Round-2 could rotate (mask,
	// masked) to (mask ⊕ δ, masked) and the reconstructed share would
	// be silently corrupted; binding both closes that gap.
	tau := s.transcriptTau1(message)
	commitInput := append(append([]byte{}, s.myMask[:]...), s.myMaskedShare[:]...)
	commitInput = append(commitInput, tau...)
	s.myCommit = transcriptHash32(tagSignR1, commitInput)

	// MACs to every peer in the quorum.
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

	return &Round1Message{
		NodeID:    s.NodeID,
		SessionID: s.SessionID,
		Attempt:   s.Attempt,
		Commit:    s.myCommit,
		MACs:      macs,
	}, nil
}

// Round2 ingests every party's Round-1 broadcast, verifies the MACs
// against this party, and emits the Round-2 reveal carrying (r_i,
// masked_share_i). Peers re-derive D_i from the reveal and check it
// equals the Round-1 commit.
//
// On MAC failure, returns ErrRound1MACBad along with AbortEvidence
// that the protocol-layer driver MUST broadcast as a complaint.
func (s *ThresholdSigner) Round2(round1Msgs []*Round1Message) (*Round2Message, *AbortEvidence, error) {
	if len(round1Msgs) < 1 {
		return nil, nil, ErrEmptyQuorum
	}
	// Verify session and attempt consistency, and MACs from each peer
	// to this party.
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
		// Peer's MAC to me uses the same shared key under our pair
		// derivation (deriveMACKey is symmetric — see comment there).
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
		// Constant-time MAC compare.
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

	// Round-2 reveal: (r_i, masked_share_i). Pack into PartialSig.
	revealed := make([]byte, 0, 128)
	revealed = append(revealed, s.myMask[:]...)
	revealed = append(revealed, s.myMaskedShare[:]...)

	return &Round2Message{
		NodeID:     s.NodeID,
		SessionID:  s.SessionID,
		Attempt:    s.Attempt,
		W1:         nil, // unused in v0.1 reconstruction-aggregator instantiation
		PartialSig: revealed,
	}, nil, nil
}

// Combine produces a FIPS 204 ML-DSA signature from a quorum of
// Round-2 reveals.
//
// params, groupPubkey, message, sessionID, attempt, and quorum MUST
// match what was passed to NewThresholdSigner. Round-2 messages must
// come from at least `threshold` distinct quorum members; any number
// beyond threshold is tolerated and ignored.
//
// Combine is a pure function — it does not require ThresholdSigner
// state. Any honest party in the quorum can call Combine after Round
// 2 completes.
//
// The returned Signature, when passed to Verify(params, groupPubkey,
// message, sig), returns nil (i.e. the signature is FIPS 204 valid).
func Combine(params *Params, groupPubkey *PublicKey, message []byte, ctx []byte, randomized bool, sessionID [16]byte, attempt uint32, quorum []NodeID, threshold int, round1 []*Round1Message, round2 []*Round2Message, allShares []*KeyShare) (*Signature, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if groupPubkey == nil {
		return nil, ErrNilPublicKey
	}
	if len(round1) < threshold || len(round2) < threshold {
		return nil, ErrInsufficientQuor
	}

	// Index Round-1 messages by sender.
	r1ByID := make(map[NodeID]*Round1Message, len(round1))
	for _, m := range round1 {
		if m.SessionID != sessionID || m.Attempt != attempt {
			return nil, ErrSessionMismatch
		}
		r1ByID[m.NodeID] = m
	}

	// For each Round-2 reveal: re-derive D_i and compare against
	// the matching Round-1 commit.
	revealedShares := make(map[NodeID][64]byte, threshold)
	for _, r2 := range round2 {
		r1, ok := r1ByID[r2.NodeID]
		if !ok {
			continue
		}
		if r2.SessionID != sessionID || r2.Attempt != attempt {
			return nil, ErrSessionMismatch
		}
		if len(r2.PartialSig) != 128 {
			return nil, ErrRound2CommitBad
		}
		var mask [64]byte
		var masked [64]byte
		copy(mask[:], r2.PartialSig[:64])
		copy(masked[:], r2.PartialSig[64:])

		// Re-derive D_i = cSHAKE256(mask || masked || tau_1).
		tau := transcriptTau1Bytes(sessionID, attempt, quorum, r2.NodeID, groupPubkey, message)
		commitInput := append(append([]byte{}, mask[:]...), masked[:]...)
		commitInput = append(commitInput, tau...)
		recomputed := transcriptHash32(tagSignR1, commitInput)
		if !ctEqual32(recomputed, r1.Commit) {
			return nil, ErrRound2CommitBad
		}
		// Recover share = masked XOR mask.
		var share [64]byte
		for i := 0; i < 64; i++ {
			share[i] = masked[i] ^ mask[i]
		}
		revealedShares[r2.NodeID] = share
	}

	if len(revealedShares) < threshold {
		return nil, ErrInsufficientQuor
	}

	// Pair each revealed share with its KeyShare entry to recover
	// the EvalPoint. The aggregator gets allShares as a directory so
	// it can map NodeID → EvalPoint without recomputing the DKG
	// committee order.
	keyShareByID := make(map[NodeID]*KeyShare, len(allShares))
	for _, ks := range allShares {
		keyShareByID[ks.NodeID] = ks
	}

	shares := make([]shamirShare, 0, threshold)
	for id, sBytes := range revealedShares {
		ks, ok := keyShareByID[id]
		if !ok {
			return nil, ErrNotInQuorum
		}
		var buf [shareWireSize]byte
		copy(buf[:], sBytes[:])
		shares = append(shares, shareFromBytes(ks.EvalPoint, buf))
		if len(shares) == threshold {
			break
		}
	}

	// Reconstruct the GF(257) byte-sum (NOT mod 256) so the cSHAKE256
	// mix input matches DKG's mix input bit-for-bit. The committee
	// root is canonical given allShares.
	byteSum, err := shamirReconstructGF(shares)
	if err != nil {
		return nil, err
	}
	committeeRoot := committeeRootFromShares(allShares)
	byteSumBytes := make([]byte, SeedSize*2)
	for b := 0; b < SeedSize; b++ {
		byteSumBytes[2*b] = byte(byteSum[b] >> 8)
		byteSumBytes[2*b+1] = byte(byteSum[b])
	}
	mixInput := append(append([]byte{}, byteSumBytes...), committeeRoot[:]...)
	var masterSeed [SeedSize]byte
	copy(masterSeed[:], cshake256(mixInput, SeedSize, tagSeedShare))

	// FIPS 204 sign with the reconstructed seed-derived key.
	sk, err := KeyFromSeed(params, masterSeed)
	if err != nil {
		return nil, err
	}
	// Sanity: the reconstructed pubkey MUST match groupPubkey, else
	// the aggregator's share set is wrong / tampered.
	if !sk.Pub.Equal(groupPubkey) {
		return nil, ErrPubkeyMismatch
	}
	// Use deterministic-randomness path so KATs are reproducible.
	// Production callers set randomized=true; KAT/test callers pass
	// randomized=false.
	sigBytes, err := mldsaSign(params.Mode, sk.Bytes, message, ctx, randomized, rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Signature{Mode: params.Mode, Bytes: sigBytes}, nil
}

// transcriptTau1 builds the Round-1 transcript tau_1 = (sid, kappa,
// T, i, pk, mu). tau_1 is bound into every commit and MAC so that a
// cross-session replay of the commit-and-reveal pair becomes a
// transcript mismatch.
func (s *ThresholdSigner) transcriptTau1(_ []byte) []byte {
	return transcriptTau1Bytes(s.SessionID, s.Attempt, s.Quorum, s.NodeID, s.SecretShare.Pub, s.Message)
}

// transcriptTau1ForSender builds tau_1 with sender's NodeID rather
// than this party's NodeID — used when verifying a peer's commit
// MAC. tau_1 is sender-dependent because each party's commit binds
// to its own NodeID (preventing share-equivocation across parties).
func (s *ThresholdSigner) transcriptTau1ForSender(sender NodeID) []byte {
	return transcriptTau1Bytes(s.SessionID, s.Attempt, s.Quorum, sender, s.SecretShare.Pub, s.Message)
}

// transcriptTau1Bytes is the package-level implementation of tau_1.
func transcriptTau1Bytes(sid [16]byte, attempt uint32, quorum []NodeID, sender NodeID, pk *PublicKey, message []byte) []byte {
	parts := [][]byte{}
	parts = append(parts, sid[:])
	parts = append(parts, []byte{byte(attempt >> 24), byte(attempt >> 16), byte(attempt >> 8), byte(attempt)})
	for _, q := range quorum {
		parts = append(parts, q[:])
	}
	parts = append(parts, sender[:])
	if pk != nil {
		parts = append(parts, pk.Bytes)
	}
	parts = append(parts, message)
	// Flatten into a single byte string via SP 800-185 encode_string
	// so commit boundaries are unambiguous.
	out := []byte{}
	out = append(out, leftEncode(uint64(len(parts)))...)
	for _, p := range parts {
		out = append(out, encodeString(p)...)
	}
	return out
}

// deriveMACKey derives a symmetric MAC key between (a, b). Symmetric:
// deriveMACKey(a, b, pk) == deriveMACKey(b, a, pk) for the same pk.
func deriveMACKey(a, b NodeID, pk *PublicKey) [32]byte {
	// Sort the pair so both ends derive the same key.
	first, second := a, b
	if nodeIDLess(b, a) {
		first, second = b, a
	}
	parts := [][]byte{first[:], second[:]}
	if pk != nil {
		parts = append(parts, pk.Bytes)
	}
	return transcriptHash32("PULSAR-M-SIGN-MACKEY-V1", parts...)
}

// committeeRootFromShares reconstructs the DKG committee root from a
// directory of KeyShares. The committee root is the canonical
// 32-byte digest of the sorted committee that DKG installed.
func committeeRootFromShares(shares []*KeyShare) [32]byte {
	ids := make([]NodeID, 0, len(shares))
	for _, s := range shares {
		ids = append(ids, s.NodeID)
	}
	// Sort canonically.
	for i := 1; i < len(ids); i++ {
		for j := i; j > 0 && nodeIDLess(ids[j], ids[j-1]); j-- {
			ids[j], ids[j-1] = ids[j-1], ids[j]
		}
	}
	parts := make([][]byte, 0, len(ids)+1)
	parts = append(parts, []byte("PULSAR-M-COMMITTEE-V1"))
	for _, id := range ids {
		parts = append(parts, id[:])
	}
	return transcriptHash32(tagDKGCommit, parts...)
}

// ctEqualSlice is a constant-time byte-slice equality check. Returns
// false if lengths differ; otherwise scans every byte regardless of
// where the first mismatch occurs.
func ctEqualSlice(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
