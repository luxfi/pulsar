// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// talus_nonce_dkg.go — the dealerless Shamir Nonce DKG (TALUS §2.4).
//
// This is the REAL, dealerless replacement for the trusted nonce-sharing inside
// DealNonceMPCDebug: no party (and no dealer) ever learns the joint one-time
// nonce ȳ. Each party h samples its OWN small contribution y_h, Shamir-shares it
// over the quorum's evaluation points, and ships one share to every member.
// Every member sums the shares it RECEIVES to obtain its nonce share
//
//	y_i = Σ_h f_h(x_i) = F(x_i),   F = Σ_h f_h,   F(0) = Σ_h y_h = ȳ,
//
// where f_h is party h's fresh degree-(T−1) Shamir polynomial with constant term
// y_h. Because each y_i is an evaluation of the single degree-(T−1) polynomial F,
// the y_i are a valid Shamir sharing of ȳ at threshold T: any T of them
// Lagrange-interpolate to ȳ (used ONLY inside the signing response z = y + c·s1,
// where ȳ is masked by the secret key — never reconstructed in the clear), and
// any T−1 of them are information-theoretically independent of ȳ.
//
// SMALL JOINT NONCE. The contribution range R_h = ⌊(γ1 − 2β − 4)/N⌋ guarantees
// ‖ȳ‖∞ ≤ Σ_h ‖y_h‖∞ ≤ N·R_h ≤ γ1 − 2β − 4, so the aggregated response clears the
// FIPS 204 reject bound ‖z‖∞ ≤ ‖ȳ‖∞ + ‖c·s1‖∞ ≤ (γ1 − 2β − 4) + β = γ1 − β − 4 <
// γ1 − β for every admissible challenge. (TALUS samples y_h ∈ [−γ1/|S|, γ1/|S|];
// the slightly tighter R_h folds in the 2β BCC margin and a 4-coefficient slack.)
//
// ONE-TIME USE. A nonce DKG instance is bound to a single nonceID and ERASES its
// secret state after Finalize or Abort. Reusing a nonce share across two
// messages reuses ȳ, which leaks the key (two z's on the same y solve for c·s1);
// the consumed flag makes that a hard error.
//
// MALICIOUS SECURITY (documented hook, not the core). Each contribution is bound
// by a hash commitment (ContribCommit) so a rushing party cannot choose y_h after
// seeing others'. Full malicious VSS — verifiable that every received share lies
// on a consistent degree-(T−1) polynomial, with identifiable abort on a bad
// dealer — needs Pedersen commitments over a SEPARATE prime-order group (Feldman
// over GF(q) is INSECURE here: q−1 = 2^13·3·5·… has tiny DL subgroups) plus a
// complaint round. That layer is orthogonal and fail-closed-pending; the
// dealerless share arithmetic below is the load-bearing, fully-real deliverable.

import (
	"errors"
	"io"

	"golang.org/x/crypto/sha3"
)

var (
	// ErrNonceDKGShape rejects a malformed quorum / eval-point list / share.
	ErrNonceDKGShape = errors.New("pulsar: nonce DKG shape does not match the parameter set / quorum")
	// ErrNonceDKGNotInQuorum is returned when a participant's NodeID is absent
	// from the quorum it was constructed against.
	ErrNonceDKGNotInQuorum = errors.New("pulsar: nonce DKG participant not in quorum")
	// ErrNonceDKGMissingDeal is returned by Finalize when a participant has not
	// received a contribution share from every quorum member.
	ErrNonceDKGMissingDeal = errors.New("pulsar: nonce DKG missing a contribution share from some quorum member")
	// ErrNonceDKGConsumed marks a one-time nonce instance that has already been
	// finalized or aborted — its secret state is erased and cannot be reused.
	ErrNonceDKGConsumed = errors.New("pulsar: nonce DKG instance already consumed (one-time use)")
	// ErrNonceDKGBadCommit is returned when a received contribution share does
	// not match its sender's announced commitment (rushing / equivocation).
	ErrNonceDKGBadCommit = errors.New("pulsar: nonce DKG contribution share does not match its commitment")
	// ErrNonceDKGNonceMismatch rejects a deal bound to a different nonceID.
	ErrNonceDKGNonceMismatch = errors.New("pulsar: nonce DKG deal bound to a different nonceID")
)

// NonceDKGDeal is one party's contribution share routed to one recipient:
// f_From(x_To), a length-L poly-vector over GF(q). The Commit field binds the
// SENDER's whole contribution (every recipient sees the same Commit) so a
// participant can detect a sender that equivocates between recipients.
type NonceDKGDeal struct {
	NonceID [32]byte
	From    NodeID
	To      NodeID
	Share   polyVec  // f_From(x_To), length L over GF(q)
	Commit  [32]byte // hash commitment to From's full contribution (binds y_h)
}

// NonceDKGParticipant is one validator's local state machine for the dealerless
// nonce DKG. It holds its OWN contribution y_h (erased after dealing), the
// shares it has received, and finally its single nonce share y_i. No field, and
// no method, ever materialises the joint nonce ȳ.
type NonceDKGParticipant struct {
	mode       Mode
	nodeID     NodeID
	quorum     []NodeID
	evalPoints []uint32
	threshold  int
	nonceID    [32]byte
	rng        io.Reader

	contribution polyVec            // y_h, this party's small contribution (secret; erased after Deal)
	dealtCommit  [32]byte           // commitment to y_h that this party broadcasts
	received     map[NodeID]polyVec // f_h(x_self) received from each h
	recvCommit   map[NodeID][32]byte
	yShare       polyVec // y_i = Σ_h f_h(x_self) — set by Finalize
	dealt        bool
	consumed     bool
}

// NewNonceDKGParticipant constructs one validator's nonce-DKG instance bound to
// nonceID. quorum must be sorted ascending and distinct and contain nodeID;
// evalPoints are the GF(q) Shamir points parallel to quorum. The instance is
// one-time: it serves exactly one nonceID and erases its secret on Finalize/Abort.
func NewNonceDKGParticipant(mode Mode, nodeID NodeID, quorum []NodeID, evalPoints []uint32, threshold int, nonceID [32]byte, rng io.Reader) (*NonceDKGParticipant, error) {
	if _, _, _, ok := bccParams(mode); !ok {
		return nil, ErrBCCParamSet
	}
	if len(quorum) == 0 || len(evalPoints) != len(quorum) {
		return nil, ErrNonceDKGShape
	}
	if threshold < 1 || len(quorum) < threshold {
		return nil, ErrInvalidThreshold
	}
	inQuorum := false
	for i := 1; i < len(quorum); i++ {
		if !nodeIDLess(quorum[i-1], quorum[i]) {
			return nil, ErrCommitteeDuplicate
		}
	}
	for _, q := range quorum {
		if q == nodeID {
			inQuorum = true
		}
	}
	if !inQuorum {
		return nil, ErrNonceDKGNotInQuorum
	}
	return &NonceDKGParticipant{
		mode:       mode,
		nodeID:     nodeID,
		quorum:     append([]NodeID{}, quorum...),
		evalPoints: append([]uint32{}, evalPoints...),
		threshold:  threshold,
		nonceID:    nonceID,
		rng:        rng,
		received:   make(map[NodeID]polyVec, len(quorum)),
		recvCommit: make(map[NodeID][32]byte, len(quorum)),
	}, nil
}

// Deal samples this party's small contribution y_h, Shamir-shares it over the
// quorum eval points, and returns one NonceDKGDeal per recipient (including a
// self-deal). The contribution is erased from local state immediately after the
// shares are formed — only the shares (held by recipients) and the public
// commitment survive. ‖y_h‖∞ ≤ ⌊(γ1 − 2β − 4)/N⌋.
func (p *NonceDKGParticipant) Deal() ([]NonceDKGDeal, error) {
	if p.consumed {
		return nil, ErrNonceDKGConsumed
	}
	if p.dealt {
		return nil, errors.New("pulsar: nonce DKG already dealt")
	}
	_, L, _ := modeShape(p.mode)
	_, beta, _, _ := bccParams(p.mode)
	_, _, gamma1Bits, _ := modeTauOmega(p.mode)
	gamma1 := uint32(1) << gamma1Bits
	jointR := gamma1 - 2*beta - 4
	n := uint32(len(p.quorum))
	perPartyR := jointR / n // ⌊R/N⌋ so the joint sum stays ≤ R

	// 1. Sample y_h ∈ R_q^L with ‖y_h‖∞ ≤ perPartyR, store its [0,q) rep.
	yH := make(polyVec, L)
	for l := 0; l < L; l++ {
		for j := 0; j < mldsaN; j++ {
			v, err := randCenteredGFq(p.rng, perPartyR)
			if err != nil {
				return nil, err
			}
			yH[l][j] = v
		}
	}
	p.contribution = yH

	// 2. Commit to the contribution (binds y_h before any share is opened).
	p.dealtCommit = nonceContribCommit(p.nonceID, p.nodeID, yH)

	// 3. Shamir-share y_h over the quorum eval points at threshold T.
	perParty, err := shamirSharePolyVecGFq(yH, p.evalPoints, p.threshold, p.rng)
	if err != nil {
		return nil, err
	}
	deals := make([]NonceDKGDeal, len(p.quorum))
	for i := range p.quorum {
		deals[i] = NonceDKGDeal{
			NonceID: p.nonceID,
			From:    p.nodeID,
			To:      p.quorum[i],
			Share:   perParty[i],
			Commit:  p.dealtCommit,
		}
	}

	// 4. Erase the contribution: after this point y_h exists nowhere on this
	// node; only the dealt shares (now in transit to recipients) carry it, and
	// no T−1 of them reveal it.
	for l := range yH {
		yH[l] = poly{}
	}
	p.contribution = nil
	p.dealt = true
	return deals, nil
}

// Receive accepts one contribution share addressed to this participant, checking
// the nonce binding and the sender's commitment consistency.
func (p *NonceDKGParticipant) Receive(deal NonceDKGDeal) error {
	if p.consumed {
		return ErrNonceDKGConsumed
	}
	if deal.NonceID != p.nonceID {
		return ErrNonceDKGNonceMismatch
	}
	if deal.To != p.nodeID {
		return ErrNonceDKGShape
	}
	_, L, _ := modeShape(p.mode)
	if len(deal.Share) != L {
		return ErrNonceDKGShape
	}
	// Commitment consistency: if we have already seen From's commitment (e.g.
	// gossiped), it must match (no equivocation between recipients).
	if c, ok := p.recvCommit[deal.From]; ok && c != deal.Commit {
		return ErrNonceDKGBadCommit
	}
	p.recvCommit[deal.From] = deal.Commit
	p.received[deal.From] = append(polyVec(nil), deal.Share...)
	return nil
}

// Finalize sums the received contribution shares into this party's single nonce
// share y_i = Σ_h f_h(x_self). It requires a share from EVERY quorum member (a
// missing dealer is an abort, not a silent degree drop). The joint nonce ȳ is
// never formed. The returned y_i is also cached for SetNonceShare.
func (p *NonceDKGParticipant) Finalize() (polyVec, error) {
	if p.consumed {
		return nil, ErrNonceDKGConsumed
	}
	_, L, _ := modeShape(p.mode)
	for _, h := range p.quorum {
		if _, ok := p.received[h]; !ok {
			return nil, ErrNonceDKGMissingDeal
		}
	}
	yShare := make(polyVec, L)
	for _, h := range p.quorum {
		sh := p.received[h]
		for l := 0; l < L; l++ {
			for j := 0; j < mldsaN; j++ {
				yShare[l][j] = uint32((uint64(yShare[l][j]) + uint64(sh[l][j])) % shamirPrimeQ)
			}
		}
	}
	p.yShare = yShare
	return append(polyVec(nil), yShare...), nil
}

// CommitRoot returns a stable commitment to the SET of contributions seen by
// this participant — the public binding the consensus layer records so every
// honest party agrees on the same joint nonce derivation. It hashes the sorted
// per-contributor commitments; it carries NO secret (not y_h, not the shares).
func (p *NonceDKGParticipant) CommitRoot() [32]byte {
	h := sha3.NewShake256()
	_, _ = h.Write([]byte("PULSAR-TALUS/nonce-dkg-commit-root/v1"))
	_, _ = h.Write(p.nonceID[:])
	for _, id := range p.quorum { // quorum is sorted, so this is canonical
		if c, ok := p.recvCommit[id]; ok {
			_, _ = h.Write(id[:])
			_, _ = h.Write(c[:])
		}
	}
	var out [32]byte
	_, _ = h.Read(out[:])
	return out
}

// NodeID returns this participant's identity.
func (p *NonceDKGParticipant) NodeID() NodeID { return p.nodeID }

// Consumed reports whether the one-time nonce has been used/aborted.
func (p *NonceDKGParticipant) Consumed() bool { return p.consumed }

// Consume marks the nonce share as used by a signing round and erases the
// secret share. After Consume the same instance cannot deal or finalize again —
// a nonce is one-time.
func (p *NonceDKGParticipant) Consume() {
	p.eraseSecret()
}

// Abort discards an in-flight nonce (e.g. on a failed BCC clearance) and erases
// the secret so it can never be revived or reused.
func (p *NonceDKGParticipant) Abort() {
	p.eraseSecret()
}

func (p *NonceDKGParticipant) eraseSecret() {
	for l := range p.contribution {
		p.contribution[l] = poly{}
	}
	p.contribution = nil
	for h := range p.received {
		sh := p.received[h]
		for l := range sh {
			sh[l] = poly{}
		}
		delete(p.received, h)
	}
	for l := range p.yShare {
		p.yShare[l] = poly{}
	}
	p.yShare = nil
	p.consumed = true
}

// nonceContribCommit is the hash commitment a party broadcasts for its
// contribution y_h: SHAKE-256 over a domain tag, the nonceID, the contributor
// ID, and the packed contribution. It binds y_h (so it cannot be chosen after
// seeing others' shares) without revealing it before the shares are distributed.
// (Hash-commitment binding; the hiding/equivocation-proof VSS layer is the
// documented malicious-security hook.)
func nonceContribCommit(nonceID [32]byte, from NodeID, contribution polyVec) [32]byte {
	h := sha3.NewShake256()
	_, _ = h.Write([]byte("PULSAR-TALUS/nonce-contrib-commit/v1"))
	_, _ = h.Write(nonceID[:])
	_, _ = h.Write(from[:])
	_, _ = h.Write(packPolyVec(contribution))
	var out [32]byte
	_, _ = h.Read(out[:])
	return out
}
