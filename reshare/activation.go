// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package reshare

// Activation certificate (post-reshare circuit-breaker).
//
// Resharing is meaningless without a hard go/no-go switch at the chain
// level: if the new committee cannot collectively sign under the
// UNCHANGED group public key, then the shares it holds do not actually
// reconstruct the master secret, and rotating to those shares would
// brick the chain. The activation certificate is the proof that the
// new committee CAN sign — and therefore the chain accepts the new
// epoch.
//
// Activation message canonical bytes (signed by the new committee
// under the UNCHANGED GroupKey):
//
//	"QUASAR-PULSAR-ACTIVATE-v1" ||
//	    transcript_hash         (32 bytes; from TranscriptInputs.Hash)
//	    reshare_transcript_hash (32 bytes; from ReshareTranscript.Hash)

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/luxfi/pulsar/hash"
)

// ActivationMessage is the canonical bytes-to-be-signed for the
// post-reshare circuit-breaker.
type ActivationMessage struct {
	Transcript        TranscriptInputs
	ReshareTranscript ReshareTranscript
}

// ReshareTranscript is the structured digest of the resharing exchange.
type ReshareTranscript struct {
	CommitDigests       map[int][32]byte
	ComplaintHashes     [][32]byte
	DisqualifiedSenders []int
	QualifiedQuorum     []int
}

// Hash returns the canonical 32-byte digest of the ReshareTranscript
// under the supplied HashSuite. nil resolves to the production default.
func (rt *ReshareTranscript) Hash(suite hash.HashSuite) [32]byte {
	s := hash.Resolve(suite)
	parts := buildExchangeTranscriptParts(rt)
	return s.TranscriptHash(parts...)
}

func buildExchangeTranscriptParts(rt *ReshareTranscript) [][]byte {
	enc32 := func(v uint32) []byte {
		var b [4]byte
		b[0] = byte(v >> 24)
		b[1] = byte(v >> 16)
		b[2] = byte(v >> 8)
		b[3] = byte(v)
		return b[:]
	}
	parts := [][]byte{
		[]byte("pulsar.reshare.exchange-transcript.v1"),
	}

	commitParties := make([]int, 0, len(rt.CommitDigests))
	for id := range rt.CommitDigests {
		commitParties = append(commitParties, id)
	}
	insertionSortInts(commitParties)
	parts = append(parts, []byte("commit_count"), enc32(uint32(len(commitParties))))
	for _, id := range commitParties {
		parts = append(parts, []byte("commit_party"), enc32(uint32(id)))
		d := rt.CommitDigests[id]
		parts = append(parts, []byte("commit_digest"), append([]byte(nil), d[:]...))
	}

	parts = append(parts, []byte("complaint_count"), enc32(uint32(len(rt.ComplaintHashes))))
	for _, ch := range rt.ComplaintHashes {
		parts = append(parts, []byte("complaint_hash"), append([]byte(nil), ch[:]...))
	}

	dq := append([]int(nil), rt.DisqualifiedSenders...)
	insertionSortInts(dq)
	parts = append(parts, []byte("disqualified_count"), enc32(uint32(len(dq))))
	for _, id := range dq {
		parts = append(parts, []byte("disqualified_id"), enc32(uint32(id)))
	}

	q := append([]int(nil), rt.QualifiedQuorum...)
	insertionSortInts(q)
	parts = append(parts, []byte("qualified_count"), enc32(uint32(len(q))))
	for _, id := range q {
		parts = append(parts, []byte("qualified_id"), enc32(uint32(id)))
	}
	return parts
}

// SignableBytes returns the canonical bytes the new committee
// threshold-signs to produce an activation cert.
func (a *ActivationMessage) SignableBytes(suite hash.HashSuite) []byte {
	var buf bytes.Buffer
	buf.WriteString("QUASAR-PULSAR-ACTIVATE-v1")
	t := a.Transcript.Hash(suite)
	buf.Write(t[:])
	rth := a.ReshareTranscript.Hash(suite)
	buf.Write(rth[:])
	return buf.Bytes()
}

// ActivationCert wraps the threshold signature emitted by the new
// committee over an ActivationMessage.
type ActivationCert struct {
	Message   ActivationMessage
	Signature []byte
}

// Errors returned by the activation circuit-breaker.
var (
	ErrActivationFailed   = errors.New("reshare: activation cert failed to verify under group public key")
	ErrTranscriptMismatch = errors.New("reshare: activation transcript hash does not match local view")
)

// VerifyActivation runs the chain-level activation check.
// suite=nil resolves to the production default (Pulsar-SHA3).
func VerifyActivation(
	cert *ActivationCert,
	localTranscriptHash [32]byte,
	localExchangeHash [32]byte,
	suite hash.HashSuite,
	verify func(message []byte, signature []byte) bool,
) error {
	if cert == nil {
		return errors.New("reshare: nil activation cert")
	}
	expectedTranscript := cert.Message.Transcript.Hash(suite)
	if expectedTranscript != localTranscriptHash {
		return fmt.Errorf("%w: cert says %x, chain says %x",
			ErrTranscriptMismatch, expectedTranscript, localTranscriptHash)
	}
	expectedExchange := cert.Message.ReshareTranscript.Hash(suite)
	if expectedExchange != localExchangeHash {
		return fmt.Errorf("%w: exchange hash mismatch", ErrTranscriptMismatch)
	}
	if !verify(cert.Message.SignableBytes(suite), cert.Signature) {
		return ErrActivationFailed
	}
	return nil
}

// insertionSortInts is a hand-rolled O(n^2) sort suitable for the
// small slices this package operates on (committee size ≤ 32 in any
// realistic deployment).
func insertionSortInts(s []int) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
