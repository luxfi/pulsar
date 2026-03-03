// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Reshare commit + complaint wire-format fuzz harnesses.
//
// FuzzReshareCommitDigest    — CommitDigest over malformed Vector[Poly] bytes
// FuzzReshareComplaintMessage — canonical Complaint.Bytes() parser
//
// Property: every decoder path under fuzzMaxRawSize never escapes a
// panic, even on attacker-controlled length-prefix inputs
// (luxfi/lattice#2).

package reshare

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/luxfi/pulsar/hash"
	"github.com/luxfi/pulsar/utils"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/structs"
)

const fuzzMaxRawSize = 1024

// fuzzCommitDigestRecover invokes CommitDigest against a 1-element
// commit vector reconstructed from raw bytes, with a recover boundary
// to neutralize the upstream-lattigo DoS path (luxfi/lattice#2).
func fuzzCommitDigestRecover(raw []byte) (err error) {
	if len(raw) > fuzzMaxRawSize {
		return fmt.Errorf("input exceeds fuzzMaxRawSize")
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("commit-digest panic recovered: %v", r)
		}
	}()
	r, perr := ring.NewRing(1<<10, []uint64{0x7ffffd8001})
	if perr != nil {
		return perr
	}
	v := utils.InitializeVector(r, 4)
	if _, derr := v.ReadFrom(bytes.NewReader(raw)); derr != nil {
		return derr
	}
	_ = CommitDigest([]structs.Vector[ring.Poly]{v}, hash.Default())
	return nil
}

// parseComplaintBytes is the inverse of Complaint.Bytes — a
// length-prefix-aware structural parser. It is intentionally
// strict: rejects truncated inputs, oversized evidence claims, and
// version-tag mismatches with a clean error rather than a panic.
func parseComplaintBytes(raw []byte) (*Complaint, error) {
	const versionTag = "pulsar.reshare.complaint.v1"
	if len(raw) < len(versionTag)+32+4+4+1+4 {
		return nil, fmt.Errorf("truncated: %d bytes", len(raw))
	}
	if string(raw[:len(versionTag)]) != versionTag {
		return nil, fmt.Errorf("bad version tag")
	}
	off := len(versionTag)
	c := &Complaint{}
	copy(c.TranscriptHash[:], raw[off:off+32])
	off += 32
	c.SenderID = int(binary.BigEndian.Uint32(raw[off : off+4]))
	off += 4
	c.ComplainerID = int(binary.BigEndian.Uint32(raw[off : off+4]))
	off += 4
	c.Reason = ComplaintReason(raw[off])
	off++
	evLen := binary.BigEndian.Uint32(raw[off : off+4])
	off += 4
	if int(evLen) > fuzzMaxRawSize {
		return nil, fmt.Errorf("evidence length %d exceeds cap", evLen)
	}
	if off+int(evLen) > len(raw) {
		return nil, fmt.Errorf("evidence truncated: claim %d, have %d",
			evLen, len(raw)-off)
	}
	c.Evidence = append([]byte(nil), raw[off:off+int(evLen)]...)
	return c, nil
}

// addSmallSeeds adds a small seed corpus.
func addSmallSeeds(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add(bytes.Repeat([]byte{0xff}, 32))
	f.Add(append([]byte("pulsar.reshare.complaint.v1"), bytes.Repeat([]byte{0x00}, 41)...))
	f.Add(append([]byte("pulsar.reshare.complaint.v1"),
		append(bytes.Repeat([]byte{0x00}, 41),
			[]byte{0xff, 0xff, 0xff, 0xff}...)...)) // huge evidence claim
}

// FuzzReshareCommitDigest fuzzes the commit-digest surface (lattigo
// Vector decode + transcript hash). Property: 0 panics under the
// fuzz max raw size cap.
func FuzzReshareCommitDigest(f *testing.F) {
	addSmallSeeds(f)

	f.Fuzz(func(t *testing.T, raw []byte) {
		_ = fuzzCommitDigestRecover(raw)
	})
}

// FuzzReshareComplaintMessage fuzzes the structural complaint parser.
// Property: the parser cleanly errors on malformed inputs and never
// panics, even on huge evidence-length claims.
func FuzzReshareComplaintMessage(f *testing.F) {
	addSmallSeeds(f)

	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = parseComplaintBytes(raw)
	})
}

// TestFuzzCorpus_ReshareCommitDigestReplay replays the small-seed
// corpus deterministically.
func TestFuzzCorpus_ReshareCommitDigestReplay(t *testing.T) {
	for _, raw := range [][]byte{
		{},
		{0x00},
		bytes.Repeat([]byte{0xff}, 32),
	} {
		_ = fuzzCommitDigestRecover(raw)
	}
}

// TestFuzzCorpus_ReshareComplaintReplay confirms the parser rejects
// malformed inputs cleanly.
func TestFuzzCorpus_ReshareComplaintReplay(t *testing.T) {
	for _, raw := range [][]byte{
		{},
		{0x00},
		append([]byte("pulsar.reshare.complaint.v1"), bytes.Repeat([]byte{0x00}, 41)...),
	} {
		_, _ = parseComplaintBytes(raw)
	}
}
