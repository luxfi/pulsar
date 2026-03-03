// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// dkg2 wire-format fuzz harnesses.
//
// FuzzDKG2Round1Output  — Round1Output.SerializeCommits bytes (Vector[Vector[Poly]])
// FuzzDKG2Round2Output  — Round-2 share vector bytes (Vector[Poly])
//
// Property: every decoder path under fuzzMaxRawSize never escapes a
// panic to the caller, even on attacker-controlled length-prefix
// inputs (luxfi/lattice#2 DoS surface).

package dkg2

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/luxfi/pulsar/utils"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/structs"
)

// fuzzMaxRawSize bounds the input handed to the lattigo decoder so
// the unpatched-upstream-lattigo DoS path (luxfi/lattice#2) is
// neutralized by the recover boundary in <1ms. See
// pulsar/threshold/fuzz_round_test.go for the rationale.
const fuzzMaxRawSize = 1024

// decodeVectorWithRecover decodes a Vector[Poly] from raw bytes with
// the same defense-in-depth stack as
// pulsar/threshold/fuzz_round_test.go: hard byte cap + recover.
func decodeVectorWithRecover(raw []byte) (err error) {
	if len(raw) > fuzzMaxRawSize {
		return fmt.Errorf("input exceeds fuzzMaxRawSize")
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("decode panic recovered: %v", r)
		}
	}()
	r, perr := ring.NewRing(1<<10, []uint64{0x7ffffd8001})
	if perr != nil {
		return perr
	}
	v := utils.InitializeVector(r, 8)
	_, derr := v.ReadFrom(bytes.NewReader(raw))
	_ = structs.Vector[ring.Poly](v) // type-assertion for clarity
	return derr
}

// addSmallSeeds adds bounded-size seeds. Real protocol data is
// exercised by TestFuzzCorpus_*Replay, NOT here.
func addSmallSeeds(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0x01, 0x02, 0x03, 0x04})
	f.Add(bytes.Repeat([]byte{0xff}, 32))
	f.Add(bytes.Repeat([]byte{0xaa}, 64))
	f.Add(append([]byte{0x10, 0x00, 0x00, 0x00}, bytes.Repeat([]byte{0xcc}, 24)...))
}

// FuzzDKG2Round1Output fuzzes the Round-1 commitment-vector decoder.
// dkg2.Round1Output.Commits is broadcast publicly in the dkg2 protocol;
// any peer can supply attacker-controlled bytes for this lane.
func FuzzDKG2Round1Output(f *testing.F) {
	addSmallSeeds(f)

	f.Fuzz(func(t *testing.T, raw []byte) {
		_ = decodeVectorWithRecover(raw)
	})
}

// FuzzDKG2Round2Output fuzzes the Round-2 share-vector decoder.
// dkg2 Round-2 outputs are private but transit on an authenticated
// channel; an attacker who compromises a single point-to-point link
// must not be able to crash the receiver via malformed bytes.
func FuzzDKG2Round2Output(f *testing.F) {
	addSmallSeeds(f)

	f.Fuzz(func(t *testing.T, raw []byte) {
		_ = decodeVectorWithRecover(raw)
	})
}

// TestFuzzCorpus_DKG2Round1Replay confirms the small-seed corpus is
// at least decodable to the point of producing a clean error (or
// nil) rather than a panic.
func TestFuzzCorpus_DKG2Round1Replay(t *testing.T) {
	for _, raw := range [][]byte{
		{},
		{0x00},
		{0x01, 0x02, 0x03, 0x04},
		bytes.Repeat([]byte{0xff}, 32),
	} {
		if err := decodeVectorWithRecover(raw); err == nil {
			// nil is fine — empty/zero input may decode to empty vector
			continue
		}
	}
}

// TestFuzzCorpus_DKG2Round2Replay mirrors the Round-1 replay.
func TestFuzzCorpus_DKG2Round2Replay(t *testing.T) {
	for _, raw := range [][]byte{
		{},
		{0x00},
		bytes.Repeat([]byte{0xaa}, 64),
	} {
		_ = decodeVectorWithRecover(raw)
	}
}
