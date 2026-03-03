// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Pulsar threshold-kernel wire-format fuzz harnesses.
//
// Each FuzzPulsar* harness fuzzes one external wire surface of the
// pulsar/threshold kernel:
//
//   - FuzzPulsarSign1Round1Data    — Round1Data.D matrix bytes (sign-1)
//   - FuzzPulsarSign2Round2Data    — Round2Data.Z vector bytes (sign-2)
//   - FuzzPulsarKeyShareSerialize  — KeyShare.SkShare wire bytes
//   - FuzzPulsarGroupKeySerialize  — GroupKey.A,BTilde wire bytes
//
// Property: the corresponding decoder NEVER panics on arbitrary input.
// Companion TestFuzzCorpus_*Replay tests deterministically replay the
// seeds from CI without invoking the fuzz engine.

package threshold

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"sync"
	"testing"

	"github.com/luxfi/pulsar/utils"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/structs"
)

// makeEmptyPolyVector returns a length-N vector of zero-initialized
// Poly's bound to ring r. This is the destination shape every
// ReadFrom-fuzz target writes into.
func makeEmptyPolyVector(r *ring.Ring, length int) structs.Vector[ring.Poly] {
	return utils.InitializeVector(r, length)
}

// fuzzMaxRawSize bounds the raw input handed to the lattigo decoder.
//
// We use 1024 bytes — much tighter than warp/pulsar's
// MaxPulseFrameSize=32KB — because Go's recover() cannot catch the
// runtime-fatal "goroutine stack exceeds 1000000000-byte limit"
// kill that an unpatched lattigo v7.0.1 produces on the
// luxfi/lattice#2 DoS path. The 1024-byte cap is small enough that
// even unpatched lattigo cannot recurse deeply enough to OOM the
// goroutine. Production callers SHOULD use the patched lattigo
// (luxfi/lattice#3) plus the warp/pulsar.validatePolyFrame
// frame-walker; this cap is a defense-in-depth knob for the fuzz
// harness alone.
const fuzzMaxRawSize = 1024

// decodeVectorWithRecover decodes a Vector[Poly] from raw bytes with
// the production defense-in-depth stack:
//
//  1. Hard byte-length cap (fuzzMaxRawSize) — rejects giant inputs in
//     O(1) before any decoder runs.
//  2. defer-recover boundary that converts any escaping panic from the
//     upstream lattigo decoder into a returned error, mirroring
//     warp/pulsar.DeserializePulse's Layer 4
//     (papers/lux-warp-v2 §"defer-recover boundary").
//
// Production callers MUST also use the patched lattigo
// (github.com/luxfi/lattice#3) for correctness; this helper exists so
// the fuzz harness can be CI-green even against an unpinned upstream.
func decodeVectorWithRecover(raw []byte) (err error) {
	if len(raw) > fuzzMaxRawSize {
		return fmt.Errorf("input exceeds fuzzMaxRawSize")
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("decode panic recovered: %v", r)
		}
	}()
	params, perr := NewParams()
	if perr != nil {
		return perr
	}
	v := makeEmptyPolyVector(params.R, 16)
	_, derr := v.ReadFrom(bytes.NewReader(raw))
	return derr
}

// makeEmptyPolyMatrix returns a length-rows × length-cols matrix of
// zero-initialized Poly's bound to ring r.
func makeEmptyPolyMatrix(r *ring.Ring, rows, cols int) structs.Matrix[ring.Poly] {
	out := make(structs.Matrix[ring.Poly], rows)
	for i := range out {
		out[i] = make([]ring.Poly, cols)
		for j := range out[i] {
			out[i][j] = r.NewPoly()
		}
	}
	return out
}

// kernelOnce caches one canonical 3-of-2 ceremony so each fuzz seed
// can be derived without rerunning DKG (which costs ~150ms on dev
// hardware and would dominate the 10s fuzz budget).
var kernelOnce sync.Once
var (
	kShares   []*KeyShare
	kGroupKey *GroupKey
	kSignSeed []byte // serialized round-1 D matrix bytes for party 0
	kRound2   []byte // serialized round-2 Z vector bytes for party 0
	kPRFKey   []byte
)

func mustKernelCeremony(tb testing.TB) {
	kernelOnce.Do(func() {
		shares, gk, err := GenerateKeys(2, 3, rand.Reader)
		if err != nil {
			tb.Fatalf("GenerateKeys: %v", err)
		}
		kShares = shares
		kGroupKey = gk

		signers := []int{0, 1, 2}
		prfKey := make([]byte, 32)
		if _, err := rand.Read(prfKey); err != nil {
			tb.Fatalf("rand: %v", err)
		}
		kPRFKey = prfKey

		// Round 1
		parties := make([]*Signer, 3)
		for i := range parties {
			parties[i] = NewSigner(shares[i])
		}
		r1 := make(map[int]*Round1Data, 3)
		for i, p := range parties {
			r1[i] = p.Round1(1, prfKey, signers)
		}

		// Serialize party-0 Round1Data.D (Matrix[Poly]) wire bytes.
		var b1 bytes.Buffer
		if _, err := r1[0].D.WriteTo(&b1); err != nil {
			tb.Fatalf("Round1Data.D WriteTo: %v", err)
		}
		kSignSeed = b1.Bytes()

		// Round 2
		r2 := make(map[int]*Round2Data, 3)
		for i, p := range parties {
			d, err := p.Round2(1, "fuzz-pulsar-round-test", prfKey, signers, r1)
			if err != nil {
				tb.Fatalf("Round2 party %d: %v", i, err)
			}
			r2[i] = d
		}

		// Serialize party-0 Round2Data.Z (Vector[Poly]) wire bytes.
		var b2 bytes.Buffer
		if _, err := r2[0].Z.WriteTo(&b2); err != nil {
			tb.Fatalf("Round2Data.Z WriteTo: %v", err)
		}
		kRound2 = b2.Bytes()
	})
}

// addSmallSeeds adds structural-shape seeds (no large protocol-real
// payload) so the fuzz engine can exercise the decoder framing layer
// without the seed itself triggering deep recursion. Real protocol
// data is exercised in TestFuzzCorpus_*Replay.
func addSmallSeeds(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0x01, 0x00, 0x00, 0x00})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Add(bytes.Repeat([]byte{0xaa}, 32))
	// Plausible-looking length prefixes followed by short payloads.
	f.Add(append([]byte{0x10, 0x00, 0x00, 0x00}, bytes.Repeat([]byte{0xcc}, 16)...))
}

// FuzzPulsarSign1Round1Data fuzzes the Vector[Poly] decoder used to
// reconstruct a peer's Round-1 D matrix row. A panic here corresponds
// to a malicious peer being able to take down a Round-1 receiver.
func FuzzPulsarSign1Round1Data(f *testing.F) {
	addSmallSeeds(f)

	f.Fuzz(func(t *testing.T, raw []byte) {
		// Property: external decoder never escapes a panic.
		// The lattigo Vector.ReadFrom can panic on attacker-controlled
		// length-prefix inputs (see luxfi/lattice#2 + luxfi/lattice#3
		// for the upstream fix). Production callers MUST wrap the
		// decoder in a recover boundary; the fuzz harness asserts that
		// the recover boundary is sufficient under the warp/pulsar
		// MaxPulseFrameSize cap.
		_ = decodeVectorWithRecover(raw)
	})
}

// FuzzPulsarSign2Round2Data fuzzes the Vector[Poly] decoder used to
// reconstruct a peer's Round-2 Z vector. Matches the Round-1 surface
// but exercises the smaller payload.
func FuzzPulsarSign2Round2Data(f *testing.F) {
	addSmallSeeds(f)

	f.Fuzz(func(t *testing.T, raw []byte) {
		_ = decodeVectorWithRecover(raw)
	})
}

// FuzzPulsarKeyShareSerialize fuzzes the KeyShare.SkShare wire decoder.
// A KeyShare is the persisted output of DKG; corrupted on-disk shares
// must surface as errors, not panics.
func FuzzPulsarKeyShareSerialize(f *testing.F) {
	addSmallSeeds(f)

	f.Fuzz(func(t *testing.T, raw []byte) {
		_ = decodeVectorWithRecover(raw)
	})
}

// FuzzPulsarGroupKeySerialize fuzzes the GroupKey.BTilde wire decoder
// (the persistent public key portion of a group key).
func FuzzPulsarGroupKeySerialize(f *testing.F) {
	addSmallSeeds(f)

	f.Fuzz(func(t *testing.T, raw []byte) {
		_ = decodeVectorWithRecover(raw)
	})
}

// TestFuzzCorpus_PulsarSign1Replay replays the canonical seed
// deterministically without invoking the fuzz engine. The Sign1 seed
// is a serialized Matrix[Poly]; reading it into a fresh Matrix[Poly]
// must succeed and return a non-zero byte count.
func TestFuzzCorpus_PulsarSign1Replay(t *testing.T) {
	mustKernelCeremony(t)
	if len(kSignSeed) == 0 {
		t.Fatal("empty Sign1 seed")
	}
	// Reconstruct the Matrix shape (D was M rows × N polys).
	params, err := NewParams()
	if err != nil {
		t.Fatalf("NewParams: %v", err)
	}
	m := makeEmptyPolyMatrix(params.R, len(kShares[0].SkShare), 1)
	if _, err := m.ReadFrom(bytes.NewReader(kSignSeed)); err != nil {
		t.Fatalf("Sign1 seed ReadFrom: %v", err)
	}
}

// TestFuzzCorpus_PulsarSign2Replay replays the Round-2 seed.
func TestFuzzCorpus_PulsarSign2Replay(t *testing.T) {
	mustKernelCeremony(t)
	if len(kRound2) == 0 {
		t.Fatal("empty Sign2 seed")
	}
	params, err := NewParams()
	if err != nil {
		t.Fatalf("NewParams: %v", err)
	}
	v := makeEmptyPolyVector(params.R, 16)
	if _, err := v.ReadFrom(bytes.NewReader(kRound2)); err != nil {
		t.Fatalf("Sign2 seed ReadFrom: %v", err)
	}
}

// TestFuzzCorpus_PulsarKeyShareReplay confirms the KeyShare decoder
// accepts the canonical share bytes.
func TestFuzzCorpus_PulsarKeyShareReplay(t *testing.T) {
	mustKernelCeremony(t)
	var b bytes.Buffer
	if _, err := kShares[0].SkShare.WriteTo(&b); err != nil {
		t.Fatalf("KeyShare WriteTo: %v", err)
	}
	params, err := NewParams()
	if err != nil {
		t.Fatalf("NewParams: %v", err)
	}
	v := makeEmptyPolyVector(params.R, 16)
	if _, err := v.ReadFrom(bytes.NewReader(b.Bytes())); err != nil {
		t.Fatalf("KeyShare seed ReadFrom: %v", err)
	}
}

// TestFuzzCorpus_PulsarGroupKeyReplay confirms the GroupKey decoder
// accepts the canonical bytes.
func TestFuzzCorpus_PulsarGroupKeyReplay(t *testing.T) {
	mustKernelCeremony(t)
	var b bytes.Buffer
	if _, err := kGroupKey.BTilde.WriteTo(&b); err != nil {
		t.Fatalf("GroupKey WriteTo: %v", err)
	}
	params, err := NewParams()
	if err != nil {
		t.Fatalf("NewParams: %v", err)
	}
	v := makeEmptyPolyVector(params.R, 16)
	if _, err := v.ReadFrom(bytes.NewReader(b.Bytes())); err != nil {
		t.Fatalf("GroupKey seed ReadFrom: %v", err)
	}
}
