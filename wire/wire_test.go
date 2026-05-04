// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/luxfi/math/codec"
)

func encodeUvarint(out *bytes.Buffer, v uint64) {
	for v >= 0x80 {
		out.WriteByte(byte(v) | 0x80)
		v >>= 7
	}
	out.WriteByte(byte(v))
}

// TestValidateVectorPolyFrame_RejectsHugeLength is the regression
// test for lattice issue #4 (Vector[T].ReadFrom unbounded allocation),
// now centralized through luxfi/math/codec.Reader. The exact attack
// input from the original fuzz finding (9-byte varint encoding of a
// 70-trillion-element length) MUST be rejected with
// codec.ErrLimitExceeded.
func TestValidateVectorPolyFrame_RejectsHugeLength(t *testing.T) {
	// Length: 70_368_955_777_453 — same value used in lattice issue #4.
	const huge = uint64(70_368_955_777_453)

	var buf bytes.Buffer
	encodeUvarint(&buf, huge)

	err := ValidateVectorPolyFrame(buf.Bytes())
	if err == nil {
		t.Fatal("ValidateVectorPolyFrame returned nil for huge length")
	}
	if !errors.Is(err, codec.ErrLimitExceeded) {
		t.Errorf("err is not ErrLimitExceeded: %v", err)
	}
	t.Logf("rejected as expected: %v", err)
}

// TestValidateVectorPolyFrame_HappyPath confirms the bounded reader
// accepts a length within cap.
func TestValidateVectorPolyFrame_HappyPath(t *testing.T) {
	want := []uint64{1, 2, 3}
	var buf bytes.Buffer
	encodeUvarint(&buf, uint64(len(want)))
	for _, v := range want {
		_ = binary.Write(&buf, binary.LittleEndian, v)
	}
	if err := ValidateVectorPolyFrame(buf.Bytes()); err != nil {
		t.Errorf("happy-path: %v", err)
	}
}

// TestValidateVectorPolyFrame_AtCap accepts exactly MaxLatticeUintSliceLen.
func TestValidateVectorPolyFrame_AtCap(t *testing.T) {
	var buf bytes.Buffer
	encodeUvarint(&buf, uint64(MaxLatticeUintSliceLen))
	// Provide a payload large enough to satisfy the read; we don't
	// care about its content, only that it doesn't exceed
	// MaxFrameBytes.
	payload := make([]byte, MaxLatticeUintSliceLen*8)
	buf.Write(payload)
	if err := ValidateVectorPolyFrame(buf.Bytes()); err != nil {
		t.Errorf("at-cap: %v", err)
	}
}

// TestValidateVectorPolyFrame_OverCap rejects MaxLatticeUintSliceLen + 1.
func TestValidateVectorPolyFrame_OverCap(t *testing.T) {
	var buf bytes.Buffer
	encodeUvarint(&buf, uint64(MaxLatticeUintSliceLen+1))
	err := ValidateVectorPolyFrame(buf.Bytes())
	if err == nil {
		t.Fatal("over-cap returned nil")
	}
	if !errors.Is(err, codec.ErrLimitExceeded) {
		t.Errorf("err is not ErrLimitExceeded: %v", err)
	}
}
