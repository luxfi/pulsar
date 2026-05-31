// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// wire.go — canonical wire codec for Signature and PublicKey (the
// group public key on the wire) plus a stateless VerifyBytes helper
// that any independent peer can call given only:
//
//   - the wire bytes of the group public key (PULG-framed),
//   - the bytes of the message that was signed,
//   - the wire bytes of the signature (PULS-framed),
//
// and obtain a bool answer with no additional state. This is the
// surface luxfi/threshold/pkg/thresholdd consumes to publish Pulsar
// outputs over a JSON-RPC bus — and the surface independent
// verifiers (other mpcd, bridge nodes, L1 verifier contracts) must
// satisfy.
//
// The Class N1 manifesto of Pulsar (see verify.go, spec/nist-mptc-
// category.tex) is that a Pulsar Signature is bit-identical to a
// single-party FIPS 204 ML-DSA signature on the same (message,
// group public key) tuple. The wire codec preserves this property
// by transporting the FIPS 204 bytes verbatim inside a small
// domain-separated frame. A relying party that strips the PULS /
// PULG frame obtains the FIPS 204 wire bytes that
// cloudflare/circl's mldsa{44,65,87}.Verify accepts unmodified —
// this is what TestPulsar_Wire_FIPS204Verifiable asserts.
//
// Wire frame layout (big-endian throughout):
//
//	Signature:
//	  magic(4) = 'P' 'U' 'L' 'S' = 0x50554C53
//	  version(2) = 0x0001
//	  mode(1)    = 0x2C | 0x41 | 0x57   (44 | 65 | 87, the FIPS 204 level)
//	  len(4)     = FIPS 204 SignatureSize for mode (2420 | 3309 | 4627)
//	  payload    = len bytes — the FIPS 204 sigEncode(c̃, z, h) output
//
//	GroupKey:
//	  magic(4) = 'P' 'U' 'L' 'G' = 0x50554C47
//	  version(2) = 0x0001
//	  mode(1)    = 0x2C | 0x41 | 0x57
//	  len(4)     = FIPS 204 PublicKeySize for mode (1312 | 1952 | 2592)
//	  payload    = len bytes — the FIPS 204 (ρ || t_1) encoding
//
// Domain separation: the four-byte magic is distinct from corona's
// CORS / CORG (0x434F5253 / 0x434F5247), so a corona-shaped frame
// fed into pulsar's parser is rejected at the first dispatch and
// vice versa. Distinct magic per type within pulsar means a
// GroupKey frame fed into the signature slot is rejected before
// any length-decode is attempted.
//
// Bounded reads: every length-prefix read is checked against the
// remaining bytes in the reader BEFORE any allocation. Beyond that,
// the wire codec also pins the declared FIPS 204 length to the
// canonical value for the Mode — a malformed frame that claims a
// 4 GiB signature for ModeP65 is rejected without allocating any
// buffer. Any wire-format change (additional field, version flip)
// bumps versionV1.
//
// Trailing garbage policy: STRICT — UnmarshalBinary returns an
// error if any byte remains after the declared frame. Mirrors
// corona/wire.go.
//
// Version-bump rule: any byte-level change to the layout (new
// field, reordered fields, bigger length prefix, additional FIPS
// 204 mode) requires bumping versionV1. The Mode byte is
// independent — adding ModeP44/65/87 alternates does NOT bump the
// version because Mode is a structural payload selector, not a
// format change.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// Wire-format identifiers. Distinct from corona's CORS / CORG so
// the parsers cannot cross-accept and a passive observer can tell
// from the first four bytes which protocol the payload belongs to.
const (
	wireMagicPulsarSig      uint32 = 0x50554C53 // "PULS" Pulsar Signature
	wireMagicPulsarGroupKey uint32 = 0x50554C47 // "PULG" Pulsar GroupKey
	wireVersionV1           uint16 = 1
)

// Errors returned by the wire codec. Typed for errors.Is matching
// in callers (the dispatcher, downstream relying parties, fuzzers).
var (
	ErrWireMagicMismatch   = errors.New("pulsar/wire: magic mismatch")
	ErrWireVersionMismatch = errors.New("pulsar/wire: version mismatch")
	ErrWireFrameTooShort   = errors.New("pulsar/wire: frame too short")
	ErrWireFrameRejected   = errors.New("pulsar/wire: frame rejected by bounded reader")
	ErrWireModeUnknown     = errors.New("pulsar/wire: unknown mode byte")
	ErrWireLengthMismatch  = errors.New("pulsar/wire: declared length does not match FIPS 204 size for mode")
	ErrWireTrailingBytes   = errors.New("pulsar/wire: trailing bytes after frame")
)

// wireFixedSigHeader is magic(4) + version(2) + mode(1) + len(4).
const wireFixedSigHeader = 4 + 2 + 1 + 4

// wireFixedGroupKeyHeader has the same shape as wireFixedSigHeader.
const wireFixedGroupKeyHeader = wireFixedSigHeader

// MarshalBinary serialises a Signature into the canonical PULS frame.
//
// The body bytes are the FIPS 204 sigEncode(c̃, z, h) output
// verbatim — Pulsar adds NO envelope around them. Stripping the
// 11-byte header recovers the unmodified FIPS 204 bytes that
// cloudflare/circl's mldsa{44,65,87}.Verify accepts. This is the
// load-bearing property TestPulsar_Wire_FIPS204Verifiable pins.
//
// Returns an error if the Signature's Mode is unknown, its Bytes
// field does not match the FIPS 204 size for the Mode, or the
// Signature receiver is nil.
func (s *Signature) MarshalBinary() ([]byte, error) {
	if s == nil {
		return nil, errors.New("pulsar: nil Signature")
	}
	sigSize, err := sigSizeForMode(s.Mode)
	if err != nil {
		return nil, fmt.Errorf("pulsar/wire: %w", err)
	}
	if len(s.Bytes) != sigSize {
		return nil, fmt.Errorf("pulsar/wire: Signature.Bytes length %d != FIPS 204 size %d for %s",
			len(s.Bytes), sigSize, s.Mode)
	}

	out := make([]byte, 0, wireFixedSigHeader+sigSize)
	out = binary.BigEndian.AppendUint32(out, wireMagicPulsarSig)
	out = binary.BigEndian.AppendUint16(out, wireVersionV1)
	out = append(out, byte(s.Mode))
	out = binary.BigEndian.AppendUint32(out, uint32(sigSize))
	out = append(out, s.Bytes...)
	return out, nil
}

// UnmarshalBinary parses a Signature from canonical PULS frame.
//
// Validation order is strict: magic, version, mode, length-against-
// FIPS 204-size are all checked BEFORE any payload bytes are read.
// The codec never allocates a payload buffer larger than the canonical
// FIPS 204 signature size for the declared mode, so a malformed length
// header cannot trigger an oversized allocation.
//
// Trailing bytes after the frame are rejected (ErrWireTrailingBytes)
// to keep the format strictly canonical — there is exactly one
// well-formed encoding of any (mode, bytes) pair.
func (s *Signature) UnmarshalBinary(b []byte) error {
	if s == nil {
		return errors.New("pulsar: nil Signature receiver")
	}
	if len(b) < wireFixedSigHeader {
		return ErrWireFrameTooShort
	}
	r := bytes.NewReader(b)

	var magic uint32
	if err := binary.Read(r, binary.BigEndian, &magic); err != nil {
		return fmt.Errorf("pulsar/wire: read magic: %w", err)
	}
	if magic != wireMagicPulsarSig {
		return fmt.Errorf("%w: got 0x%08x, want 0x%08x", ErrWireMagicMismatch, magic, wireMagicPulsarSig)
	}

	var version uint16
	if err := binary.Read(r, binary.BigEndian, &version); err != nil {
		return fmt.Errorf("pulsar/wire: read version: %w", err)
	}
	if version != wireVersionV1 {
		return fmt.Errorf("%w: got %d, want %d", ErrWireVersionMismatch, version, wireVersionV1)
	}

	modeByte, err := r.ReadByte()
	if err != nil {
		return fmt.Errorf("pulsar/wire: read mode: %w", err)
	}
	mode := Mode(modeByte)
	sigSize, err := sigSizeForMode(mode)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrWireModeUnknown, err)
	}

	var declared uint32
	if err := binary.Read(r, binary.BigEndian, &declared); err != nil {
		return fmt.Errorf("pulsar/wire: read length: %w", err)
	}
	// Bounded read: declared length must equal the canonical FIPS 204
	// size for the mode AND must not exceed the remaining buffer.
	// Both checks happen BEFORE the payload allocation.
	if int(declared) != sigSize {
		return fmt.Errorf("%w: declared %d, FIPS 204 size for %s is %d",
			ErrWireLengthMismatch, declared, mode, sigSize)
	}
	if int(declared) > r.Len() {
		return fmt.Errorf("%w: declared length %d exceeds remaining %d",
			ErrWireFrameRejected, declared, r.Len())
	}

	payload := make([]byte, declared)
	if _, err := r.Read(payload); err != nil {
		return fmt.Errorf("pulsar/wire: read payload: %w", err)
	}
	if r.Len() != 0 {
		return fmt.Errorf("%w: %d bytes remaining", ErrWireTrailingBytes, r.Len())
	}

	s.Mode = mode
	s.Bytes = payload
	return nil
}

// MarshalBinary serialises a PublicKey (used on the wire as the
// group public key) into the canonical PULG frame.
//
// The body bytes are the FIPS 204 (ρ || t_1) public-key encoding
// verbatim — Pulsar adds NO envelope around them. Stripping the
// 11-byte header recovers the unmodified FIPS 204 public-key bytes
// that cloudflare/circl's mldsa{44,65,87}.PublicKey.Unpack accepts.
//
// Returns an error if the PublicKey's Mode is unknown, its Bytes
// field does not match the FIPS 204 size for the Mode, or the
// PublicKey receiver is nil.
func (p *PublicKey) MarshalBinary() ([]byte, error) {
	if p == nil {
		return nil, errors.New("pulsar: nil PublicKey")
	}
	pkSize, err := pubKeySizeForMode(p.Mode)
	if err != nil {
		return nil, fmt.Errorf("pulsar/wire: %w", err)
	}
	if len(p.Bytes) != pkSize {
		return nil, fmt.Errorf("pulsar/wire: PublicKey.Bytes length %d != FIPS 204 size %d for %s",
			len(p.Bytes), pkSize, p.Mode)
	}

	out := make([]byte, 0, wireFixedGroupKeyHeader+pkSize)
	out = binary.BigEndian.AppendUint32(out, wireMagicPulsarGroupKey)
	out = binary.BigEndian.AppendUint16(out, wireVersionV1)
	out = append(out, byte(p.Mode))
	out = binary.BigEndian.AppendUint32(out, uint32(pkSize))
	out = append(out, p.Bytes...)
	return out, nil
}

// UnmarshalBinary parses a PublicKey from canonical PULG frame.
//
// Validation order matches Signature.UnmarshalBinary: magic,
// version, mode, length-against-FIPS 204-size are all checked
// BEFORE any payload bytes are read. Trailing bytes after the
// frame are rejected.
func (p *PublicKey) UnmarshalBinary(b []byte) error {
	if p == nil {
		return errors.New("pulsar: nil PublicKey receiver")
	}
	if len(b) < wireFixedGroupKeyHeader {
		return ErrWireFrameTooShort
	}
	r := bytes.NewReader(b)

	var magic uint32
	if err := binary.Read(r, binary.BigEndian, &magic); err != nil {
		return fmt.Errorf("pulsar/wire: read magic: %w", err)
	}
	if magic != wireMagicPulsarGroupKey {
		return fmt.Errorf("%w: got 0x%08x, want 0x%08x", ErrWireMagicMismatch, magic, wireMagicPulsarGroupKey)
	}

	var version uint16
	if err := binary.Read(r, binary.BigEndian, &version); err != nil {
		return fmt.Errorf("pulsar/wire: read version: %w", err)
	}
	if version != wireVersionV1 {
		return fmt.Errorf("%w: got %d, want %d", ErrWireVersionMismatch, version, wireVersionV1)
	}

	modeByte, err := r.ReadByte()
	if err != nil {
		return fmt.Errorf("pulsar/wire: read mode: %w", err)
	}
	mode := Mode(modeByte)
	pkSize, err := pubKeySizeForMode(mode)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrWireModeUnknown, err)
	}

	var declared uint32
	if err := binary.Read(r, binary.BigEndian, &declared); err != nil {
		return fmt.Errorf("pulsar/wire: read length: %w", err)
	}
	if int(declared) != pkSize {
		return fmt.Errorf("%w: declared %d, FIPS 204 size for %s is %d",
			ErrWireLengthMismatch, declared, mode, pkSize)
	}
	if int(declared) > r.Len() {
		return fmt.Errorf("%w: declared length %d exceeds remaining %d",
			ErrWireFrameRejected, declared, r.Len())
	}

	payload := make([]byte, declared)
	if _, err := r.Read(payload); err != nil {
		return fmt.Errorf("pulsar/wire: read payload: %w", err)
	}
	if r.Len() != 0 {
		return fmt.Errorf("%w: %d bytes remaining", ErrWireTrailingBytes, r.Len())
	}

	p.Mode = mode
	p.Bytes = payload
	return nil
}

// VerifyBytes is the stateless verifier the threshold orchestration
// layer (luxfi/threshold/pkg/thresholdd) needs to publish a
// signature over a JSON-RPC bus: it accepts the canonical wire
// bytes of a GroupKey (the group public key, in a PULG frame) and
// a Signature (in a PULS frame) plus the message that was signed,
// and returns true iff the signature verifies under the group key.
//
// Rejection of any malformed input returns false (NOT an error) —
// the dispatcher distinguishes "no valid signature" from
// "infrastructure error" via its JSON-RPC envelope; bytes-in,
// bool-out keeps this helper pure. The signature MUST verify under
// the FIPS 204 verifier verbatim (no Pulsar envelope) — this
// matches the Class N1 manifesto.
//
// Mode mismatch between the parsed Signature and parsed GroupKey
// is treated as verification failure (returns false). This keeps
// the helper allocation-free of any cross-mode dispatch surprises.
//
// Empty context: VerifyBytes calls FIPS 204 Verify with an empty
// context string. Callers needing the FIPS 204 §6.3 context binding
// must transport the context bytes by including them in the
// message argument (canonical convention: ctx || 0x00 || msg). The
// wire codec stays narrow so the dispatcher remains a thin proxy.
func VerifyBytes(gpkBytes, message, sigBytes []byte) bool {
	var gk PublicKey
	if err := gk.UnmarshalBinary(gpkBytes); err != nil {
		return false
	}
	var sig Signature
	if err := sig.UnmarshalBinary(sigBytes); err != nil {
		return false
	}
	if gk.Mode != sig.Mode {
		return false
	}
	return mldsaVerifyMode(gk.Mode, gk.Bytes, message, nil, sig.Bytes)
}

// mldsaVerifyMode is the constant-time FIPS 204 Verify dispatch.
// Kept distinct from sign.go's mldsaVerify so this file is
// self-contained for the wire layer; both paths call into the
// same circl primitives.
func mldsaVerifyMode(mode Mode, packedPk, message, ctx, sig []byte) bool {
	switch mode {
	case ModeP44:
		if len(packedPk) != mldsa44.PublicKeySize || len(sig) != mldsa44.SignatureSize {
			return false
		}
		var pk mldsa44.PublicKey
		var pkBuf [mldsa44.PublicKeySize]byte
		copy(pkBuf[:], packedPk)
		pk.Unpack(&pkBuf)
		return mldsa44.Verify(&pk, message, ctx, sig)
	case ModeP65:
		if len(packedPk) != mldsa65.PublicKeySize || len(sig) != mldsa65.SignatureSize {
			return false
		}
		var pk mldsa65.PublicKey
		var pkBuf [mldsa65.PublicKeySize]byte
		copy(pkBuf[:], packedPk)
		pk.Unpack(&pkBuf)
		return mldsa65.Verify(&pk, message, ctx, sig)
	case ModeP87:
		if len(packedPk) != mldsa87.PublicKeySize || len(sig) != mldsa87.SignatureSize {
			return false
		}
		var pk mldsa87.PublicKey
		var pkBuf [mldsa87.PublicKeySize]byte
		copy(pkBuf[:], packedPk)
		pk.Unpack(&pkBuf)
		return mldsa87.Verify(&pk, message, ctx, sig)
	default:
		return false
	}
}

// sigSizeForMode returns the FIPS 204 signature size for the
// declared mode, or ErrWireModeUnknown if the mode is unrecognised.
// Centralising this here means the wire codec does not depend on
// params.go's table — the codec carries its own canonical numbers
// so a corrupted Params can never confuse the parser.
func sigSizeForMode(mode Mode) (int, error) {
	switch mode {
	case ModeP44:
		return mldsa44.SignatureSize, nil
	case ModeP65:
		return mldsa65.SignatureSize, nil
	case ModeP87:
		return mldsa87.SignatureSize, nil
	default:
		return 0, fmt.Errorf("mode 0x%02x", byte(mode))
	}
}

// pubKeySizeForMode returns the FIPS 204 public-key size for the
// declared mode.
func pubKeySizeForMode(mode Mode) (int, error) {
	switch mode {
	case ModeP44:
		return mldsa44.PublicKeySize, nil
	case ModeP65:
		return mldsa65.PublicKeySize, nil
	case ModeP87:
		return mldsa87.PublicKeySize, nil
	default:
		return 0, fmt.Errorf("mode 0x%02x", byte(mode))
	}
}
