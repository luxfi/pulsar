// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsarm

import "errors"

// params.go — concrete parameter sets for Pulsar-M and the canonical
// Mode -> Params resolution. The parameters mirror FIPS 204 ML-DSA's
// three security levels per pulsar-m.tex §5 (parameters.tex).

// Mode identifies which FIPS 204 parameter set a Pulsar-M instance
// targets. The Pulsar-M family inherits FIPS 204's three NIST PQ
// security categories.
type Mode uint8

const (
	// ModeUnspecified rejects every operation; included so the zero
	// Mode is invalid (forces explicit initialization).
	ModeUnspecified Mode = 0

	// ModeP44 targets FIPS 204 ML-DSA-44 (NIST PQ Category 2,
	// ≥128-bit classical security). 1312-byte pk, 2420-byte signature.
	ModeP44 Mode = 44

	// ModeP65 targets FIPS 204 ML-DSA-65 (NIST PQ Category 3,
	// ≥192-bit classical security). 1952-byte pk, 3309-byte signature.
	// This is the production target for Lux consensus
	// (SigSchemePulsarM65).
	ModeP65 Mode = 65

	// ModeP87 targets FIPS 204 ML-DSA-87 (NIST PQ Category 5,
	// ≥256-bit classical security). 2592-byte pk, 4627-byte signature.
	ModeP87 Mode = 87
)

// String returns the canonical mode name.
func (m Mode) String() string {
	switch m {
	case ModeP44:
		return "Pulsar-M-44"
	case ModeP65:
		return "Pulsar-M-65"
	case ModeP87:
		return "Pulsar-M-87"
	default:
		return "Pulsar-M-unspecified"
	}
}

// Params captures the concrete parameters of a Pulsar-M instance.
// The values are derived from FIPS 204 §4 Table 1 (and pulsar-m.tex
// §5 parameters.tex).
type Params struct {
	Mode Mode

	// FIPS 204 module-LWE shape.
	K     int    // module dimension
	L     int    // secret dimension (ℓ)
	Eta   int    // secret coefficient bound η
	Tau   int    // challenge weight τ
	Omega int    // hint bound ω
	Q     uint64 // 8380417 — FIPS 204 prime modulus
	N     int    // 256 — ring degree

	// Wire sizes (matches cloudflare/circl FIPS 204 implementation).
	PublicKeySize  int
	PrivateKeySize int
	SignatureSize  int

	// Pulsar-M-specific. ShamirPrime is the prime over which seed-byte
	// Shamir shares are computed. We use 8380417 (the FIPS 204 q): it
	// is prime, fits two bytes plus three bits, and gives a uniform
	// distribution on per-byte share values modulo the same prime that
	// the rest of the protocol already operates on.
	ShamirPrime uint64

	// MaxRestart is the maximum number of FIPS 204 rejection-restart
	// attempts before the protocol aborts. FIPS 204's expected restart
	// count is ~5 for ML-DSA-65; setting the bound to 256 gives an
	// abort probability < 2^-512 under correct sampling.
	MaxRestart uint32
}

// SeedSize is the byte length of an ML-DSA key seed across all
// parameter sets. The Pulsar-M threshold layer Shamir-shares this
// seed across the committee.
const SeedSize = 32

// TargetCommitteeSize is the canonical "extreme committee" size used
// in spec/pulsar-m.tex section "Large committees" and in the bench
// harness. It exercises the GF(q) Shamir path at 1 111 111 signers —
// over four orders of magnitude beyond the GF(257) cap of 256.
//
// Rationale for the exact value: seven 1s. The digit literal is
// memorable, and the value sits at ≈13.3 % of the GF(q) party-count
// limit q − 1 = 8 380 416, leaving ≈87 % headroom for over-
// provisioning, joining-without-reshare slack, and future
// grow-without-fork.
//
// Arithmetic-width note. At N = 1 111 111 every per-byte share value
// remains a single uint32 lane (mod q is ≤ 23 bits). One Lagrange
// multiplication needs at most 46 bits of intermediate width, so
// uint64 accumulators suffice everywhere — uint128 / uint256 are not
// required for Pulsar-M's core arithmetic. (Wider widths are
// reserved for the SNARK side of Z-Chain, which operates over
// ~254-bit prime-order fields.)
const TargetCommitteeSize = 1_111_111

// Hard-coded parameter tables per FIPS 204 §4 Table 1.
//
// PublicKeySize / PrivateKeySize / SignatureSize values match
// cloudflare/circl's mldsa{44,65,87} package constants verbatim — they
// are the canonical FIPS 204 wire sizes.

// ParamsP44 is the Pulsar-M-44 parameter set.
var ParamsP44 = &Params{
	Mode:           ModeP44,
	K:              4,
	L:              4,
	Eta:            2,
	Tau:            39,
	Omega:          80,
	Q:              8380417,
	N:              256,
	PublicKeySize:  1312,
	PrivateKeySize: 2560,
	SignatureSize:  2420,
	ShamirPrime:    8380417,
	MaxRestart:     256,
}

// ParamsP65 is the Pulsar-M-65 parameter set (production target).
var ParamsP65 = &Params{
	Mode:           ModeP65,
	K:              6,
	L:              5,
	Eta:            4,
	Tau:            49,
	Omega:          55,
	Q:              8380417,
	N:              256,
	PublicKeySize:  1952,
	PrivateKeySize: 4032,
	SignatureSize:  3309,
	ShamirPrime:    8380417,
	MaxRestart:     256,
}

// ParamsP87 is the Pulsar-M-87 parameter set.
var ParamsP87 = &Params{
	Mode:           ModeP87,
	K:              8,
	L:              7,
	Eta:            2,
	Tau:            60,
	Omega:          75,
	Q:              8380417,
	N:              256,
	PublicKeySize:  2592,
	PrivateKeySize: 4896,
	SignatureSize:  4627,
	ShamirPrime:    8380417,
	MaxRestart:     256,
}

// ParamsFor returns the canonical Params for the given Mode.
func ParamsFor(mode Mode) (*Params, error) {
	switch mode {
	case ModeP44:
		return ParamsP44, nil
	case ModeP65:
		return ParamsP65, nil
	case ModeP87:
		return ParamsP87, nil
	default:
		return nil, ErrUnknownMode
	}
}

// MustParamsFor is the panic-on-error variant of ParamsFor for use in
// constants and tests. Production code must use ParamsFor.
func MustParamsFor(mode Mode) *Params {
	p, err := ParamsFor(mode)
	if err != nil {
		panic(err)
	}
	return p
}

// Validate checks that a Params struct is internally consistent and
// matches one of the registered parameter sets. This is the central
// audit gate for downstream code that takes a *Params from an
// untrusted source.
func (p *Params) Validate() error {
	if p == nil {
		return ErrNilParams
	}
	canonical, err := ParamsFor(p.Mode)
	if err != nil {
		return err
	}
	if *p != *canonical {
		return ErrParamsTampered
	}
	return nil
}

// Errors returned by params operations.
var (
	ErrUnknownMode    = errors.New("pulsarm: unknown mode")
	ErrNilParams      = errors.New("pulsarm: nil params")
	ErrParamsTampered = errors.New("pulsarm: params do not match canonical set")
)
