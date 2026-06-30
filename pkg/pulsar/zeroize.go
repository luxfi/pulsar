// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// zeroize.go — best-effort secret-buffer zeroization.
//
// Threat model: a Pulsar process holding reconstructed secret
// material (e.g. the Combine aggregator's master seed) is at risk
// of coredump / /proc/self/mem / swap-file exfiltration if the
// secret is left live on the heap or stack after use. Go provides
// no native `runtime.Memzero` and the GC may copy buffers around;
// zeroize is a defense-in-depth measure, not a guarantee.
//
// We deliberately do NOT use `defer` for zeroize calls — the
// hot-path callers are short, and explicit zeroization at the
// return site keeps the secret-handling code path locally legible
// (per the project's "no defer for secret cleanup" convention).
//
// Use these helpers on every secret-bearing buffer right before
// returning from the function that allocated it.

// zeroizeBytes overwrites every byte of b with 0.
//
// The compiler is unable to elide this loop because b is a
// reference type; the loop visits the underlying backing array.
// On a future Go that recognises this pattern as dead-store, swap
// to `crypto/subtle.ConstantTimeCopy(0, b, zeros)` or `golang.org/
// x/crypto/internal/subtle` once one is exposed.
func zeroizeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// zeroizeSeed overwrites a fixed-size [SeedSize]byte buffer.
// Separate from zeroizeBytes so the call site is self-documenting:
// "this is the master seed being wiped."
func zeroizeSeed(s *[SeedSize]byte) {
	for i := range s {
		s[i] = 0
	}
}

// zeroizeU16 overwrites a fixed-size [SeedSize]uint16 buffer
// (e.g. the GF(257) byteSum carried by shamirReconstructGF before
// the cSHAKE256 mix).
func zeroizeU16(s *[SeedSize]uint16) {
	for i := range s {
		s[i] = 0
	}
}

// zeroizePrivateKey wipes the secret-bearing fields of a
// PrivateKey (Bytes and Seed). Sets references to nil where
// possible so the underlying backing arrays can be GC'd; before
// they are, the bytes have been overwritten in place so a
// concurrent coredump captures zeros.
func zeroizePrivateKey(sk *PrivateKey) {
	if sk == nil {
		return
	}
	zeroizeBytes(sk.Bytes)
	zeroizeSeed(&sk.Seed)
}
