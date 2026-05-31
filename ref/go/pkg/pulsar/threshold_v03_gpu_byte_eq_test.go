// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// threshold_v03_gpu_byte_eq_test.go — byte-equality contract between
// the pure-Go v0.3 algebraic-threshold ML-DSA path and the path with
// gpu.UseAccelerator() opted in.
//
// The lattice/v7/gpu dispatcher is the shared GPU NTT entry point used
// by luxfi/corona's R-LWE threshold signing and (by construction of
// this subpackage) luxfi/pulsar's M-LWE threshold signing. Corona is
// rank-1 Pulsar (R_q^k specialised at k=1); the polynomial arithmetic
// is the same primitive. Sharing the dispatcher keeps one and only
// one place — luxfi/lattice/v7/gpu — owning the cgo plumbing.
//
// TODAY (v0.3): pulsar's FIPS 204 NTT in mldsa_lattice.go operates on
// [256]uint32 polynomials in 32-bit Montgomery form. The lattice/v7
// dispatcher operates on []uint64 polynomials in 64-bit Montgomery
// form. Pulsar's per-poly NTT does NOT route through ring.SubRing, so
// the dispatcher is not engaged by pulsar's production sign path at
// pulsar's N=256 production ring degree. The byte-equality contract
// therefore reduces to "both legs run the canonical pure-Go FIPS 204
// NTT" — vacuously equal.
//
// LOAD-BEARING SCOPE: this test is the regression guard for the v0.4
// lift that widens mldsa_lattice.go's NTT to a 64-bit Montgomery form
// routable through ring.SubRing. At that point the lattice
// dispatcher's per-SubRing fast-path WILL engage on pulsar
// signatures, and any byte divergence between the dispatched leg and
// the pure-Go leg surfaces here as a test failure before it slips
// into a KAT regression.
//
// IMPORT-GRAPH NOTE: this test file imports
// github.com/luxfi/pulsar/ref/go/pkg/pulsar/gpu (the wrapper around
// lattice/v7/gpu). The import lives in a _test.go file so the
// non-test reference compile of github.com/luxfi/pulsar/ref/go/pkg/pulsar
// does NOT pull lattice/v7. Reviewers building the reference for
// NIST submission with `go build ./ref/go/pkg/pulsar` see only the
// circl + golang.org/x/crypto + stdlib transitive graph. Reviewers
// running `go test ./ref/go/pkg/pulsar` pull lattice/v7 as a pure-Go
// dependency; no cgo is engaged unless `-tags gpu` AND `CGO_ENABLED=1`
// AND a Metal / CUDA backend link config are all set.

import (
	"bytes"
	"testing"

	pgpu "github.com/luxfi/pulsar/ref/go/pkg/pulsar/gpu"
)

// TestPulsar_GPU_ByteEqual asserts that the v0.3 algebraic threshold
// ML-DSA signature produced via the pure-Go path is bit-identical to
// the signature produced via the GPU-accelerator-enabled path for the
// same committee, threshold, seed, message, and session id.
//
// Exercised shapes mirror the existing TestAlgebraic_FullCycle_*
// coverage: (5, 3) is the canonical small fixture; (7, 4) and (10, 7)
// add intermediate quorum sizes so a divergence in any code path
// proportional to t, n, or t·N would surface.
func TestPulsar_GPU_ByteEqual(t *testing.T) {
	for _, tc := range []struct {
		name string
		n, t int
	}{
		{"n5_t3", 5, 3},
		{"n7_t4", 7, 4},
		{"n10_t7", 10, 7},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			msg := []byte("pulsar gpu byte-eq " + tc.name)
			var sid [16]byte
			copy(sid[:], "v03-gpu-byte-eq!")

			runLeg := func(gpuOn bool) []byte {
				if gpuOn {
					if err := pgpu.UseAccelerator(); err != nil {
						t.Fatalf("UseAccelerator: %v", err)
					}
				} else {
					pgpu.DisableAccelerator()
				}
				sig := runV03Once(t, tc.n, tc.t, msg, sid)
				return sig.Bytes
			}

			cpu := runLeg(false)
			gpu := runLeg(true)
			pgpu.DisableAccelerator() // clean global state for subsequent tests

			if !bytes.Equal(cpu, gpu) {
				t.Fatalf("signature bytes mismatch: cpu_len=%d gpu_len=%d cpu_head=%x gpu_head=%x",
					len(cpu), len(gpu), cpu[:32], gpu[:32])
			}
		})
	}
}

// TestPulsar_GPU_ByteEqual_Force exercises the byte-equal contract
// with the lattice/v7 single-poly dispatch threshold forced to 1. On
// a cgo+gpu build with a Metal / CUDA backend live this would
// dispatch every registered SubRing NTT to the GPU regardless of N —
// but pulsar's FIPS 204 NTT does not flow through ring.SubRing today
// so the contract still reduces to the pure-Go path. The test
// exists so a future v0.4 batched lift that DOES route through
// ring.SubRing is automatically gated on byte equality at the
// smallest possible dispatch threshold.
func TestPulsar_GPU_ByteEqual_Force(t *testing.T) {
	msg := []byte("pulsar gpu byte-eq forced")
	var sid [16]byte
	copy(sid[:], "v03-gpu-be-force")

	pgpu.DisableAccelerator()
	cpu := runV03Once(t, 5, 3, msg, sid).Bytes

	if err := pgpu.UseAcceleratorForce(); err != nil {
		t.Fatalf("UseAcceleratorForce: %v", err)
	}
	forced := runV03Once(t, 5, 3, msg, sid).Bytes
	pgpu.DisableAccelerator()

	if !bytes.Equal(cpu, forced) {
		t.Fatalf("forced GPU signature differs: cpu_head=%x forced_head=%x",
			cpu[:32], forced[:32])
	}
}

// runV03Once drives the v0.3 ceremony retry loop and returns the
// emitted signature. It reuses the existing stageAlgebraic helper
// from threshold_v03_test.go — that helper handles identity setup,
// session-key derivation, the rejection-restart loop, and aggregator
// call. Reusing it keeps THIS file focused on the byte-equality
// assertion, not on re-deriving the ceremony fixture.
func runV03Once(t testing.TB, n, threshold int, msg []byte, sid [16]byte) *Signature {
	t.Helper()
	var (
		sig *Signature
		err error
	)
	for attempt := uint32(0); attempt < 64; attempt++ {
		sig, _, _, _, _, _, _, err = stageAlgebraic(t, n, threshold, msg, sid, attempt)
		if err == nil {
			return sig
		}
		if err != ErrAlgebraicRestart {
			t.Fatalf("attempt %d unexpected err: %v", attempt, err)
		}
	}
	t.Fatalf("no acceptance within 64 attempts")
	return nil
}
