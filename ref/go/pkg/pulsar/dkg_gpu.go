// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// dkg_gpu.go — GPU acceleration dispatch for the DKG per-party compute.
//
// The DKG per-party compute decomposes into three workloads:
//
//   1. Per-party 32-byte contribution sampling (one cSHAKE256 read).
//   2. Per-party (t-1) * 32 polynomial-coefficient generation (one cSHAKE256
//      stretch + reduction modulo p ∈ {257, 8380417}).
//   3. Per-position polynomial evaluation: for each of n committee positions
//      i ∈ {1..n} and each of 32 byte-slots b, compute
//        f_i(b) = c_0[b] + c_1[b]·i + c_2[b]·i^2 + … + c_{t-1}[b]·i^{t-1}  (mod p)
//      via Horner's method.
//
// Step (3) is the only workload whose cost scales as n·t·SeedSize and is
// embarrassingly parallel across the (i, b) lattice. The CPU path
// (shamirDealRandomGF / shamirDealRandomQ in shamir.go and shamir_gfq.go)
// evaluates this lattice in a tight single-threaded loop. The GPU-dispatch
// path here splits the 32 byte-slots across runtime.NumCPU() workers and
// fans out each byte-slot's n Horner chains to scalar instructions. The
// inner Horner chain itself is data-dependent and stays scalar.
//
// Byte-equality guarantee.
//
// Both the CPU and GPU-dispatch paths consume the SAME coefficient stream
// (the cSHAKE256 output of the same key material) and execute the SAME
// modular arithmetic (Horner mod p). The only difference is the dispatch
// order. Modular addition and multiplication are commutative and the
// reduction modulus is the same prime, so per-(i, b) outputs are byte-equal
// regardless of which goroutine computes them. The output share[] slice is
// indexed by deterministic i ∈ {1..n}; writes never collide because each
// worker owns a disjoint set of (i, b) cells.
//
// Backend selection.
//
// dkgComputeBackend returns the active dispatch path. The default is
// kDKGBackendCPU (single-threaded, byte-identical to the historical CPU
// path). When backend.Default() resolves to GPU and runtime.NumCPU() > 1
// the path switches to kDKGBackendParallel. The accel.LatticeOps surface is
// not used here directly because the workload is small-prime modular
// arithmetic with no NTT structure; the accel-dispatch surface is reserved
// for the v0.2 R_q^k Pedersen DKG (doc.go sub-package "dkg") where NTT
// over Z_q[X]/(X^256+1) IS the hot loop and BatchNTTForward + PolyMul map
// directly. The hook is exported as DKGGPUDispatchAvailable for the v0.2
// integration.
//
// Threat model alignment.
//
// The parallel path is constant-time per (i, b) cell and never branches on
// secret material. The dispatch order itself is determined by GOMAXPROCS
// and the slot index — a non-secret. A power-side-channel attacker who can
// distinguish parallel from sequential execution learns the deployment
// configuration, not the secret share. The cSHAKE256 coefficient stream is
// consumed in a fixed order (off += 2 in GF(257), off += 4 in GF(q))
// before any goroutine fan-out; the parallel section reads only from the
// already-derived coeffs[] table.

import (
	"encoding/binary"
	"runtime"
	"sync"
)

// dkgComputeBackend identifies the backend used by Shamir polynomial
// evaluation during DKG. The default is CPU (single-threaded) which is
// byte-identical to the historical reference implementation.
type dkgComputeBackend uint8

const (
	// kDKGBackendCPU is the single-threaded reference path. Always
	// available; always byte-equal to the historical implementation.
	kDKGBackendCPU dkgComputeBackend = iota

	// kDKGBackendParallel is the multi-goroutine fan-out path. Splits
	// the 32 byte-slots across runtime.GOMAXPROCS workers. Output is
	// byte-equal to kDKGBackendCPU because the work splits cleanly by
	// (i, b) cell — no shared writes, no reduction across workers.
	kDKGBackendParallel
)

// dkgGPUEnabled is the package-level GPU dispatch toggle. The init() in
// dkg_gpu_accel.go (cgo build) flips this to true if an accel session is
// available; the no-cgo path leaves it false. Tests that want to force the
// parallel path independent of the build can call SetDKGGPUForTest.
var dkgGPUEnabled bool

// SetDKGGPUForTest forces the DKG dispatch backend. Returns the previous
// value so tests can restore the original. Test-only; do not call from
// production code paths.
func SetDKGGPUForTest(on bool) bool {
	prev := dkgGPUEnabled
	dkgGPUEnabled = on
	return prev
}

// DKGGPUDispatchAvailable reports whether the GPU dispatch path is wired
// in this build. Production callers can probe this for diagnostics; the
// hot path consults dkgComputeBackend() directly to avoid the extra
// function call.
func DKGGPUDispatchAvailable() bool {
	return dkgGPUEnabled
}

// resolveDKGBackend returns the active DKG compute backend.
//
// The resolution honours:
//   - the package-level dkgGPUEnabled flag (set by accel init or tests),
//   - the available core count (parallel needs ≥ 2 workers to amortise the
//     goroutine setup cost),
//   - the input shape (n parties × t threshold). Below kDKGParallelMinCells
//     the goroutine setup dwarfs the work and CPU is faster.
func resolveDKGBackend(n, t int) dkgComputeBackend {
	if !dkgGPUEnabled {
		return kDKGBackendCPU
	}
	if runtime.GOMAXPROCS(0) < 2 {
		return kDKGBackendCPU
	}
	// 32 byte-slots × n parties × t coefficients = work cells. Below
	// this threshold the goroutine-spawn cost dominates the inner-loop
	// work and the parallel path regresses.
	//
	// Empirically tuned on Apple M1 Max (BenchmarkDKG_GPU_PolyEvalOnly):
	//
	//   n=21,  t=14  → 9408 cells   → 0.72x   (regress) → CPU
	//   n=64,  t=43  → 88064 cells  → 2.12x   (win)     → parallel
	//   n=128, t=86  → 352256 cells → 2.31x             → parallel
	//   n=256, t=171 → 1.4M cells   → 3.48x             → parallel
	//
	// The crossover sits between n=21 and n=64. We pin the threshold at
	// 32 × 32 × 32 = 32768 cells (n=32, t=32) which is the smallest
	// shape that consistently wins on M1 Max with 10 GOMAXPROCS. This
	// keeps the common Lux validator-committee shape (n=21, t=14) on
	// the single-threaded path where it actually runs fastest, and
	// switches to parallel as soon as the shape grows past it.
	const kDKGParallelMinCells = 32 * 32 * SeedSize // 32768
	if n*t*SeedSize < kDKGParallelMinCells {
		return kDKGBackendCPU
	}
	return kDKGBackendParallel
}

// shamirDealRandomGFAccel is the backend-dispatched counterpart to
// shamirDealRandomGF (shamir.go). It produces byte-identical output to the
// reference path; the only difference is HOW the polynomial-evaluation
// lattice is traversed.
//
// secret: 32 GF(257) lanes (each in [0, 257)). The DKG path enters with
// values in [0, 256) (byte lifts) but the function tolerates the full
// GF(257) range so HJKY97 reshare callers (which may emit 256) reuse it.
//
// coeffStream MUST be at least (t-1) * SeedSize * 2 bytes. The caller in
// dkg.go derives this from cSHAKE256; this function does not stretch.
//
// This function is internal and is exercised by both the dispatch path and
// the explicit byte-equality tests (dkg_gpu_test.go).
func shamirDealRandomGFAccel(secret [SeedSize]uint16, n, t int, coeffStream []byte) ([]shamirShare, error) {
	if t < 1 || n < t {
		return nil, ErrInvalidThreshold
	}
	if n > 256 {
		return nil, ErrCommitteeTooLarge
	}
	needed := (t - 1) * SeedSize * 2
	if needed < 2 {
		needed = 2
	}
	if len(coeffStream) < needed {
		coeffStream = cshake256(coeffStream, needed, tagSeedShare)
	}

	// Build the coefficient table once on the dispatching goroutine. This
	// matches the byte-by-byte stream consumption of the CPU reference so
	// the per-coefficient values are byte-equal.
	coeffs := make([][SeedSize]uint16, t)
	for b := 0; b < SeedSize; b++ {
		coeffs[0][b] = secret[b] % uint16(shamirPrime)
	}
	off := 0
	for d := 1; d < t; d++ {
		for b := 0; b < SeedSize; b++ {
			r := uint32(coeffStream[off])<<8 | uint32(coeffStream[off+1])
			off += 2
			coeffs[d][b] = uint16(r % shamirPrime)
		}
	}

	shares := make([]shamirShare, n)
	for i := 1; i <= n; i++ {
		shares[i-1].X = uint32(i)
	}

	switch resolveDKGBackend(n, t) {
	case kDKGBackendParallel:
		shamirEvalParallelGF(coeffs, n, t, shares)
	default:
		shamirEvalSequentialGF(coeffs, n, t, shares)
	}
	return shares, nil
}

// shamirEvalSequentialGF is the byte-identical mirror of the inner loop in
// shamirDealRandomGF. Used as the CPU dispatch leg and as the reference for
// the parallel-path equality check.
func shamirEvalSequentialGF(coeffs [][SeedSize]uint16, n, t int, shares []shamirShare) {
	for i := 1; i <= n; i++ {
		x := uint32(i)
		for b := 0; b < SeedSize; b++ {
			// Horner: acc = (((c_{t-1} * x) + c_{t-2}) * x + ...) + c_0
			acc := uint32(coeffs[t-1][b])
			for d := t - 2; d >= 0; d-- {
				acc = (acc*x + uint32(coeffs[d][b])) % shamirPrime
			}
			shares[i-1].Y[b] = uint16(acc)
		}
	}
}

// shamirEvalParallelGF splits the 32 byte-slots across GOMAXPROCS workers.
// Each worker computes its slot's n Horner chains independently and writes
// to disjoint shares[i-1].Y[b] cells (different b across workers). No
// reduction step needed — output is byte-equal to shamirEvalSequentialGF.
func shamirEvalParallelGF(coeffs [][SeedSize]uint16, n, t int, shares []shamirShare) {
	workers := runtime.GOMAXPROCS(0)
	if workers > SeedSize {
		workers = SeedSize
	}
	if workers < 1 {
		workers = 1
	}
	// Slot fan-out: each worker takes a stride of byte-slots.
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(w int) {
			defer wg.Done()
			for b := w; b < SeedSize; b += workers {
				for i := 1; i <= n; i++ {
					x := uint32(i)
					acc := uint32(coeffs[t-1][b])
					for d := t - 2; d >= 0; d-- {
						acc = (acc*x + uint32(coeffs[d][b])) % shamirPrime
					}
					shares[i-1].Y[b] = uint16(acc)
				}
			}
		}(w)
	}
	wg.Wait()
}

// shamirDealRandomQAccel is the backend-dispatched counterpart to
// shamirDealRandomQ (shamir_gfq.go). Same contract, GF(q) arithmetic.
func shamirDealRandomQAccel(secret [SeedSize]byte, n, t int, coeffStream []byte) ([]shamirShareQ, error) {
	if t < 1 || n < t {
		return nil, ErrInvalidThreshold
	}
	if uint64(n) > uint64(MaxCommitteeQ) {
		return nil, ErrCommitteeTooLargeQ
	}
	needed := (t - 1) * SeedSize * 4
	if needed < 4 {
		needed = 4
	}
	if len(coeffStream) < needed {
		coeffStream = cshake256(coeffStream, needed, tagSeedShare)
	}

	coeffs := make([][SeedSize]uint32, t)
	for b := 0; b < SeedSize; b++ {
		coeffs[0][b] = uint32(secret[b])
	}
	off := 0
	for d := 1; d < t; d++ {
		for b := 0; b < SeedSize; b++ {
			r := binary.BigEndian.Uint32(coeffStream[off : off+4])
			off += 4
			coeffs[d][b] = uint32(uint64(r) % shamirPrimeQ)
		}
	}

	shares := make([]shamirShareQ, n)
	for i := 1; i <= n; i++ {
		shares[i-1].X = uint32(i)
	}

	switch resolveDKGBackend(n, t) {
	case kDKGBackendParallel:
		shamirEvalParallelQ(coeffs, n, t, shares)
	default:
		shamirEvalSequentialQ(coeffs, n, t, shares)
	}
	return shares, nil
}

// shamirEvalSequentialQ mirrors the inner Horner loop of shamirDealRandomQ.
func shamirEvalSequentialQ(coeffs [][SeedSize]uint32, n, t int, shares []shamirShareQ) {
	for i := 1; i <= n; i++ {
		x := uint64(i)
		for b := 0; b < SeedSize; b++ {
			acc := uint64(coeffs[t-1][b])
			for d := t - 2; d >= 0; d-- {
				acc = (acc*x + uint64(coeffs[d][b])) % shamirPrimeQ
			}
			shares[i-1].Y[b] = uint32(acc)
		}
	}
}

// shamirEvalParallelQ splits byte-slots across workers; same disjoint-write
// argument as shamirEvalParallelGF.
func shamirEvalParallelQ(coeffs [][SeedSize]uint32, n, t int, shares []shamirShareQ) {
	workers := runtime.GOMAXPROCS(0)
	if workers > SeedSize {
		workers = SeedSize
	}
	if workers < 1 {
		workers = 1
	}
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(w int) {
			defer wg.Done()
			for b := w; b < SeedSize; b += workers {
				for i := 1; i <= n; i++ {
					x := uint64(i)
					acc := uint64(coeffs[t-1][b])
					for d := t - 2; d >= 0; d-- {
						acc = (acc*x + uint64(coeffs[d][b])) % shamirPrimeQ
					}
					shares[i-1].Y[b] = uint32(acc)
				}
			}
		}(w)
	}
	wg.Wait()
}
