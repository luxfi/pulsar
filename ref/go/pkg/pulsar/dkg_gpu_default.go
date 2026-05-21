// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !gpu

package pulsar

// dkg_gpu_default.go — no-GPU build of the DKG dispatch.
//
// Without the `gpu` build tag the dispatch path defaults to the
// single-threaded CPU mirror. Tests that exercise the parallel fan-out
// must call SetDKGGPUForTest(true). Production binaries built without
// `-tags gpu` still use the multi-goroutine fan-out only when explicitly
// enabled by the caller (e.g. via a runtime configuration hook), which
// matches the broader luxfi/crypto convention: GPU paths are opt-in at
// build time, not silently auto-enabled.
//
// The `gpu` build (dkg_gpu_accel.go) flips dkgGPUEnabled to true at init
// and exposes the parallel fan-out by default. The selector still
// short-circuits to CPU below the cell-count threshold so small DKG
// ceremonies (n=3, t=2 ceremonies in tests) keep their micro-bench
// latency unchanged.

func init() {
	// Off by default in the non-gpu build. Tests opt in via
	// SetDKGGPUForTest. This is the inverse of the gpu-tagged init().
	dkgGPUEnabled = false
}
