// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build gpu

package pulsar

// dkg_gpu_accel.go — GPU build of the DKG dispatch.
//
// Built only with `-tags gpu`. The build tag deliberately does not pull
// in luxfi/accel; pulsar stays a no-cgo module so it remains buildable
// in every consumer (consensus, node, bridge, KAT regen pipeline). The
// real GPU kernel for R_q^k Pedersen DKG (when v0.2 ships) lives in the
// engine layer (consensus/engine/gpu_batch_pipeline.go) where the accel
// session is owned and the host has the native libraries installed.
//
// For the current reference DKG over GF(257) / GF(8380417) Shamir, the
// `gpu` tag enables the parallel byte-slot fan-out path. The fan-out is
// PURE GO — no CGO, no native libraries — and produces byte-equal output
// to the single-threaded path. This is the "GPU" the user sees today:
// real parallelism via the Go runtime, deterministic and byte-equal.
// The v0.2 path (BatchNTTForward over R_q^k coefficients) lands at the
// same dispatch point when the engine layer registers the accel hook.

func init() {
	// On by default in the gpu build. Production callers can still
	// force CPU via SetDKGGPUForTest(false) for KAT regeneration or
	// constant-time profiling.
	dkgGPUEnabled = true
}
