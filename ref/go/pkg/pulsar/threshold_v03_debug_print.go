// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// threshold_v03_debug_print.go — TEMPORARY debug printer used by
// the iso-test. Delete before shipping.

import "fmt"

func debugV03PrintC(c poly) {
	fmt.Printf("[V03-DEBUG-FROMSIGNER] c[0..4]=%v\n", c[0:5])
	// Count non-zero
	nz := 0
	for i := 0; i < mldsaN; i++ {
		if c[i] != 0 {
			nz++
		}
	}
	fmt.Printf("[V03-DEBUG-FROMSIGNER] c nonzeros=%d\n", nz)
	// Show last 5 positions
	fmt.Printf("[V03-DEBUG-FROMSIGNER] c[251..255]=%v\n", c[251:256])
}

func debugV03PrintCTilde(cTilde []byte) {
	if len(cTilde) > 8 {
		fmt.Printf("[V03-DEBUG-FROMSIGNER] cTilde[0..7]=%v\n", cTilde[0:8])
	}
}

func debugV03PrintMu(mu [64]byte) {
	fmt.Printf("[V03-DEBUG-FROMSIGNER] mu[0..7]=%v\n", mu[0:8])
}

func debugV03PrintW1Packed(w1 []byte) {
	if len(w1) > 8 {
		fmt.Printf("[V03-DEBUG-FROMSIGNER] w1Packed[0..7]=%v len=%d\n", w1[0:8], len(w1))
	}
}

func debugV03PrintW(w polyVec) {
	if len(w) > 0 {
		fmt.Printf("[V03-DEBUG-FROMSIGNER] w[0][0..4]=%v\n", w[0][0:5])
	}
}
