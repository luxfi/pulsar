// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsarm

import "math"

// logFloat / expFloat are the math.Log / math.Exp pair, pulled
// behind named indirection so luxround.go can stub them in unit
// tests if needed.
func logFloat(x float64) float64 { return math.Log(x) }
func expFloat(x float64) float64 { return math.Exp(x) }
