// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// threshold_v03_reflect_test.go — tiny reflect indirection used by
// TestAlgebraic_SetupHasNoSkField. Kept in its own file so the reflect
// import does not bleed into the rest of the test surface.

import "reflect"

type reflectType = reflect.Type

func reflectTypeImpl(v interface{}) reflectType {
	return reflect.TypeOf(v)
}
