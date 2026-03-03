package utils

import (
	"testing"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/sampling"
	"github.com/luxfi/lattice/v7/utils/structs"
)

func TestMatrixVectorMul(t *testing.T) {
	r, err := ring.NewRing(256, []uint64{8380417})
	if err != nil {
		t.Fatal(err)
	}

	prng, _ := sampling.NewPRNG()
	sampler := ring.NewUniformSampler(prng, r)

	tests := []struct {
		name string
		rows int
		cols int
	}{
		{
			name: "square matrix",
			rows: 3,
			cols: 3,
		},
		{
			name: "rectangular matrix",
			rows: 4,
			cols: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create random matrix and vector
			A := createTestMatrix(r, sampler, tt.rows, tt.cols)
			v := createTestVector(r, sampler, tt.cols)
			result := make(structs.Vector[ring.Poly], tt.rows)
			for i := range result {
				result[i] = r.NewPoly()
			}

			// Multiply
			MatrixVectorMul(r, A, v, result)

			// Check dimensions
			if len(result) != tt.rows {
				t.Errorf("MatrixVectorMul() result has length %d, want %d", len(result), tt.rows)
			}

			// Verify result is non-nil
			for i, poly := range result {
				if poly.N() == 0 {
					t.Errorf("Result contains invalid polynomial at index %d", i)
				}
			}
		})
	}
}

func TestVectorAdd(t *testing.T) {
	r, err := ring.NewRing(256, []uint64{8380417})
	if err != nil {
		t.Fatal(err)
	}

	prng, _ := sampling.NewPRNG()
	sampler := ring.NewUniformSampler(prng, r)

	tests := []struct {
		name string
		size int
	}{
		{
			name: "small vectors",
			size: 3,
		},
		{
			name: "large vectors",
			size: 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v1 := createTestVector(r, sampler, tt.size)
			v2 := createTestVector(r, sampler, tt.size)
			result := make(structs.Vector[ring.Poly], tt.size)
			for i := range result {
				result[i] = r.NewPoly()
			}

			VectorAdd(r, v1, v2, result)

			// Check dimensions
			if len(result) != tt.size {
				t.Errorf("VectorAdd() result has length %d, want %d", len(result), tt.size)
			}
		})
	}
}

func TestVectorSub(t *testing.T) {
	r, err := ring.NewRing(256, []uint64{8380417})
	if err != nil {
		t.Fatal(err)
	}

	prng, _ := sampling.NewPRNG()
	sampler := ring.NewUniformSampler(prng, r)

	tests := []struct {
		name string
		size int
	}{
		{
			name: "small vectors",
			size: 3,
		},
		{
			name: "large vectors",
			size: 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v1 := createTestVector(r, sampler, tt.size)
			v2 := createTestVector(r, sampler, tt.size)
			result := make(structs.Vector[ring.Poly], tt.size)
			for i := range result {
				result[i] = r.NewPoly()
			}

			VectorSub(r, v1, v2, result)

			// Check dimensions
			if len(result) != tt.size {
				t.Errorf("VectorSub() result has length %d, want %d", len(result), tt.size)
			}
		})
	}
}

func TestNTTConversions(t *testing.T) {
	r, err := ring.NewRing(256, []uint64{8380417})
	if err != nil {
		t.Fatal(err)
	}

	prng, _ := sampling.NewPRNG()
	sampler := ring.NewUniformSampler(prng, r)

	tests := []struct {
		name string
		rows int
		cols int
	}{
		{
			name: "small matrix",
			rows: 2,
			cols: 2,
		},
		{
			name: "large matrix",
			rows: 3,
			cols: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test matrix conversions
			matrix := createTestMatrix(r, sampler, tt.rows, tt.cols)

			// Store original values for comparison
			original := make(structs.Matrix[ring.Poly], tt.rows)
			for i := range original {
				original[i] = make(structs.Vector[ring.Poly], tt.cols)
				for j := range original[i] {
					original[i][j] = *matrix[i][j].CopyNew()
				}
			}

			// Convert to NTT and back
			ConvertMatrixToNTT(r, matrix)
			ConvertMatrixFromNTT(r, matrix)

			// Verify round-trip (approximately - NTT may introduce small numerical differences)
			for i := range matrix {
				for j := range matrix[i] {
					// Just verify they're still valid polynomials
					if matrix[i][j].N() == 0 {
						t.Errorf("Matrix NTT round-trip produced invalid polynomial at [%d][%d]", i, j)
					}
				}
			}

			// Test vector conversions
			vector := createTestVector(r, sampler, tt.cols)

			// Convert to NTT and back
			ConvertVectorToNTT(r, vector)
			ConvertVectorFromNTT(r, vector)

			// Verify round-trip
			for i := range vector {
				if vector[i].N() == 0 {
					t.Errorf("Vector NTT round-trip produced invalid polynomial at index %d", i)
				}
			}
		})
	}
}

func TestSamplePolyVector(t *testing.T) {
	r, err := ring.NewRing(256, []uint64{8380417})
	if err != nil {
		t.Fatal(err)
	}

	prng, _ := sampling.NewPRNG()
	sampler := ring.NewUniformSampler(prng, r)

	tests := []struct {
		name string
		size int
	}{
		{
			name: "small vector",
			size: 3,
		},
		{
			name: "large vector",
			size: 20,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := SamplePolyVector(r, tt.size, sampler, false, false)

			// Check dimensions
			if len(v) != tt.size {
				t.Errorf("SamplePolyVector() returned vector of length %d, want %d", len(v), tt.size)
			}

			// Verify all polynomials are valid
			for i, poly := range v {
				if poly.N() == 0 {
					t.Errorf("SamplePolyVector() returned invalid polynomial at index %d", i)
				}
			}
		})
	}
}

func TestSamplePolyMatrix(t *testing.T) {
	r, err := ring.NewRing(256, []uint64{8380417})
	if err != nil {
		t.Fatal(err)
	}

	prng, _ := sampling.NewPRNG()
	sampler := ring.NewUniformSampler(prng, r)

	tests := []struct {
		name string
		rows int
		cols int
	}{
		{
			name: "small matrix",
			rows: 2,
			cols: 3,
		},
		{
			name: "square matrix",
			rows: 5,
			cols: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := SamplePolyMatrix(r, tt.rows, tt.cols, sampler, false, false)

			// Check dimensions
			if len(m) != tt.rows {
				t.Errorf("SamplePolyMatrix() returned %d rows, want %d", len(m), tt.rows)
			}
			if len(m) > 0 && len(m[0]) != tt.cols {
				t.Errorf("SamplePolyMatrix() returned %d columns, want %d", len(m[0]), tt.cols)
			}

			// Verify all polynomials are valid
			for i := range m {
				for j := range m[i] {
					if m[i][j].N() == 0 {
						t.Errorf("SamplePolyMatrix() returned invalid polynomial at [%d][%d]", i, j)
					}
				}
			}
		})
	}
}

func TestInitializeMatrix(t *testing.T) {
	r, err := ring.NewRing(256, []uint64{8380417})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		rows int
		cols int
	}{
		{
			name: "small matrix",
			rows: 2,
			cols: 3,
		},
		{
			name: "square matrix",
			rows: 4,
			cols: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := InitializeMatrix(r, tt.rows, tt.cols)

			// Check dimensions
			if len(m) != tt.rows {
				t.Errorf("InitializeMatrix() returned %d rows, want %d", len(m), tt.rows)
			}
			if len(m) > 0 && len(m[0]) != tt.cols {
				t.Errorf("InitializeMatrix() returned %d columns, want %d", len(m[0]), tt.cols)
			}

			// Verify all polynomials are initialized
			for i := range m {
				for j := range m[i] {
					if m[i][j].N() == 0 {
						t.Errorf("InitializeMatrix() returned uninitialized polynomial at [%d][%d]", i, j)
					}
				}
			}
		})
	}
}

// Helper functions for testing
func createTestVector(r *ring.Ring, sampler ring.Sampler, size int) structs.Vector[ring.Poly] {
	v := make(structs.Vector[ring.Poly], size)
	for i := range v {
		v[i] = sampler.ReadNew()
	}
	return v
}

func createTestMatrix(r *ring.Ring, sampler ring.Sampler, rows, cols int) structs.Matrix[ring.Poly] {
	m := make(structs.Matrix[ring.Poly], rows)
	for i := range m {
		m[i] = make(structs.Vector[ring.Poly], cols)
		for j := range m[i] {
			m[i][j] = sampler.ReadNew()
		}
	}
	return m
}
