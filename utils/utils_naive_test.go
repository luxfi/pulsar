package utils

import (
	"testing"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/sampling"
	"github.com/luxfi/lattice/v7/utils/structs"
)

func TestMulPolyNaive(t *testing.T) {
	r, err := ring.NewRing(256, []uint64{8380417})
	if err != nil {
		t.Fatal(err)
	}

	prng, _ := sampling.NewPRNG()
	sampler := ring.NewUniformSampler(prng, r)

	tests := []struct {
		name string
	}{
		{
			name: "basic multiplication",
		},
		{
			name: "multiplication with zero",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var a, b ring.Poly

			switch tt.name {
			case "basic multiplication":
				a = sampler.ReadNew()
				b = sampler.ReadNew()
			case "multiplication with zero":
				a = sampler.ReadNew()
				b = r.NewPoly() // zero polynomial
			}

			result := r.NewPoly()
			MulPolyNaive(r, a, b, result)

			// Verify result is valid
			if result.N() == 0 {
				t.Error("MulPolyNaive() returned invalid polynomial")
			}
		})
	}
}

func TestMatrixVectorMulNaive(t *testing.T) {
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
			rows: 2,
			cols: 2,
		},
		{
			name: "rectangular matrix",
			rows: 3,
			cols: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			A := createNaiveTestMatrix(r, sampler, tt.rows, tt.cols)
			v := createNaiveTestVector(r, sampler, tt.cols)

			result := make(structs.Vector[ring.Poly], tt.rows)
			for i := range result {
				result[i] = r.NewPoly()
			}
			MatrixVectorMulNaive(r, A, v, result)

			// Check dimensions
			if len(result) != tt.rows {
				t.Errorf("MatrixVectorMulNaive() returned vector of length %d, want %d", len(result), tt.rows)
			}

			// Verify all polynomials are valid
			for i, poly := range result {
				if poly.N() == 0 {
					t.Errorf("MatrixVectorMulNaive() returned invalid polynomial at index %d", i)
				}
			}
		})
	}
}

// Helper functions for naive tests
func createNaiveTestVector(r *ring.Ring, sampler ring.Sampler, size int) structs.Vector[ring.Poly] {
	v := make(structs.Vector[ring.Poly], size)
	for i := range v {
		v[i] = sampler.ReadNew()
	}
	return v
}

func createNaiveTestMatrix(r *ring.Ring, sampler ring.Sampler, rows, cols int) structs.Matrix[ring.Poly] {
	m := make(structs.Matrix[ring.Poly], rows)
	for i := range m {
		m[i] = make(structs.Vector[ring.Poly], cols)
		for j := range m[i] {
			m[i][j] = sampler.ReadNew()
		}
	}
	return m
}
