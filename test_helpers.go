package main

import (
	"crypto/rand"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/sampling"
	"github.com/luxfi/lattice/v7/utils/structs"
)

// TestHelpers provides utility functions for tests

// CreateTestRing creates a ring for testing
func CreateTestRing() (*ring.Ring, error) {
	return ring.NewRing(256, []uint64{8380417})
}

// CreateTestVector creates a test vector with random values
func CreateTestVector(r *ring.Ring, size int) structs.Vector[ring.Poly] {
	prng, _ := sampling.NewPRNG()
	sampler := ring.NewUniformSampler(prng, r)
	v := make(structs.Vector[ring.Poly], size)
	for i := range v {
		v[i] = sampler.ReadNew()
	}
	return v
}

// CreateTestMatrix creates a test matrix with random values
func CreateTestMatrix(r *ring.Ring, rows, cols int) structs.Matrix[ring.Poly] {
	prng, _ := sampling.NewPRNG()
	sampler := ring.NewUniformSampler(prng, r)
	m := make(structs.Matrix[ring.Poly], rows)
	for i := range m {
		m[i] = make(structs.Vector[ring.Poly], cols)
		for j := range m[i] {
			m[i][j] = sampler.ReadNew()
		}
	}
	return m
}

// GetRandomBytes generates random bytes
func GetRandomBytes(length int) []byte {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return bytes
}
