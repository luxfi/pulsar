package primitives

import (
	"testing"

	"github.com/luxfi/pulsar/utils"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/sampling"
	"github.com/luxfi/lattice/v7/utils/structs"
)

func TestPRNGKey(t *testing.T) {
	r, err := ring.NewRing(256, []uint64{8380417})
	if err != nil {
		t.Fatal(err)
	}

	// Create a test secret key share
	prng, _ := sampling.NewPRNG()
	sampler := ring.NewUniformSampler(prng, r)
	skShare := make(structs.Vector[ring.Poly], 3)
	for i := range skShare {
		skShare[i] = sampler.ReadNew()
	}

	key := PRNGKey(skShare)

	if len(key) != 32 {
		t.Errorf("PRNGKey() returned %d bytes, want 32", len(key))
	}

	// Verify deterministic
	key2 := PRNGKey(skShare)
	for i := range key {
		if key[i] != key2[i] {
			t.Error("PRNGKey() is not deterministic")
			break
		}
	}
}

func TestGenerateMAC(t *testing.T) {
	r, err := ring.NewRing(256, []uint64{8380417})
	if err != nil {
		t.Fatal(err)
	}

	// Create test inputs
	prng, _ := sampling.NewPRNG()
	sampler := ring.NewUniformSampler(prng, r)

	TildeD := make(structs.Matrix[ring.Poly], 2)
	for i := range TildeD {
		TildeD[i] = make(structs.Vector[ring.Poly], 2)
		for j := range TildeD[i] {
			TildeD[i][j] = sampler.ReadNew()
		}
	}

	MACKey := []byte("test-mac-key-32-bytes-long------")
	partyID := 1
	sid := 1
	T := []int{1, 2, 3}
	otherParty := 2

	// Test generation mode
	mac := GenerateMAC(TildeD, MACKey, partyID, sid, T, otherParty, false)
	if len(mac) != 32 {
		t.Errorf("GenerateMAC() returned %d bytes, want 32", len(mac))
	}

	// Test verification mode
	macVerify := GenerateMAC(TildeD, MACKey, partyID, sid, T, otherParty, true)
	if len(macVerify) != 32 {
		t.Errorf("GenerateMAC() in verify mode returned %d bytes, want 32", len(macVerify))
	}
}

func TestGaussianHash(t *testing.T) {
	r, err := ring.NewRing(256, []uint64{8380417})
	if err != nil {
		t.Fatal(err)
	}

	hash := []byte("test-hash-32-bytes-long---------")
	mu := "test-message"
	sigmaU := 1.0
	boundU := 6.0
	length := 5

	result := GaussianHash(r, hash, mu, sigmaU, boundU, length)

	if len(result) != length {
		t.Errorf("GaussianHash() returned %d elements, want %d", len(result), length)
	}

	// Verify deterministic
	result2 := GaussianHash(r, hash, mu, sigmaU, boundU, length)
	for i := range result {
		if !r.Equal(result[i], result2[i]) {
			t.Error("GaussianHash() is not deterministic")
			break
		}
	}
}

func TestPRF(t *testing.T) {
	r, err := ring.NewRing(256, []uint64{8380417})
	if err != nil {
		t.Fatal(err)
	}

	sd_ij := []byte("seed-data")
	PRFKey := []byte("prf-key-32-bytes-long-----------")
	mu := "message"
	hash := []byte("hash-data")
	n := 5

	result := PRF(r, sd_ij, PRFKey, mu, hash, n)

	if len(result) != n {
		t.Errorf("PRF() returned %d elements, want %d", len(result), n)
	}

	// Verify deterministic
	result2 := PRF(r, sd_ij, PRFKey, mu, hash, n)
	for i := range result {
		if !r.Equal(result[i], result2[i]) {
			t.Error("PRF() is not deterministic")
			break
		}
	}
}

func TestHash(t *testing.T) {
	r, err := ring.NewRing(256, []uint64{8380417})
	if err != nil {
		t.Fatal(err)
	}

	prng, _ := sampling.NewPRNG()
	sampler := ring.NewUniformSampler(prng, r)

	// Create test inputs
	A := make(structs.Matrix[ring.Poly], 2)
	for i := range A {
		A[i] = make(structs.Vector[ring.Poly], 2)
		for j := range A[i] {
			A[i][j] = sampler.ReadNew()
		}
	}

	b := make(structs.Vector[ring.Poly], 2)
	for i := range b {
		b[i] = sampler.ReadNew()
	}

	D := make(map[int]structs.Matrix[ring.Poly])
	for k := 0; k < 2; k++ {
		D[k] = make(structs.Matrix[ring.Poly], 2)
		for i := range D[k] {
			D[k][i] = make(structs.Vector[ring.Poly], 2)
			for j := range D[k][i] {
				D[k][i][j] = sampler.ReadNew()
			}
		}
	}

	sid := 1
	T := []int{1, 2}

	result := Hash(A, b, D, sid, T)

	if len(result) != 32 {
		t.Errorf("Hash() returned %d bytes, want 32", len(result))
	}

	// Verify deterministic
	result2 := Hash(A, b, D, sid, T)
	for i := range result {
		if result[i] != result2[i] {
			t.Error("Hash() is not deterministic")
			break
		}
	}
}

func TestLowNormHash(t *testing.T) {
	r, err := ring.NewRing(256, []uint64{8380417})
	if err != nil {
		t.Fatal(err)
	}

	prng, _ := sampling.NewPRNG()
	sampler := ring.NewUniformSampler(prng, r)

	// Create test inputs
	A := make(structs.Matrix[ring.Poly], 2)
	for i := range A {
		A[i] = make(structs.Vector[ring.Poly], 2)
		for j := range A[i] {
			A[i][j] = sampler.ReadNew()
		}
	}

	b := make(structs.Vector[ring.Poly], 2)
	for i := range b {
		b[i] = sampler.ReadNew()
	}

	h := make(structs.Vector[ring.Poly], 2)
	for i := range h {
		h[i] = sampler.ReadNew()
	}

	mu := "message"
	kappa := 10

	result := LowNormHash(r, A, b, h, mu, kappa)

	if result.N() == 0 {
		t.Error("LowNormHash() returned invalid polynomial")
	}

	// Verify deterministic
	result2 := LowNormHash(r, A, b, h, mu, kappa)
	if !r.Equal(result, result2) {
		t.Error("LowNormHash() is not deterministic")
	}
}

func TestGenerateRandomSeed(t *testing.T) {
	// Initialize precomputed randomness for the test
	testKey := []byte("test-key-for-randomness-generation")
	utils.PrecomputeRandomness(1024, testKey) // Precompute enough randomness for the test

	seed := GenerateRandomSeed()

	if len(seed) != 32 {
		t.Errorf("GenerateRandomSeed() returned %d bytes, want 32", len(seed))
	}

	// Verify randomness (two calls should produce different results)
	seed2 := GenerateRandomSeed()
	same := true
	for i := range seed {
		if seed[i] != seed2[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("GenerateRandomSeed() appears to be deterministic")
	}
}
