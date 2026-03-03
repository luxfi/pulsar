package primitives

import (
	"math/big"
	"testing"

	"github.com/luxfi/pulsar/utils"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/sampling"
	"github.com/luxfi/lattice/v7/utils/structs"
)

func TestComputeLagrangeCoefficients(t *testing.T) {
	r, err := ring.NewRing(256, []uint64{8380417})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		parties []int
		wantLen int
	}{
		{
			name:    "two parties",
			parties: []int{1, 2},
			wantLen: 2,
		},
		{
			name:    "three parties",
			parties: []int{1, 2, 3},
			wantLen: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			coeffs := ComputeLagrangeCoefficients(r, tt.parties, big.NewInt(8380417))

			if len(coeffs) != tt.wantLen {
				t.Errorf("ComputeLagrangeCoefficients() returned %d coefficients, want %d", len(coeffs), tt.wantLen)
			}

			// Verify coefficients are valid polynomials
			for i, coeff := range coeffs {
				if coeff.N() == 0 {
					t.Errorf("Lagrange coefficient %d has N=0", i)
				}
			}
		})
	}
}

func TestShamirSecretSharing(t *testing.T) {
	r, err := ring.NewRing(256, []uint64{8380417})
	if err != nil {
		t.Fatal(err)
	}

	// Initialize precomputed randomness for the test
	testKey := []byte("test-key-for-shamir-secret-sharing")
	utils.PrecomputeRandomness(100000, testKey) // Precompute enough randomness

	prng, _ := sampling.NewPRNG()
	sampler := ring.NewUniformSampler(prng, r)

	tests := []struct {
		name   string
		secret structs.Vector[ring.Poly]
		n      int
		k      int
	}{
		{
			name:   "2-of-2 sharing",
			secret: createTestSecret(r, sampler, 3),
			n:      2,
			k:      2,
		},
		{
			name:   "3-of-3 sharing",
			secret: createTestSecret(r, sampler, 3),
			n:      3,
			k:      3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create Lagrange coefficients for reconstruction
			parties := make([]int, tt.n)
			for i := range parties {
				parties[i] = i + 1
			}
			lagrangeCoeffs := ComputeLagrangeCoefficients(r, parties, big.NewInt(8380417))

			// Generate shares
			shares := ShamirSecretSharing(r, tt.secret, tt.n, lagrangeCoeffs)

			// Verify we got correct number of shares
			if len(shares) != tt.n {
				t.Errorf("ShamirSecretSharing() returned %d shares, want %d", len(shares), tt.n)
			}

			// Verify each share has correct dimensions
			for i, share := range shares {
				if len(share) != len(tt.secret) {
					t.Errorf("Share %d has length %d, want %d", i, len(share), len(tt.secret))
				}
				// Verify share polynomials are valid
				for j, poly := range share {
					if poly.N() == 0 {
						t.Errorf("Share %d, poly %d has N=0", i, j)
					}
				}
			}
		})
	}
}

func TestShamirSecretSharingGeneral(t *testing.T) {
	r, err := ring.NewRing(256, []uint64{8380417})
	if err != nil {
		t.Fatal(err)
	}

	// Initialize precomputed randomness for the test
	testKey := []byte("test-key-for-shamir-general")
	utils.PrecomputeRandomness(100000, testKey) // Precompute enough randomness

	prng, _ := sampling.NewPRNG()
	sampler := ring.NewUniformSampler(prng, r)

	tests := []struct {
		name   string
		secret structs.Vector[ring.Poly]
		t      int
		k      int
	}{
		{
			name:   "2-of-3 sharing",
			secret: createTestSecret(r, sampler, 3),
			t:      2,
			k:      3,
		},
		{
			name:   "3-of-5 sharing",
			secret: createTestSecret(r, sampler, 3),
			t:      3,
			k:      5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate shares
			shares := ShamirSecretSharingGeneral(r, tt.secret, tt.t, tt.k)

			// Verify we got correct number of shares
			if len(shares) != tt.k {
				t.Errorf("ShamirSecretSharingGeneral() returned %d shares, want %d", len(shares), tt.k)
			}

			// Verify each share has correct dimensions
			for i, share := range shares {
				if len(share) != len(tt.secret) {
					t.Errorf("Share %d has length %d, want %d", i, len(share), len(tt.secret))
				}
				// Verify share polynomials are valid
				for j, poly := range share {
					if poly.N() == 0 {
						t.Errorf("Share %d, poly %d has N=0", i, j)
					}
				}
			}
		})
	}
}

// Helper function to create test secrets
func createTestSecret(r *ring.Ring, sampler ring.Sampler, size int) structs.Vector[ring.Poly] {
	secret := make(structs.Vector[ring.Poly], size)
	for i := range secret {
		secret[i] = sampler.ReadNew()
	}
	return secret
}
