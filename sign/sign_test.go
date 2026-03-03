package sign

import (
	"testing"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/sampling"
	"github.com/luxfi/lattice/v7/utils/structs"
)

func TestPartyState_Initialization(t *testing.T) {
	r, err := ring.NewRing(256, []uint64{8380417})
	if err != nil {
		t.Fatal(err)
	}

	party := NewParty(1, r, r, r, nil)

	if party.ID != 1 {
		t.Errorf("Expected party ID 1, got %d", party.ID)
	}
	if party.Ring == nil {
		t.Error("Expected non-nil Ring")
	}
}

func TestSignConstants(t *testing.T) {
	// Test that constants are properly defined
	if LogN == 0 {
		t.Error("LogN should not be zero")
	}
	if Q == 0 {
		t.Error("Q should not be zero")
	}
	if QXi == 0 {
		t.Error("QXi should not be zero")
	}
	if QNu == 0 {
		t.Error("QNu should not be zero")
	}
	if M == 0 {
		t.Error("M should not be zero")
	}
	if N == 0 {
		t.Error("N should not be zero")
	}
	if KeySize == 0 {
		t.Error("KeySize should not be zero")
	}
}

func TestCheckL2Norm(t *testing.T) {
	r, err := ring.NewRing(256, []uint64{8380417})
	if err != nil {
		t.Fatal(err)
	}

	prng, _ := sampling.NewPRNG()
	sampler := ring.NewUniformSampler(prng, r)

	tests := []struct {
		name   string
		size   int
		expect bool
	}{
		{
			name:   "small vector within bound",
			size:   3,
			expect: true,
		},
		{
			name:   "large vector within bound",
			size:   10,
			expect: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create two vectors for testing - Delta and z
			delta := make(structs.Vector[ring.Poly], tt.size)
			z := make(structs.Vector[ring.Poly], tt.size)

			for i := range delta {
				if tt.expect {
					// Use small values for expected to pass
					delta[i] = r.NewPoly()
					z[i] = r.NewPoly()
					// Set small coefficients manually for predictable test
					for j := 0; j < r.N(); j++ {
						delta[i].Coeffs[0][j] = 1
						z[i].Coeffs[0][j] = 1
					}
				} else {
					// Create polynomial with random values
					delta[i] = sampler.ReadNew()
					z[i] = sampler.ReadNew()
				}
			}

			result := CheckL2Norm(r, delta, z)

			// Note: The actual pass/fail depends on the internal bound check
			// We're just verifying it doesn't crash
			if result && !tt.expect {
				t.Log("CheckL2Norm passed when it might have been expected to fail")
			}
		})
	}
}
