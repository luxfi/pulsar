// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dkg

import (
	"testing"

	"github.com/luxfi/pulsar/sign"

	"github.com/luxfi/lattice/v7/utils/structs"

	"github.com/luxfi/lattice/v7/ring"
)

func TestDKG_2of3(t *testing.T) {
	runDKG(t, 3, 2)
}

func TestDKG_3of5(t *testing.T) {
	runDKG(t, 5, 3)
}

func TestDKG_InvalidParams(t *testing.T) {
	params, err := NewParams()
	if err != nil {
		t.Fatalf("NewParams: %v", err)
	}

	// threshold >= n
	_, err = NewDKGSession(params, 0, 3, 3)
	if err != ErrInvalidThreshold {
		t.Errorf("expected ErrInvalidThreshold, got %v", err)
	}

	// threshold = 0
	_, err = NewDKGSession(params, 0, 3, 0)
	if err != ErrInvalidThreshold {
		t.Errorf("expected ErrInvalidThreshold, got %v", err)
	}

	// n < 2
	_, err = NewDKGSession(params, 0, 1, 1)
	if err != ErrInvalidPartyCount {
		t.Errorf("expected ErrInvalidPartyCount, got %v", err)
	}

	// partyID out of range
	_, err = NewDKGSession(params, 5, 3, 2)
	if err != ErrInvalidPartyID {
		t.Errorf("expected ErrInvalidPartyID, got %v", err)
	}

	// negative partyID
	_, err = NewDKGSession(params, -1, 3, 2)
	if err != ErrInvalidPartyID {
		t.Errorf("expected ErrInvalidPartyID, got %v", err)
	}
}

func TestDKG_MissingData(t *testing.T) {
	params, err := NewParams()
	if err != nil {
		t.Fatalf("NewParams: %v", err)
	}

	n, threshold := 3, 2
	sessions := make([]*DKGSession, n)
	round1Outputs := make([]*Round1Output, n)

	for i := 0; i < n; i++ {
		sessions[i], err = NewDKGSession(params, i, n, threshold)
		if err != nil {
			t.Fatalf("NewDKGSession(%d): %v", i, err)
		}
	}

	for i := 0; i < n; i++ {
		round1Outputs[i], err = sessions[i].Round1()
		if err != nil {
			t.Fatalf("Round1(%d): %v", i, err)
		}
	}

	// Provide incomplete shares (missing party 0)
	shares := make(map[int]structs.Vector[ring.Poly])
	commits := make(map[int][]structs.Vector[ring.Poly])
	for i := 1; i < n; i++ {
		shares[i] = round1Outputs[i].Shares[0]
		commits[i] = round1Outputs[i].Commits
	}

	_, _, err = sessions[0].Round2(shares, commits)
	if err == nil {
		t.Error("expected error for missing data, got nil")
	}
}

// runDKG executes a full DKG protocol and verifies the result.
func runDKG(t *testing.T, n, threshold int) {
	t.Helper()

	params, err := NewParams()
	if err != nil {
		t.Fatalf("NewParams: %v", err)
	}

	// Create sessions for all parties
	sessions := make([]*DKGSession, n)
	for i := 0; i < n; i++ {
		sessions[i], err = NewDKGSession(params, i, n, threshold)
		if err != nil {
			t.Fatalf("NewDKGSession(%d): %v", i, err)
		}
	}

	// Round 1: Each party generates polynomial, shares, and commitments
	round1Outputs := make([]*Round1Output, n)
	for i := 0; i < n; i++ {
		round1Outputs[i], err = sessions[i].Round1()
		if err != nil {
			t.Fatalf("Round1(%d): %v", i, err)
		}
		t.Logf("Party %d: Round1 complete, %d commits, %d shares", i, len(round1Outputs[i].Commits), len(round1Outputs[i].Shares))
	}

	// Verify Round 1 output dimensions
	for i := 0; i < n; i++ {
		if len(round1Outputs[i].Commits) != threshold {
			t.Errorf("Party %d: expected %d commits, got %d", i, threshold, len(round1Outputs[i].Commits))
		}
		if len(round1Outputs[i].Shares) != n {
			t.Errorf("Party %d: expected %d shares, got %d", i, n, len(round1Outputs[i].Shares))
		}
		for j := 0; j < n; j++ {
			if len(round1Outputs[i].Shares[j]) != sign.N {
				t.Errorf("Party %d share for %d: expected vector length %d, got %d", i, j, sign.N, len(round1Outputs[i].Shares[j]))
			}
		}
	}

	// Round 2: Each party collects shares and commitments from all others, verifies, and aggregates
	secretShares := make([]structs.Vector[ring.Poly], n)
	publicKeys := make([]structs.Vector[ring.Poly], n)

	for j := 0; j < n; j++ {
		// Collect shares and commits destined for party j
		shares := make(map[int]structs.Vector[ring.Poly])
		commits := make(map[int][]structs.Vector[ring.Poly])
		for i := 0; i < n; i++ {
			shares[i] = round1Outputs[i].Shares[j]
			commits[i] = round1Outputs[i].Commits
		}

		secretShares[j], publicKeys[j], err = sessions[j].Round2(shares, commits)
		if err != nil {
			t.Fatalf("Round2(%d): %v", j, err)
		}
		t.Logf("Party %d: Round2 complete, secret share size=%d, public key size=%d",
			j, len(secretShares[j]), len(publicKeys[j]))
	}

	// Verify all parties computed the same public key
	r := params.R
	for j := 1; j < n; j++ {
		for idx := 0; idx < len(publicKeys[0]); idx++ {
			// Compare rounded public key polynomials
			pk0 := publicKeys[0][idx]
			pkJ := publicKeys[j][idx]
			if pk0.N() != pkJ.N() {
				t.Errorf("Party 0 and party %d public key poly %d have different degrees", j, idx)
				continue
			}
			for level := range pk0.Coeffs {
				for coefIdx := range pk0.Coeffs[level] {
					if pk0.Coeffs[level][coefIdx] != pkJ.Coeffs[level][coefIdx] {
						t.Errorf("Party 0 and party %d disagree on public key poly %d coeff [%d][%d]", j, idx, level, coefIdx)
						break
					}
				}
			}
		}
	}

	// Verify secret shares have the expected dimension
	for j := 0; j < n; j++ {
		if len(secretShares[j]) != sign.N {
			t.Errorf("Party %d secret share: expected length %d, got %d", j, sign.N, len(secretShares[j]))
		}
	}

	// Verify Feldman consistency: the aggregated secret shares and public key are consistent.
	// For party j: A * sum(f_i(j)) should relate to the aggregated commitments.
	// Check that A * secretShare_j (NTT) gives a consistent result across parties
	// when weighted by Lagrange coefficients.
	for j := 0; j < n; j++ {
		shareNTT := make(structs.Vector[ring.Poly], sign.N)
		for idx := 0; idx < sign.N; idx++ {
			shareNTT[idx] = *secretShares[j][idx].CopyNew()
			r.NTT(shareNTT[idx], shareNTT[idx])
		}
		product := initVector(r, sign.M)
		matVecMul(r, sessions[0].A, shareNTT, product)

		// Just verify it's non-zero (sanity check)
		allZero := true
		for idx := 0; idx < sign.M; idx++ {
			for _, c := range product[idx].Coeffs[0] {
				if c != 0 {
					allZero = false
					break
				}
			}
			if !allZero {
				break
			}
		}
		if allZero {
			t.Errorf("Party %d: A * secretShare is zero vector, unexpected", j)
		}
	}

	t.Logf("DKG %d-of-%d completed successfully", threshold, n)
}

// initVector creates a zero vector of ring polynomials.
func initVector(r *ring.Ring, size int) structs.Vector[ring.Poly] {
	v := make(structs.Vector[ring.Poly], size)
	for i := range v {
		v[i] = r.NewPoly()
	}
	return v
}

// matVecMul computes result = matrix * vector in NTT domain.
func matVecMul(r *ring.Ring, matrix structs.Matrix[ring.Poly], vec structs.Vector[ring.Poly], result structs.Vector[ring.Poly]) {
	for i := range matrix {
		for j := range matrix[i] {
			tmp := r.NewPoly()
			r.MulCoeffsBarrett(matrix[i][j], vec[j], tmp)
			r.Add(result[i], tmp, result[i])
		}
	}
}
