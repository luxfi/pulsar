// Package pulsarm is the reference implementation of Pulsar-M, a threshold
// implementation of NIST FIPS 204 ML-DSA targeting NIST MPTC Class N1
// (signing) + N4 (ML keygen / DKG).
//
// The headline claim of Pulsar-M is output interchangeability with FIPS 204:
// a signature produced by an n-of-t threshold ceremony verifies under
// unmodified FIPS 204 ML-DSA.Verify(pk, message, signature). See
// docs/nist-mptc-category.md for the formal claim and its scope.
//
// Status: pre-spec-freeze. The exported API in this package will change
// up to the spec encoding freeze (target end of August 2026). After
// freeze the API is fixed and a v0.1 tag will be cut.
//
// All cryptographic operations route through:
//
//   - sub-package "hash"        — NIST SP 800-185 (cSHAKE256/KMAC256/TupleHash256) only
//   - sub-package "primitives"  — Module-LWE polynomial-vector arithmetic
//   - sub-package "sign"        — two-round threshold sign protocol
//   - sub-package "dkg"         — Pedersen DKG over R_q^k
//   - sub-package "reshare"     — proactive resharing with beacon-randomized quorum
//   - sub-package "fmt"         — wire encoding / KAT format
//
// All logging — including for any error path — uses github.com/luxfi/log.
// The standard library's log package is forbidden in this module: a
// secret-correlated value reaching stdout is a side channel even at debug
// level (HIP-0077 red review F8). This is enforced by a CI lint, not just
// convention.
package pulsarm

// Version is the spec version this implementation targets.
const Version = "0.0.0-spec-draft"
