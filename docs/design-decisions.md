# Design decisions log

Each entry: decision, rationale, alternatives, status, date.

## DD-001 Target FIPS 204 output interchangeability (Class N)

**Decision.** Pulsar-M aims for Class N1 + N4 (NIST MPTC IR 8214C):
threshold-produced signatures verify under unmodified FIPS 204
ML-DSA.Verify.

**Rationale.** Output interchangeability gives the strongest NIST
positioning. FIPS-validated ML-DSA modules in 2026 (BoringSSL FIPS,
AWS-LC, OpenSSL 3.0) consume Pulsar-M certs without code changes. This
is the headline pitch for MPTC.

**Alternative.** Class S (special threshold-friendly primitive). Easier
spec, but does not give the FIPS-module-compatibility win. Pulsar
(R-LWE) takes this path.

**Status.** Targeted. Final class decision deferred until reference impl
demonstrates byte-equal output on at least one parameter set.

## DD-002 Hash family: SHA-3 (cSHAKE256 / KMAC256 / TupleHash256) only

**Decision.** Pulsar-M's NIST profile uses exclusively the FIPS 202 + SP
800-185 hash family. No BLAKE3.

**Rationale.** NIST MPTC §4.6 lists allowed symmetric primitives for
Class N: AES, Ascon, SHA-2, SHA-3, SHAKE/cSHAKE, HMAC/KMAC/CMAC/GMAC.
BLAKE3 is not on the list. Including BLAKE3 in the NIST submission
profile is a strategic liability.

The same SHAKE-256 sponge is used internally by ML-DSA-65 (FIPS 204
§5.1). Sharing the hash family with the underlying primitive removes a
whole class of cryptanalytic concern (cross-domain collisions, mixed
hash-family soundness arguments).

**Alternative considered.** Dual-suite with BLAKE3 as the production
profile and SHA-3 as the NIST profile, like Pulsar's current dual-suite.
Rejected because Pulsar-M is NIST-track and shouldn't ship a non-NIST
default.

**Status.** Final.

## DD-003 Lattice: Module-LWE per FIPS 204, not Ring-LWE

**Decision.** Pulsar-M operates over `R_q^k` (module of polynomials)
with the same `(q, k, ℓ, η, β, ω, ...)` parameter set as ML-DSA-65.
Not `R_q` (single polynomial) as Pulsar / Ringtail use.

**Rationale.** This is the whole point of the project. Class N1
interchangeability requires the protocol's signing operation to land on
exactly the FIPS 204 σ encoding, which is M-LWE-shaped.

**Alternative.** Stay R-LWE. Easier (we already have Pulsar). But then
we lose the Class N positioning and become Class S like Pulsar.

**Status.** Final.

## DD-004 Reference implementation language: Go

**Decision.** Reference implementation is Go (`ref/go/`). C
implementation comes after spec encodings freeze (`ref/c/`).

**Rationale.** Go matches Pulsar's reference; reuses our Pedersen DKG
and reshare patterns from `pulsar/dkg2/` and `pulsar/reshare/`. Clear,
boring, no assembly. NIST MPTC §4.3 doesn't mandate language.

**Alternative.** C reference first. Standard NIST PQC submission style.
Rejected for round 1 because we need to ship by 2026-Nov-16; Go is
faster to write and review. C reference becomes a follow-on artifact
for round 2 review.

**Status.** Final for MPTC round 1.

## DD-005 DKG: Pedersen-style over `R_q^k`

**Decision.** Distributed keygen uses Pedersen DKG over the M-LWE module
ring, with Feldman-style verifiable secret sharing replaced by the
module-shaped Pedersen commitment scheme.

**Rationale.** Pulsar's `dkg2/` package already does this for `R_q`
(R-LWE). The M-LWE port preserves the soundness argument with constant
overhead per coefficient slot.

**Alternative.** Trusted-dealer DKG (academic Ringtail). Rejected:
incompatible with open public chains (HIP-0077 §"Pulsar vs Ringtail").

**Status.** Final.

## DD-006 Proactive resharing: HJKY97-style with beacon-randomized quorum

**Decision.** Long-lived deployments use proactive secret resharing with
a beacon-derived per-reshare quorum selection (not deterministic
smallest-ID).

**Rationale.** Deterministic quorum selection (Pulsar's current
`reshare.go:206-209`) lets a mobile adversary game the corrupt-set
positioning. HIP-0077 red review F10 flagged this. Pulsar-M's reshare
selects via the chain's randomness beacon at the reshare epoch boundary.

**Alternative.** Deterministic quorum, accept the leakage as a documented
limitation. Rejected for MPTC submission.

**Status.** Final.

## DD-007 No application-level logging in secret-touching code paths

**Decision.** Secret-touching functions (Sign, Verify-of-shares, DKG
verification, reshare verification) emit zero log lines. Constant-time
analysis treats any log call as a failed gate.

**Rationale.** Pulsar's pre-fix `log.Println(Bsquare, sumSquares)` in
`sign.go` (HIP-0077 red F8) is exactly the failure mode this rule
prevents. A logged value derived from secret state is a side channel
even at debug level.

**Alternative.** Allow debug logging gated by build tag. Rejected:
build tags get accidentally enabled in production; the rule is
absolute.

**Status.** Final. CI gate: `go vet -vettool=...` plus a custom linter
that rejects `log.*`, `fmt.Print*`, `panic` in `pkg/sign/`, `pkg/dkg/`,
`pkg/reshare/`.

## DD-008 Encoding freeze before C reference

**Decision.** Reference Go locks every byte of the wire encoding before
the C reference begins. Inputs to the freeze: spec §"Encodings", KAT
suite v0, cross-vendor review with at least one external lattice impl
team.

**Rationale.** Two implementations diverging on encoding is a recurring
source of NIST PQC submission rejections. Freeze first, port second.

**Status.** Targeted for end of August 2026.

## DD-009 Patent claims: prepared in advance

**Decision.** Patent-claim disclosures collected in
`docs/patent-notes-draft.md` from day 1 of the repo. Every contribution
adds the contributor's patent-claim notice (or explicit "no claims").

**Rationale.** NIST MPTC §6 requires Notes on Patent Claims as a package
deliverable. Late collection blows up the submission timeline.

**Status.** In progress.

## DD-010 Two-track NIST plan: MPTC now, CMVP later

**Decision.** Track A targets MPTC submission 2026-Nov-16. Track B
prepares for eventual NIST PQC standardization + CMVP module
validation, which is a multi-year process not scheduled.

**Rationale.** MPTC is the active NIST process for threshold schemes
right now. CMVP requires an approved standard, which threshold schemes
don't yet have. We can prepare a clean module boundary for future CMVP
work without waiting for the standard.

**Status.** Track A active. Track B is a parallel readiness exercise,
not a near-term gate.
