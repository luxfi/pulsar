# Pulsar V1 — External Review Package

Pulsar is a threshold protocol that emits **ordinary FIPS 204 ML-DSA signatures**.
It does not propose a new verifier-facing signature format. Its security claim is
threshold unforgeability, transcript privacy, and public consensus accountability
under a validator-run nonce transcript and proof-carrying partial protocol.

## Status (honest)

- **Contained + math-verified + production-shaped.** NOT yet production/NIST-ready.
- The legacy `AlgebraicAggregate` path leaked `c·s2`/`c·t0` (see `KNOWN_BAD_V03.md`)
  and is **hard-disabled** (fails closed).
- The replacement (boundary-cleared nonce transcripts + public hint recovery) has a
  **verified arithmetic core** (boundary clearance, FindHint↔UseHint, yield ≈9.8%) and
  a **production-shaped, fail-closed API** (NonceCert/Partial/ConsensusCert).
- **Not yet sound / pending this review:** the NonceTranscript validator-MPC security,
  the PartialProof soundness, the DKG well-formedness proof, independent-verifier
  interop on the production path, and a machine-checked boundary-clearance proof.

## Documents
- `SPEC.md` / `../../spec/threshold-mldsa-boundary-clearance.tex` — construction.
- `KNOWN_BAD_V03.md` — the contained leak (PULSAR-V13-HINT-LEAK + W-LEAK).
- `SECURITY_INVARIANTS.md` — the invariants reviewers must check.
- `THREAT_MODEL.md` — adversary, trust, leakage targets.
- `TEST_MATRIX.md` — what each test proves.
- `REPRO.md` — exact commands.
- `REVIEW_QUESTIONS.md` — the questions for reviewers.
