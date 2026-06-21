# Reviewer Questions

1. Does any production transcript reveal `w`, `LowBits(w)`, `c·s2`, `c·t0`, `r0`, or
   residual equivalents?
2. Is the NonceTranscript validator-MPC malicious-secure at the stated `t−1` threshold,
   and does it output only `W1 + clear bit + transcript root`?
3. Is `W1 = HighBits(w)` computed correctly without revealing `w`?
4. Does `BoundaryClear(w, 2β + slack)` imply the hidden `r0` bound for all valid `c,s2`?
   (ML-DSA-65/87 only; confirm `‖c·t0‖ < γ2`.)
5. Is `FindHint` exactly equivalent to the FIPS 204 `UseHint` verifier relation?
6. Does `PartialProof` soundly prove `z_i = λ_i·y_i + c·λ_i·s1_i` without leaking
   `y_i`/`s1_i`/`s2_i`/`t0_i`?
7. Is canonical nonce selection non-grindable after the block/message is observed?
8. Are rejected attempts simulatable (no secret-dependent failure predicate)?
9. Does tree aggregation preserve signer accountability and reject malformed partials?
10. Do ≥2 independent FIPS 204 ML-DSA verifiers accept all produced signatures?
