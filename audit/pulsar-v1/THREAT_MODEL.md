# Threat Model

- **Setting:** public, permissionless, leaderless BFT consensus. Any validator may
  aggregate; there is no trusted combiner.
- **Adversary:** static corruption of up to `t−1` of the active committee, including
  the coordinator/aggregator role. Sees all broadcasts and the public chain.
- **Goal of the adversary:** recover long-term key material (`s1,s2,t0`), forge, or
  grind the nonce/challenge.
- **Trust:** the validator set (quorum) is the MPC party set for DKG and the
  NonceTranscript. A dishonest quorum is already a consensus-Byzantine break.
- **Leakage targets (must be hidden from a `t−1` coalition AND the public chain):**
  `w`, `LowBits(w)`, `c·s2`, `c·t0`, `r0`, `LowBits(w + c·t0 − c·s2)`, `y_i`, `s1_i`,
  `s2_i`, `t0_i`.
- **Public (allowed):** `w1 = HighBits(w)`, commitments, QCs, `z`, the final ML-DSA
  signature `(c,z,h)`, signer bitmap, transcript roots.
