# KNOWN BAD PATH — PULSAR-V13-HINT-LEAK (CRITICAL, contained)

## The leak
The v0.3/v0.4 `AlgebraicAggregate` path (`ref/go/pkg/pulsar/threshold_v03.go`)
broadcast `CS2 = c·λ_i·s2_i` and `CT0 = c·λ_i·t0_i` **unmasked**, and the aggregator
reconstructed `c·s2_joint = c·s2_master`, `c·t0_joint = c·t0_master`. With public `c`
and `λ_i`, `s2_i = (c·λ_i)^{-1}·CS2`; and over varying public `c` the aggregate is a
linear system in the fixed master `s2`/`t0`. Leaderless ⇒ every quorum member
aggregates ⇒ every corrupt validator learns long-term secret-key material each round.
The in-code `(t-1)`-secret claim was false (it only covered the `y_i`-masked `z_i`).

## Why masking alone is insufficient (PULSAR-V13-W-LEAK)
Forming the byte-equal signature requires reconstructing `c·s2_joint`. Even with
masked individual shares, the aggregate is the master `c·s2`. And publishing full
`w = A·y` is equally fatal: with the public `w' = A·z − c·t1·2^d`,
`w' − w = c·t0 − c·s2`. So the protocol must never reconstruct `c·s2`/`c·t0`/`r0` and
must never publish full `w` — only `w1 = HighBits(w)`.

## Containment (landed)
`Round2Sign` fails closed with `ErrUnsafeThresholdV03HintPath` unless an explicit
test flag is set (`TestThresholdV03DisabledByDefault`). The replacement computes the
hint publicly from `(w', w1)` via FIPS `UseHint` (`FindHint`), and the nonce
boundary-clearance is certified by a validator quorum (NonceCert.ClearanceQC) without
opening `w`.
