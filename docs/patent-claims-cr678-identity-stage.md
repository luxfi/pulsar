# CR-6/7/8 Closure (Identity-Stage Authenticated DKG) — Patent Claim Drafts (Attorney Review)

> **Internal working document.** Bundle #13 of the Lux PATENT-INVENTORY.
> Not a filed application; not a legal opinion.

## §0 Bundle summary

- **Title**: Identity-stage authenticated distributed key generation
  with long-term ML-DSA-65 identity keys + ML-KEM-768 envelope wrap
  + per-pair session keys derived from HKDF over authenticated key
  agreement, closing the CR-6 vacuous-commit, CR-7 ephemeral-session,
  and CR-8 KEM-wrapped-envelope concerns simultaneously.
- **Inventors**: Lux Industries cryptography team.
- **Priority date**: file as US provisional within 12 months.
- **Estimated claim count**: 12 (1 independent + 11 dependent).
- **Defensive-vs-offensive**: **Offensive.**
- **Note**: this bundle EXTENDS Pulsar's existing 21 claims at
  `patent-claims.md`; it does NOT replace them. The bundle adds
  the identity-stage architecture as a separate inventive concept.

## §1 Background and prior art

1. **GG18 / GG20 / CGGMP21** (Gennaro-Goldfeder et al.): threshold
   ECDSA DKG without identity stage; participants are assumed
   pre-authenticated.
2. **FROST RFC 9591** (Komlo-Goldberg): threshold Schnorr DKG; same.
3. **Pulsar v0.1** (early Lux work): used plain envelopes
   without KEM wrap, vulnerable to CR-7 (replay) and CR-8 (no
   confidentiality between dealers and recipients).
4. **TLS 1.3 + ML-KEM-768 hybrid** (RFC 8446 + ML-KEM): public-
   internet-grade PQ transport, not DKG-specific.
5. **Krawczyk 2003 "SIGMA"** (CRYPTO 2003): signed Diffie-Hellman
   handshake with identity stage.

Closest prior art is [5] SIGMA. Lux's contribution applies the
SIGMA pattern to threshold-DKG envelopes using PQ primitives
(ML-DSA-65 identity + ML-KEM-768 envelope wrap), and closes
three specific cryptographic-review (CR) concerns:

- **CR-6**: a vacuous commit existed in Pulsar v0.1's DKG output
  that did not bind any per-party state. Removed.
- **CR-7**: ephemeral session keys are derived per-pair via HKDF
  over (long-term-identity-pair, session-context, ML-KEM-shared-
  secret). Replay of a session envelope under a fresh session is
  rejected.
- **CR-8**: every DKG Round-1 envelope is wrapped under
  ML-KEM-768 with the recipient's long-term public key,
  encrypting (share || contribution) such that only the
  recipient can decrypt.

## §2 Inventive concept

Each validator maintains:

```
LongTermIdentity := struct {
    MLDSA65Pub  // long-term identity signature scheme
    MLKEM768Pub // long-term recipient KEM key
}
```

For DKG ceremony:

1. **Identity stage**: each pair of validators
   `(dealer, recipient)` derives a per-pair session key via
   `HKDF-SHA3(IK_pair) → SK_pair` where
   `IK_pair = MLKEM_Decap(receiver_sk, MLKEM_Encap(sender_pk))`
   PLUS authenticated by ML-DSA-65 signatures over the
   handshake transcript.

2. **DKG Round-1**: dealer broadcasts one envelope per recipient
   carrying `(share || contribution)` ENCRYPTED under `SK_pair`
   via AEAD (e.g., ChaCha20-Poly1305 with `SK_pair`-derived
   nonce). The envelope is ML-DSA-65-signed by the dealer over
   the encrypted payload + transcript binding.

3. **DKG Round-2 / Round-3**: standard Pulsar Pedersen DKG over
   the now-decrypted shares.

4. **Anti-replay**: per-pair session keys are derived per
   `(epoch, session-id)`, so a session envelope from a previous
   session cannot be replayed under a new session.

5. **No vacuous commit**: the only commit on the wire is the
   ML-DSA signature over a non-empty, fully-bound transcript.

## §3 Independent claim (draft)

> **Claim 1.** A computer-implemented method for authenticated
> distributed key generation among a plurality of blockchain-
> consensus participants, the method comprising:
>
> (a) provisioning each participant with a long-term identity
>     keypair comprising (i) an FIPS 204 ML-DSA-65 identity
>     signature keypair, and (ii) an FIPS 203 ML-KEM-768 recipient
>     key-encapsulation keypair;
>
> (b) at the start of a distributed-key-generation session,
>     deriving for each unordered pair of participants `(P_i,
>     P_j)` a per-pair session key `SK_pair^{(i,j),sess}` via:
>
>     (b1) an ML-KEM-768 encapsulation by one of the pair against
>          the other's long-term recipient public key, producing a
>          shared secret `ss_pair`;
>
>     (b2) an ML-DSA-65 mutual authentication step in which each
>          participant signs the handshake transcript (including
>          `ss_pair`'s ciphertext and the session identifier) and
>          the signatures are mutually verified before `SK_pair`
>          is admitted; and
>
>     (b3) deriving `SK_pair^{(i,j),sess} = HKDF(salt=session-
>          identifier || epoch, ikm=ss_pair, info=`lux-dkg-
>          pair-v1`)`;
>
> (c) in distributed-key-generation Round-1, each dealer
>     broadcasting, for each intended recipient, an envelope
>     comprising:
>
>     (c1) an ENCRYPTED payload `Enc(SK_pair^{(dealer,recipient),
>          sess}, share || contribution)` using a length-stable
>          authenticated-encryption-with-associated-data scheme
>          (e.g., ChaCha20-Poly1305 or AES-256-GCM) with the
>          per-pair session key and a session-derived nonce;
>
>     (c2) the AEAD authentication tag over the encrypted payload
>          and the session identifier;
>
>     (c3) an ML-DSA-65 signature by the dealer over the
>          encrypted payload plus the session identifier plus the
>          recipient's long-term public-key hash, providing
>          dealer-side identity authentication;
>
> (d) at each recipient:
>
>     (d1) verifying the ML-DSA-65 dealer signature against the
>          dealer's long-term identity public key recorded in the
>          chain state;
>
>     (d2) decrypting the AEAD payload using `SK_pair^{(dealer,
>          recipient),sess}` to recover `(share, contribution)`;
>
>     (d3) refusing to proceed with the DKG round if the AEAD tag
>          verification fails or the ML-DSA-65 signature
>          verification fails; and
>
> (e) executing subsequent DKG rounds (Round-2 commitment,
>     Round-3 verification) over the now-decrypted shares using
>     the underlying Pulsar Pedersen-VSS protocol.

## §4 Dependent claims (drafts)

**Claim 2.** The method of claim 1, wherein the long-term
identity keypairs of step (a) are bound into the chain's
validator-set Merkle root and are immutable for the lifetime of
the validator's membership, with key-rotation requiring a
governance-gated validator-set update.

**Claim 3.** The method of claim 1, wherein the per-pair session
key derivation of step (b) uses HKDF-SHA3 (HKDF instantiated with
SHA3-256 or KMAC256), providing post-quantum-secure key
derivation.

**Claim 4.** The method of claim 1, wherein the
session-identifier of step (b3) is the concatenation of the chain
identifier, the epoch counter, and a 32-byte random session salt
agreed by the DKG ceremony's coordinator, providing per-session
uniqueness even if the same pair of participants runs multiple
DKG ceremonies.

**Claim 5.** The method of claim 1, wherein the AEAD scheme of
step (c1) is ChaCha20-Poly1305 with a 96-bit nonce derived from
the session identifier and a per-envelope counter.

**Claim 6.** The method of claim 1, wherein the ML-KEM-768
encapsulation of step (b1) is performed in the directed `(P_i
→ P_j)` direction, with one participant designated the
encapsulator and the other the decapsulator, the designation
determined by lexicographic ordering of the pair's identity
public keys.

**Claim 7.** The method of claim 1, wherein the DKG ceremony is
the Pulsar Pedersen DKG (dkg2) for FIPS 204 ML-DSA-65 threshold
signing.

**Claim 8.** The method of claim 1, wherein the closure of three
distinct cryptographic-review concerns is achieved by the same
identity-stage architecture:
- a vacuous-commit concern is closed by removing all per-party
  commits not bound to non-empty transcript bytes;
- an ephemeral-session-key concern is closed by per-session
  HKDF derivation from `(epoch, session-id, KEM-shared-secret)`;
- a KEM-wrapped-envelope concern is closed by AEAD encryption of
  every Round-1 envelope under the per-pair session key.

**Claim 9.** The method of claim 1, wherein replay of a
previous-session envelope is detected by AEAD-tag mismatch under
the fresh session key, providing cryptographic (not just
protocol-level) replay resistance.

**Claim 10.** The method of claim 1, wherein the long-term
identity public keys are published in a chain-state Merkle tree
indexed by validator NodeID, and the per-pair session key
derivation reads the recipient's public key from the chain
state, providing on-chain validator-identity authentication.

**Claim 11.** The method of claim 1, wherein the same identity-
stage architecture is also used for the per-validator-pair Lumen
stream (a PQ end-to-end encrypted transport layer between
validators), with the per-pair session key reused across the
DKG ceremony and the Lumen stream key schedule.

**Claim 12.** A non-transitory computer-readable medium storing
the Go source code of the identity-stage DKG protocol, the
per-pair session key derivation, and the AEAD envelope
construction, including the dkg2 Pedersen DKG that consumes the
decrypted shares.

## §5 Reference to implementation

- `~/work/lux/pulsar/dkg2/` (Pedersen DKG with KEM-wrapped envelopes).
- `~/work/lux/pulsar/keyera/` (per-pair session-key derivation).
- Cross-references: `~/work/lux/pulsar/SUBMISSION.md`,
  `~/work/lux/pulsar/CRYPTOGRAPHER-SIGN-OFF.md` §"CR-6/7/8 closure".

## §6 Defensive vs offensive

**OFFENSIVE.** The SIGMA-pattern application to PQ-DKG envelopes
with ML-DSA-65 + ML-KEM-768 identity stage is a meaningful
strengthening of FROST / Pulsar baseline DKG security.

---

**Document metadata**
- Path: `pulsar/docs/patent-claims-cr678-identity-stage.md`
- Bundle: #13 of `lps/PATENT-INVENTORY.md`
- Created: 2026-05-19
