# Flow Cryptography

This Go package provides the cryptography tools needed by the Flow blockchain.
The primitives and protocols can be used in other projects and are not specific to Flow.

Notes:
   - The package has been audited for security in January 2021 on [this version](https://github.com/onflow/crypto/tree/bc6bbd277994d5d50ca3b777bd6747f555629c18). The package had a major refactor to switch all the BLS12-381 curve implementation to use [BLST](https://github.com/supranational/blst/tree/master/src) starting from version `v0.25.0`. 
   - The package used to live under the [flow-go](https://github.com/onflow/flow-go) before being moved out as a separate repository while maintaining all the module Git history.
   - The package does not provide security against side channel or fault attacks.

## Package import

To use the Flow cryptography package:

- get the package 
```
go get github.com/onflow/crypto
```
- or simply import the package to your Go project
 ```
import "github.com/onflow/crypto"
```

## Algorithms

### Hashing and Message Authentication Code:

`crypto/hash` provides the hashing and MAC algorithms required for Flow. All algorithm implement the generic interface `Hasher`. All digests are of the generic type `Hash`.

 * SHA-3: 256 and 384 output sizes
 * Legacy Kaccak: 256 output size
 * SHA-2: 256 and 384 output sizes
 * KMAC: 128 variant

### Signature schemes

All signature schemes use the generic interfaces of `PrivateKey` and `PublicKey`. All signatures are of the generic type `Signature`.

 * ECDSA
    * public keys are compressed or uncompressed.
    * ephemeral key is derived from the private key, hash and the system entropy (based on https://golang.org/pkg/crypto/ecdsa/).
    * supports NIST P-256 (secp256r1) and secp256k1 curves.

 * BLS
    * supports [BLS12-381](https://electriccoin.co/blog/new-snark-curve/) curve.
    * is implementing the minimal-signature-size variant:
    signatures in G1 and public keys in G2.
    * default set-up uses [compressed](https://www.ietf.org/archive/id/draft-irtf-cfrg-pairing-friendly-curves-08.html#name-zcash-serialization-format-) G1/G2 points, 
    but uncompressed format is also supported.
    * hashing to curve uses the [Simplified SWU map-to-curve](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-14#section-6.6.3).
    * expanding the message in hash-to-curve uses a cSHAKE-based KMAC128 with a domain separation tag.
    KMAC128 serves as an expand_message_xof function.
    * this results in the full ciphersuite BLS_SIG_BLS12381G1_XOF:KMAC128_SSWU_RO_POP_ for signatures
    and BLS_POP_BLS12381G1_XOF:KMAC128_SSWU_RO_POP_ for proofs of possession.
    * signature verification includes the signature membership check in G1.
    * public key membership check in G2 is provided outside of the signature verification.
    * aggregation of signatures, public keys and private keys.
    * verification of an aggregated signature of a single message under multiple public keys.
    * verification of an aggregated signature of multiple messages under multiple public keys.
    * batch verification of multiple signatures of a single message under multiple
    public keys, using a binary tree of aggregations.
    * SPoCK scheme based on BLS: verifies two signatures have been generated from the same message that is unknown to the verifier.

### PRNG

 * ChaCha20-based CSPRNG

## Protocols

### Threshold Signature

 * BLS-based threshold signature
    * [non interactive](https://www.iacr.org/archive/pkc2003/25670031/25670031.pdf) threshold signature reconstruction.
    * supports only BLS 12-381 curve with the same features above.
    * (t+1) signatures are required to reconstruct the threshold signature.
    * key generation (single dealer) to provide the set of keys.
    * provides a stateless api and a stateful api.


### Discrete-Log based distributed key generation

All supported Distributed Key Generation protocols are [discrete log based](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.50.2737&rep=rep1&type=pdf) and are implemented for the same BLS setup on the BLS 12-381 curve. The protocols generate key sets for the BLS-based threshold signature.

 * Feldman VSS
    * simple verifiable secret sharing with a single dealer.
    * the library does not implement the communication channels between participants. The caller should implement the methods `PrivateSend` (1-to-1 messaging) and `Broadcast` (1-to-n messaging)
    * 1-to-1 messaging must be a private channel, the caller must make sure the channel preserves confidentialiy and authenticates the sender.
    * 1-to-n broadcasting is a reliable broadcast, where honest senders are able to reach all honest receivers, and where all honest receivers end up with the same received messages. The channel should also authenticate the broadcaster.
    * It is recommended that both communication channels are unique per protocol instance. This could be achieved by prepending the messages to send/broadcast by a unique protocol instance ID.
 * Feldman VSS Qual.
    * an extension of the simple Feldman VSS.
    * implements a complaint mechanism to qualify/disqualify the dealer.
 * Joint Feldman (Pedersen)
    * distributed generation.
    * based on multiple parallel instances of Feldman VSS Qual with multiple dealers.
    * same assumptions about the communication channels as in Feldman VSS.





