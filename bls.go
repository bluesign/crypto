// +build relic

package crypto

// BLS signature scheme implementation using BLS12-381 curve ([zcash]https://github.com/zkcrypto/pairing/blob/master/src/bls12_381/README.md#bls12-381)
// Pairing, ellipic curve and modular arithmetic is using Relic library.
// This implementation does not include any security against side-channel attacks.

// existing features:
//  - the implementation is optimized for shorter signatures (on G1).
//  - public keys are longer (on G2)
//  - serialization of points on G1 and G2 is compressed ([zcash] https://github.com/zkcrypto/pairing/blob/master/src/bls12_381/README.md#serialization)
//  - hash to curve is using the optimized SWU map (https://eprint.iacr.org/2019/403.pdf section 4)
//  - expanding the message is using a cSHAKE-based KMAC128 with a domain separation tag
//  - signature verification checks the membership of signature in G1
//  - the public key membership check in G2 is implemented separately
//  - membership checks in G1 and G2 are using a naive scalar multiplication with the group order

// future features:
//  - signature aggregations
//  - membership checks in G1 and G2 using Bowe method (https://eprint.iacr.org/2019/814.pdf)
//  - implement a G1/G2 swap (signatures on G2 and public keys on G1)

// #cgo CFLAGS: -g -Wall -std=c99 -I./ -I./relic/build/include
// #cgo LDFLAGS: -Lrelic/build/lib -l relic_s
// #include "bls_include.h"
import "C"

import (
	"errors"
	"fmt"
	"sync"

	"github.com/dapperlabs/flow-go/crypto/hash"
)

// blsBLS12381Algo, embeds SignAlgo
type blsBLS12381Algo struct {
	// points to Relic context of BLS12-381 with all the parameters
	context ctx
	// the signing algo and parameters
	algo SigningAlgorithm
}

//  Once variable to use a unique instance
var blsInstance *blsBLS12381Algo
var once sync.Once

// returns a new BLS signer on curve BLS12-381
func newBLSBLS12381() *blsBLS12381Algo {
	once.Do(func() {
		blsInstance = &(blsBLS12381Algo{
			algo: BLSBLS12381,
		})
		blsInstance.init()
	})
	return blsInstance
}

// Sign signs an array of bytes using the private key
// Signature is compressed [zcash] https://github.com/zkcrypto/pairing/blob/master/src/bls12_381/README.md#serialization
// This function only reads the private key
// If the hasher used is KMAC128, the hasher is only read.
// It is recommended to use Sign with the hasher from NewBLSKMAC. If not, the hasher used
// must expand the message to 1024 bits. It is also recommended to use a hasher with a domain separation tag.
func (sk *PrKeyBLSBLS12381) Sign(data []byte, kmac hash.Hasher) (Signature, error) {
	if kmac == nil {
		return nil, errors.New("Sign requires a Hasher")
	}
	// hash the input to 128 bytes
	h := kmac.ComputeHash(data)
	return newBLSBLS12381().blsSign(&sk.scalar, h), nil
}

// BLS_KMACFunction is the customizer used for KMAC in BLS
const blsKMACFunction = "H2C"

// NewBLSKMAC returns a new KMAC128 instance with the right parameters
// chosen for BLS signatures and verifications
// it expands the message into 1024 bits (required for the optimal SwU hash to curve)
// tag is the domain separation tag, it is recommended to use a different tag for each signature domain
func NewBLSKMAC(tag string) hash.Hasher {
	// the error is ignored as the parameter lengths are in the correct range for kmac
	kmac, _ := hash.NewKMAC_128([]byte(tag), []byte("BLS_KMACFunction"), opSwUInputLenBLSBLS12381)
	return kmac
}

// Verify verifies a signature of a byte array using the public key and the input hasher
// The function assumes the public key is in the valid G2 subgroup as it is
// either generated by the library or read through the DecodePublicKey function.
// The signature membership check in G1 is included in the verifcation
// If the hasher used is KMAC128, the hasher is only read.
// The public key is only read by the function
func (pk *PubKeyBLSBLS12381) Verify(s Signature, data []byte, kmac hash.Hasher) (bool, error) {
	if kmac == nil {
		return false, errors.New("VerifyBytes requires a Hasher")
	}
	// hash the input to 128 bytes
	h := kmac.ComputeHash(data)

	return newBLSBLS12381().blsVerify(&pk.point, s, h), nil
}

// generatePrivateKey generates a private key for BLS on BLS12381 curve
// The minimum size of the input seed is 48 bytes (for a sceurity of 128 bits)
func (a *blsBLS12381Algo) generatePrivateKey(seed []byte) (PrivateKey, error) {
	if len(seed) < KeyGenSeedMinLenBLSBLS12381 || len(seed) > KeyGenSeedMaxLenBLSBLS12381 {
		return nil, fmt.Errorf("seed length should be between %d and %d bytes",
			KeyGenSeedMinLenBLSBLS12381, KeyGenSeedMaxLenBLSBLS12381)
	}

	sk := &PrKeyBLSBLS12381{
		// public key is only computed when needed
		pk: nil,
	}

	// maps the seed to a private key
	// error is not checked as it is guaranteed to be nil; len(seed)<maxScalarSize
	mapToZr(&(sk.scalar), seed)
	return sk, nil
}

// decodePrivateKey decodes a slice of bytes into a private key
// this function checks the scalar is less than the group order
func (a *blsBLS12381Algo) decodePrivateKey(privateKeyBytes []byte) (PrivateKey, error) {
	if len(privateKeyBytes) != prKeyLengthBLSBLS12381 {
		return nil, fmt.Errorf("the input length has to be equal to %d", prKeyLengthBLSBLS12381)
	}
	sk := &PrKeyBLSBLS12381{
		pk: nil,
	}
	readScalar(&sk.scalar, privateKeyBytes)
	if sk.scalar.checkMembershipZr() {
		return sk, nil
	}
	return nil, errors.New("the private key is not a valid BLS12-381 curve key")
}

// decodePublicKey decodes a slice of bytes into a public key
// this function includes a membership check in G2
func (a *blsBLS12381Algo) decodePublicKey(publicKeyBytes []byte) (PublicKey, error) {
	if len(publicKeyBytes) != pubKeyLengthBLSBLS12381 {
		return nil, fmt.Errorf("the input length has to be equal to %d", pubKeyLengthBLSBLS12381)
	}
	var pk PubKeyBLSBLS12381
	if readPointG2(&pk.point, publicKeyBytes) != nil {
		return nil, errors.New("the input slice does not encode a public key")
	}
	if pk.point.checkMembershipG2() {
		return &pk, nil
	}
	return nil, errors.New("the public key is not a valid BLS12-381 curve key")
}

// PrKeyBLSBLS12381 is the private key of BLS using BLS12_381, it implements PrivateKey
type PrKeyBLSBLS12381 struct {
	// public key
	pk *PubKeyBLSBLS12381
	// private key data
	scalar scalar
}

// Algorithm returns the Signing Algorithm
func (sk *PrKeyBLSBLS12381) Algorithm() SigningAlgorithm {
	return BLSBLS12381
}

// Size returns the private key lengh in bytes
func (sk *PrKeyBLSBLS12381) Size() int {
	return PrKeyLenBLSBLS12381
}

// computePublicKey generates the public key corresponding to
// the input private key. The function makes sure the piblic key
// is valid in G2
func (sk *PrKeyBLSBLS12381) computePublicKey() {
	var newPk PubKeyBLSBLS12381
	// compute public key pk = g2^sk
	genScalarMultG2(&(newPk.point), &(sk.scalar))
	sk.pk = &newPk
}

// PublicKey returns the public key corresponding to the private key
func (sk *PrKeyBLSBLS12381) PublicKey() PublicKey {
	if sk.pk != nil {
		return sk.pk
	}
	sk.computePublicKey()
	return sk.pk
}

// Encode returns a byte encoding of the private key
// The encoding is a raw encoding in big endian padded to the group order
func (a *PrKeyBLSBLS12381) Encode() []byte {
	dest := make([]byte, prKeyLengthBLSBLS12381)
	writeScalar(dest, &a.scalar)
	return dest
}

// Equals checks is two public keys are equal
func (sk *PrKeyBLSBLS12381) Equals(other PrivateKey) bool {
	otherBLS, ok := other.(*PrKeyBLSBLS12381)
	if !ok {
		return false
	}
	return sk.scalar.equals(&otherBLS.scalar)
}

// String returns the hex string representation of the key.
func (sk *PrKeyBLSBLS12381) String() string {
	return fmt.Sprintf("%#x", sk.Encode())
}

// PubKeyBLSBLS12381 is the public key of BLS using BLS12_381,
// it implements PublicKey
type PubKeyBLSBLS12381 struct {
	// public key data
	point pointG2
}

// Algorithm returns the Signing Algorithm
func (pk *PubKeyBLSBLS12381) Algorithm() SigningAlgorithm {
	return BLSBLS12381
}

// Size returns the public key lengh in bytes
func (pk *PubKeyBLSBLS12381) Size() int {
	return PubKeyLenBLSBLS12381
}

// Encode returns a byte encoding of the public key
// The encoding is a compressed encoding of the point
// [zcash] https://github.com/zkcrypto/pairing/blob/master/src/bls12_381/README.md#serialization
func (a *PubKeyBLSBLS12381) Encode() []byte {
	dest := make([]byte, pubKeyLengthBLSBLS12381)
	writePointG2(dest, &a.point)
	return dest
}

// Equals checks is two public keys are equal
func (pk *PubKeyBLSBLS12381) Equals(other PublicKey) bool {
	otherBLS, ok := other.(*PubKeyBLSBLS12381)
	if !ok {
		return false
	}
	return pk.point.equals(&otherBLS.point)
}

// String returns the hex string representation of the key.
func (pk *PubKeyBLSBLS12381) String() string {
	return fmt.Sprintf("%#x", pk.Encode())
}

// Get Macro definitions from the C layer as Cgo does not export macros
var signatureLengthBLSBLS12381 = int(C.get_signature_len())
var pubKeyLengthBLSBLS12381 = int(C.get_pk_len())
var prKeyLengthBLSBLS12381 = int(C.get_sk_len())

// init sets the context of BLS12381 curve
func (a *blsBLS12381Algo) init() error {
	// initializes relic context and sets the B12_381 parameters
	if err := a.context.initContext(); err != nil {
		return err
	}
	a.context.precCtx = C.init_precomputed_data_BLS12_381()

	// compare the Go and C layer constants as a sanity check
	if signatureLengthBLSBLS12381 != SignatureLenBLSBLS12381 ||
		pubKeyLengthBLSBLS12381 != PubKeyLenBLSBLS12381 ||
		prKeyLengthBLSBLS12381 != PrKeyLenBLSBLS12381 {
		return errors.New("BLS on BLS-12381 settings are not correct")
	}
	return nil
}

// reInit the context of BLS12381 curve assuming there was a previous call to init()
// If the implementation evolves and relic has multiple contexts,
// reinit should be called at every a. operation.
func (a *blsBLS12381Algo) reInit() {
	a.context.reInitContext()
}

// computes a bls signature through the C layer
func (a *blsBLS12381Algo) blsSign(sk *scalar, data []byte) Signature {
	s := make([]byte, SignatureLenBLSBLS12381)

	C.bls_sign((*C.uchar)(&s[0]),
		(*C.bn_st)(sk),
		(*C.uchar)(&data[0]),
		(C.int)(len(data)))
	return s
}

// Checks the validity of a bls signature through the C layer
func (a *blsBLS12381Algo) blsVerify(pk *pointG2, s Signature, data []byte) bool {
	if len(s) != signatureLengthBLSBLS12381 {
		return false
	}
	verif := C.bls_verify((*C.ep2_st)(pk),
		(*C.uchar)(&s[0]),
		(*C.uchar)(&data[0]),
		(C.int)(len(data)))

	return (verif == valid)
}

// checkMembershipZr checks a scalar is less than the group order (r)
func (sk *scalar) checkMembershipZr() bool {
	verif := C.check_membership_Zr((*C.bn_st)(sk))
	return verif == valid
}

// membershipCheckG2 runs a membership check of BLS public keys on BLS12-381 curve.
// Returns true if the public key is on the correct subgroup of the curve
// and false otherwise
// It is necessary to run this test once for every public key before
// it is used to verify BLS signatures. The library calls this function whenever
// it imports a key through the function DecodePublicKey.
// The membership check is separated from the signature verification to optimize
// multiple verification calls using the same public key
func (pk *pointG2) checkMembershipG2() bool {
	verif := C.check_membership_G2((*C.ep2_st)(pk))
	return verif == valid
}

// This is only a TEST/DEBUG/BENCH function
// returns the hash to G1 point from a slice of 128 bytes
func hashToG1(data []byte) *pointG1 {
	l := len(data)
	var h pointG1
	C.map_to_G1((*C.ep_st)(&h), (*C.uchar)(&data[0]), (C.int)(l))
	return &h
}

// This is only a TEST function
// wraps a call to optimized SwU algorithm since cgo can't be used
// in go test files
func OpSwUUnitTest(output []byte, input []byte) {
	C.opswu_test((*C.uchar)(&output[0]),
		(*C.uchar)(&input[0]),
		SignatureLenBLSBLS12381)
}
