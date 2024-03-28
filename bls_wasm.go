//go:build js && wasm

/*
 * Flow Crypto
 *
 * Copyright Dapper Labs, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package crypto

import (
	"github.com/onflow/crypto/hash"
)

const (
	SignatureLenBLSBLS12381 = 0
	PubKeyLenBLSBLS12381    = 0
	PrKeyLenBLSBLS12381     = 0
)

// blsBLS12381Algo, embeds SignAlgo
type blsBLS12381Algo struct {
	// the signing algo and parameters
	algo SigningAlgorithm
}

// BLS context on the BLS 12-381 curve
var blsInstance *blsBLS12381Algo

func NewExpandMsgXOFKMAC128(domainTag string) hash.Hasher {
	panic("no bls for wasm")
}

func IsBLSSignatureIdentity(s Signature) bool {
	panic("no bls for wasm")
}

type pubKeyBLSBLS12381 struct {
}

var _ PublicKey = (*pubKeyBLSBLS12381)(nil)

func (pk *pubKeyBLSBLS12381) Algorithm() SigningAlgorithm {
	panic("no bls for wasm")
}

func (a *blsBLS12381Algo) generatePrivateKey(ikm []byte) (PrivateKey, error) {
	panic("no bls for wasm")

}
func (a *blsBLS12381Algo) decodePrivateKey(privateKeyBytes []byte) (PrivateKey, error) {
	panic("no bls for wasm")
}

func (a *blsBLS12381Algo) decodePublicKey(publicKeyBytes []byte) (PublicKey, error) {
	panic("no bls for wasm")
}

func (a *blsBLS12381Algo) decodePublicKeyCompressed(publicKeyBytes []byte) (PublicKey, error) {
	panic("no bls for wasm")
}

func (pk *pubKeyBLSBLS12381) Verify(s Signature, data []byte, kmac hash.Hasher) (bool, error) {
	panic("no bls for wasm")
}

func (pk *pubKeyBLSBLS12381) Size() int {
	panic("no bls for wasm")
}

func (a *pubKeyBLSBLS12381) EncodeCompressed() []byte {
	panic("no bls for wasm")
}

func (a *pubKeyBLSBLS12381) Encode() []byte {
	panic("no bls for wasm")
}

func (pk *pubKeyBLSBLS12381) Equals(other PublicKey) bool {
	panic("no bls for wasm")
}

func (pk *pubKeyBLSBLS12381) String() string {
	panic("no bls for wasm")
}

func initBLS12381() {
	panic("no bls for wasm")

}
