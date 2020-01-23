package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func checkBytes(t *testing.T, input, expected, result []byte) {
	if !bytes.Equal(expected, result) {
		t.Errorf("hash mismatch: expect: %x have: %x, input is %x", expected, result, input)
	} else {
		t.Logf("hash test ok: expect: %x, input: %x", expected, input)
	}
}

// Sanity checks of SHA3_256
func TestSha3_256(t *testing.T) {
	input := []byte("test")
	expected, _ := hex.DecodeString("36f028580bb02cc8272a9a020f4200e346e276ae664e45ee80745574e2f5ab80")

	alg, err := NewHasher(SHA3_256, nil)
	if err != nil {
		t.Error(err.Error())
		return
	}
	hash := alg.ComputeHash(input)
	checkBytes(t, input, expected, hash)

	alg.Reset()
	alg.Write([]byte("te"))
	alg.Write([]byte("s"))
	alg.Write([]byte("t"))
	hash = alg.SumHash()
	checkBytes(t, input, expected, hash)
}

// Sanity checks of SHA3_384
func TestSha3_384(t *testing.T) {
	input := []byte("test")
	expected, _ := hex.DecodeString("e516dabb23b6e30026863543282780a3ae0dccf05551cf0295178d7ff0f1b41eecb9db3ff219007c4e097260d58621bd")

	alg, err := NewHasher(SHA3_384, nil)
	if err != nil {
		t.Error(err.Error())
		return
	}
	hash := alg.ComputeHash(input)
	checkBytes(t, input, expected, hash)

	alg.Reset()
	alg.Write([]byte("te"))
	alg.Write([]byte("s"))
	alg.Write([]byte("t"))
	hash = alg.SumHash()
	checkBytes(t, input, expected, hash)
}

// Sanity checks of SHA2_256
func TestSha2_256(t *testing.T) {
	input := []byte("test")
	expected, _ := hex.DecodeString("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")

	alg, err := NewHasher(SHA2_256, nil)
	if err != nil {
		t.Error(err.Error())
		return
	}
	hash := alg.ComputeHash(input)
	checkBytes(t, input, expected, hash)

	alg.Reset()
	alg.Write([]byte("te"))
	alg.Write([]byte("s"))
	alg.Write([]byte("t"))
	hash = alg.SumHash()
	checkBytes(t, input, expected, hash)
}

// Sanity checks of SHA2_256
func TestSha2_384(t *testing.T) {
	input := []byte("test")
	expected, _ := hex.DecodeString("768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9")

	alg, err := NewHasher(SHA2_384, nil)
	if err != nil {
		t.Error(err.Error())
		return
	}
	hash := alg.ComputeHash(input)
	checkBytes(t, input, expected, hash)

	alg.Reset()
	alg.Write([]byte("te"))
	alg.Write([]byte("s"))
	alg.Write([]byte("t"))
	hash = alg.SumHash()
	checkBytes(t, input, expected, hash)
}

// SHA3_256 bench
func BenchmarkSha3_256(b *testing.B) {
	a := []byte("Bench me!")
	alg, _ := NewHasher(SHA3_256, nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		alg.ComputeHash(a)
	}
	return
}

// SHA3_384 bench
func BenchmarkSha3_384(b *testing.B) {
	a := []byte("Bench me!")
	alg, _ := NewHasher(SHA3_384, nil)
	for i := 0; i < b.N; i++ {
		alg.ComputeHash(a)
	}
	return
}

// SHA2_256 bench
func BenchmarkSha2_256(b *testing.B) {
	a := []byte("Bench me!")
	alg, _ := NewHasher(SHA2_256, nil)
	for i := 0; i < b.N; i++ {
		alg.ComputeHash(a)
	}
	return
}

// SHA2_256 bench
func BenchmarkSha2_384(b *testing.B) {
	a := []byte("Bench me!")
	alg, _ := NewHasher(SHA2_384, nil)
	for i := 0; i < b.N; i++ {
		alg.ComputeHash(a)
	}
	return
}
