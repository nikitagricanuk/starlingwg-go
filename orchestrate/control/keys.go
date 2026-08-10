package control

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"

	"golang.org/x/crypto/curve25519"
)

// KeySize is the size in bytes of a Curve25519 public or private key.
const KeySize = 32

// PrivateKey and PublicKey are raw Curve25519 keys, independent of the
// device package's NoisePrivateKey/NoisePublicKey so this package has no
// dependency on device internals. Callers convert at the orchestrate layer.
type (
	PrivateKey [KeySize]byte
	PublicKey  [KeySize]byte
)

var errInvalidPublicKey = errors.New("control: invalid public key (all-zero DH result)")

// GeneratePrivateKey returns a new random, correctly clamped Curve25519
// private key.
func GeneratePrivateKey() (PrivateKey, error) {
	var sk PrivateKey
	if _, err := rand.Read(sk[:]); err != nil {
		return sk, err
	}
	sk[0] &= 248
	sk[31] = (sk[31] & 127) | 64
	return sk, nil
}

// PublicKey derives the Curve25519 public key for sk.
func (sk PrivateKey) PublicKey() PublicKey {
	var pk PublicKey
	curve25519.ScalarBaseMult((*[KeySize]byte)(&pk), (*[KeySize]byte)(&sk))
	return pk
}

func isZero(b []byte) bool {
	acc := byte(0)
	for _, v := range b {
		acc |= v
	}
	return subtle.ConstantTimeByteEq(acc, 0) == 1
}

// sharedSecret computes the X25519 Diffie-Hellman shared secret between sk
// and pk, rejecting degenerate (all-zero) results the same way WireGuard's
// own device.NoisePrivateKey.sharedSecret does.
func (sk PrivateKey) sharedSecret(pk PublicKey) ([KeySize]byte, error) {
	var ss [KeySize]byte
	curve25519.ScalarMult(&ss, (*[KeySize]byte)(&sk), (*[KeySize]byte)(&pk))
	if isZero(ss[:]) {
		return ss, errInvalidPublicKey
	}
	return ss, nil
}

func setZero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
