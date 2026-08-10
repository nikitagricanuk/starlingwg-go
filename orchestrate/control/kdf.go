package control

import (
	"crypto/hmac"
	"hash"

	"golang.org/x/crypto/blake2s"
)

// HMAC-based KDF, mirroring device/noise-helpers.go's KDF1/KDF2 (RFC 5869
// HKDF built on BLAKE2s) so the control channel's handshake uses the same
// well-reviewed construction as amneziawg-go's own Noise_IK, just reimplemented
// standalone since device's equivalents are unexported.

func hmac1(sum *[blake2s.Size]byte, key, in0 []byte) {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	mac.Write(in0)
	mac.Sum(sum[:0])
}

func hmac2(sum *[blake2s.Size]byte, key, in0, in1 []byte) {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	mac.Write(in0)
	mac.Write(in1)
	mac.Sum(sum[:0])
}

// kdf2 derives two outputs from key/input, as HKDF-Expand does with two
// counter blocks.
func kdf2(t0, t1 *[blake2s.Size]byte, key, input []byte) {
	var prk [blake2s.Size]byte
	hmac1(&prk, key, input)
	hmac1(t0, prk[:], []byte{0x1})
	hmac2(t1, prk[:], t0[:], []byte{0x2})
	setZero(prk[:])
}

func mixHash(h *[blake2s.Size]byte, data []byte) {
	hasher, _ := blake2s.New256(nil)
	hasher.Write(h[:])
	hasher.Write(data)
	hasher.Sum(h[:0])
	hasher.Reset()
}
