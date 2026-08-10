package control

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

// A hand-rolled Noise_IK-style handshake, mirroring the exact sequence of
// mixHash/mixKey/AEAD operations amneziawg-go's own device/noise-protocol.go
// uses for its (audited) WireGuard handshake -- just applied to the control
// channel's own static identity (each side's existing WireGuard static
// keypair) and framed over a single TCP connection instead of raw UDP
// datagrams. Unlike WG's Noise_IKpsk2, there is no preshared key mixed in:
// the two peers already authenticate each other via their known WireGuard
// public keys, which is the property IK is chosen for (the initiator must
// know the responder's static key in advance; the responder learns the
// initiator's static key, encrypted, from the first message).
//
// Message 1 (initiator -> responder): e, es, s, ss  (+ a timestamp, for
// replay rejection by the caller).
// Message 2 (responder -> initiator): e, ee, se.
//
// This does not aim for wire compatibility with the formal Noise Protocol
// Framework -- it is a self-contained, internal-use-only protocol between
// two amneziawg-go processes that already share long-term keys out of band.

const protocolName = "OrchestrateControl_IK_25519_ChaChaPoly_BLAKE2s_v1"

var (
	initialChainKey [blake2s.Size]byte
	initialHash     [blake2s.Size]byte
)

func init() {
	initialChainKey = blake2s.Sum256([]byte(protocolName))
	initialHash = blake2s.Sum256(initialChainKey[:])
}

const (
	msg1Size = KeySize + (KeySize + 16) + (8 + 16) // ephemeral + encrypted static + encrypted timestamp
	msg2Size = KeySize + 16                        // ephemeral + encrypted empty payload
)

var zeroNonce [chacha20poly1305.NonceSize]byte

func aeadSeal(key []byte, ad, plaintext []byte) []byte {
	aead, _ := chacha20poly1305.New(key)
	return aead.Seal(nil, zeroNonce[:], plaintext, ad)
}

func aeadOpen(key []byte, ad, ciphertext []byte) ([]byte, error) {
	aead, _ := chacha20poly1305.New(key)
	return aead.Open(nil, zeroNonce[:], ciphertext, ad)
}

// handshakeResult is what each side ends up with after a successful
// handshake: two directional transport keys plus the verified remote
// static public key (useful on the responder side, which does not know in
// advance which configured peer is dialing in).
type handshakeResult struct {
	RemoteStatic PublicKey
	SendKey      [chacha20poly1305.KeySize]byte
	RecvKey      [chacha20poly1305.KeySize]byte
}

// initiatorHandshake performs the IK handshake as the initiator (always Y,
// dialing out to a known X). remoteStatic must already be known.
func initiatorHandshake(rw io.ReadWriter, localPriv PrivateKey, localPub PublicKey, remoteStatic PublicKey) (*handshakeResult, error) {
	h := initialHash
	ck := initialChainKey

	mixHash(&h, remoteStatic[:])

	ePriv, err := GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("control: generate ephemeral: %w", err)
	}
	ePub := ePriv.PublicKey()
	mixHash(&h, ePub[:])

	// es: DH(e, responder_static) mixed into the chain key.
	es, err := ePriv.sharedSecret(remoteStatic)
	if err != nil {
		return nil, fmt.Errorf("control: es DH: %w", err)
	}
	var key [chacha20poly1305.KeySize]byte
	kdf2(&ck, &key, ck[:], es[:])

	staticCipher := aeadSeal(key[:], h[:], localPub[:])
	mixHash(&h, staticCipher)

	// ss: DH(initiator_static, responder_static) mixed into the chain key.
	ss, err := localPriv.sharedSecret(remoteStatic)
	if err != nil {
		return nil, fmt.Errorf("control: ss DH: %w", err)
	}
	kdf2(&ck, &key, ck[:], ss[:])

	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(time.Now().UnixNano()))
	timestampCipher := aeadSeal(key[:], h[:], tsBuf[:])
	mixHash(&h, timestampCipher)

	msg1 := make([]byte, 0, msg1Size)
	msg1 = append(msg1, ePub[:]...)
	msg1 = append(msg1, staticCipher...)
	msg1 = append(msg1, timestampCipher...)
	if len(msg1) != msg1Size {
		return nil, fmt.Errorf("control: internal error: msg1 size %d != %d", len(msg1), msg1Size)
	}
	if _, err := rw.Write(msg1); err != nil {
		return nil, fmt.Errorf("control: write msg1: %w", err)
	}

	msg2 := make([]byte, msg2Size)
	if _, err := io.ReadFull(rw, msg2); err != nil {
		return nil, fmt.Errorf("control: read msg2: %w", err)
	}
	var reEphemeral PublicKey
	copy(reEphemeral[:], msg2[:KeySize])
	emptyCipher := msg2[KeySize:]

	mixHash(&h, reEphemeral[:])

	ee, err := ePriv.sharedSecret(reEphemeral)
	if err != nil {
		return nil, fmt.Errorf("control: ee DH: %w", err)
	}
	kdf2(&ck, &key, ck[:], ee[:])

	se, err := localPriv.sharedSecret(reEphemeral)
	if err != nil {
		return nil, fmt.Errorf("control: se DH: %w", err)
	}
	kdf2(&ck, &key, ck[:], se[:])

	if _, err := aeadOpen(key[:], h[:], emptyCipher); err != nil {
		return nil, fmt.Errorf("control: msg2 authentication failed: %w", err)
	}
	mixHash(&h, emptyCipher)

	res := &handshakeResult{RemoteStatic: remoteStatic}
	kdf2(&res.SendKey, &res.RecvKey, ck[:], nil)
	setZero(ck[:])
	setZero(ePriv[:])
	return res, nil
}

var errUnknownPeer = errors.New("control: handshake from unknown static key")

// responderHandshake performs the IK handshake as the responder (always X,
// accepting an inbound TCP connection from a Y it may not yet be able to
// identify by address). isKnownPeer authenticates the initiator's static
// key once it has been decrypted from message 1, before the responder
// commits any further resources; checkReplay lets the caller reject
// replayed initiations using the timestamp embedded in message 1.
func responderHandshake(
	rw io.ReadWriter,
	localPriv PrivateKey,
	isKnownPeer func(PublicKey) bool,
	checkReplay func(PublicKey, time.Time) bool,
) (*handshakeResult, error) {
	msg1 := make([]byte, msg1Size)
	if _, err := io.ReadFull(rw, msg1); err != nil {
		return nil, fmt.Errorf("control: read msg1: %w", err)
	}
	var ie PublicKey
	copy(ie[:], msg1[:KeySize])
	staticCipher := msg1[KeySize : KeySize+KeySize+16]
	timestampCipher := msg1[KeySize+KeySize+16:]

	localPub := localPriv.PublicKey()
	h := initialHash
	ck := initialChainKey
	mixHash(&h, localPub[:])
	mixHash(&h, ie[:])

	es, err := localPriv.sharedSecret(ie)
	if err != nil {
		return nil, fmt.Errorf("control: es DH: %w", err)
	}
	var key [chacha20poly1305.KeySize]byte
	kdf2(&ck, &key, ck[:], es[:])

	staticPlain, err := aeadOpen(key[:], h[:], staticCipher)
	if err != nil {
		return nil, fmt.Errorf("control: msg1 static decrypt failed: %w", err)
	}
	var remoteStatic PublicKey
	copy(remoteStatic[:], staticPlain)
	mixHash(&h, staticCipher)

	if !isKnownPeer(remoteStatic) {
		return nil, errUnknownPeer
	}

	ss, err := localPriv.sharedSecret(remoteStatic)
	if err != nil {
		return nil, fmt.Errorf("control: ss DH: %w", err)
	}
	kdf2(&ck, &key, ck[:], ss[:])

	tsPlain, err := aeadOpen(key[:], h[:], timestampCipher)
	if err != nil {
		return nil, fmt.Errorf("control: msg1 timestamp decrypt failed: %w", err)
	}
	mixHash(&h, timestampCipher)

	ts := time.Unix(0, int64(binary.BigEndian.Uint64(tsPlain)))
	if checkReplay != nil && !checkReplay(remoteStatic, ts) {
		return nil, fmt.Errorf("control: replayed or too-old handshake initiation from %x", remoteStatic)
	}

	rePriv, err := GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("control: generate ephemeral: %w", err)
	}
	rePub := rePriv.PublicKey()
	mixHash(&h, rePub[:])

	ee, err := rePriv.sharedSecret(ie)
	if err != nil {
		return nil, fmt.Errorf("control: ee DH: %w", err)
	}
	kdf2(&ck, &key, ck[:], ee[:])

	se, err := rePriv.sharedSecret(remoteStatic)
	if err != nil {
		return nil, fmt.Errorf("control: se DH: %w", err)
	}
	kdf2(&ck, &key, ck[:], se[:])

	emptyCipher := aeadSeal(key[:], h[:], nil)
	mixHash(&h, emptyCipher)

	msg2 := make([]byte, 0, msg2Size)
	msg2 = append(msg2, rePub[:]...)
	msg2 = append(msg2, emptyCipher...)
	if _, err := rw.Write(msg2); err != nil {
		return nil, fmt.Errorf("control: write msg2: %w", err)
	}

	res := &handshakeResult{RemoteStatic: remoteStatic}
	// Responder derives the same two keys in the opposite send/recv order
	// from the initiator, mirroring device.Peer.BeginSymmetricSession.
	kdf2(&res.RecvKey, &res.SendKey, ck[:], nil)
	setZero(ck[:])
	setZero(rePriv[:])
	return res, nil
}
