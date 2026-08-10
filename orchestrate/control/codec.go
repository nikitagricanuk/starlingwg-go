package control

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"golang.org/x/crypto/chacha20poly1305"
)

// maxFrameSize bounds the length prefix so a malicious/corrupt peer can't
// make Recv allocate an unbounded buffer.
const maxFrameSize = 64 * 1024

var (
	errFrameTooLarge = fmt.Errorf("control: frame exceeds max size (%d bytes)", maxFrameSize)
	errEmptyFrame    = errors.New("control: empty decrypted frame")
)

// Conn is an authenticated, encrypted control-channel connection: a TCP
// connection plus the two directional ChaCha20-Poly1305 keys derived from
// the Noise_IK handshake. Every Send/Recv is one length-prefixed encrypted
// frame; the AEAD nonce is a per-direction monotonic counter (4 zero bytes
// + 8-byte big-endian counter), the same shape WireGuard's own transport
// nonces use.
type Conn struct {
	nc           net.Conn
	sendAEAD     cipherAEAD
	recvAEAD     cipherAEAD
	sendCtr      uint64
	recvCtr      uint64
	RemoteStatic PublicKey
}

// cipherAEAD is the minimal surface of cipher.AEAD this package needs;
// declared locally to avoid importing crypto/cipher just for the interface
// name in exported signatures.
type cipherAEAD interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

func newConn(nc net.Conn, hr *handshakeResult) (*Conn, error) {
	sendAEAD, err := chacha20poly1305.New(hr.SendKey[:])
	if err != nil {
		return nil, err
	}
	recvAEAD, err := chacha20poly1305.New(hr.RecvKey[:])
	if err != nil {
		return nil, err
	}
	return &Conn{
		nc:           nc,
		sendAEAD:     sendAEAD,
		recvAEAD:     recvAEAD,
		RemoteStatic: hr.RemoteStatic,
	}, nil
}

func nonceFromCounter(ctr uint64) [chacha20poly1305.NonceSize]byte {
	var n [chacha20poly1305.NonceSize]byte
	binary.BigEndian.PutUint64(n[4:], ctr)
	return n
}

// Send encodes and encrypts m and writes it as one length-prefixed frame.
func (c *Conn) Send(m Message) error {
	body := m.encodeBody()
	plain := make([]byte, 0, 1+len(body))
	plain = append(plain, byte(m.Type()))
	plain = append(plain, body...)

	nonce := nonceFromCounter(c.sendCtr)
	c.sendCtr++
	ct := c.sendAEAD.Seal(nil, nonce[:], plain, nil)

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(ct)))
	if _, err := c.nc.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("control: write frame length: %w", err)
	}
	if _, err := c.nc.Write(ct); err != nil {
		return fmt.Errorf("control: write frame: %w", err)
	}
	return nil
}

// Recv reads, decrypts, and decodes the next frame.
func (c *Conn) Recv() (Message, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(c.nc, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n > maxFrameSize {
		return nil, errFrameTooLarge
	}
	ct := make([]byte, n)
	if _, err := io.ReadFull(c.nc, ct); err != nil {
		return nil, fmt.Errorf("control: read frame: %w", err)
	}

	nonce := nonceFromCounter(c.recvCtr)
	c.recvCtr++
	plain, err := c.recvAEAD.Open(nil, nonce[:], ct, nil)
	if err != nil {
		return nil, fmt.Errorf("control: frame authentication failed: %w", err)
	}
	if len(plain) < 1 {
		return nil, errEmptyFrame
	}
	return decodeBody(MessageType(plain[0]), plain[1:])
}

// Close closes the underlying connection.
func (c *Conn) Close() error { return c.nc.Close() }
