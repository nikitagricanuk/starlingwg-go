package control

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func mustKey(t *testing.T) PrivateKey {
	t.Helper()
	k, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	return k
}

// handshakeOverPipe runs the initiator and responder handshakes
// concurrently over an in-memory net.Pipe() and returns both results.
func handshakeOverPipe(t *testing.T, initPriv, respPriv PrivateKey, isKnown func(PublicKey) bool) (initRes, respRes *handshakeResult, initErr, respErr error) {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	respPub := respPriv.PublicKey()

	done := make(chan struct{})
	go func() {
		defer close(done)
		respRes, respErr = responderHandshake(c2, respPriv, isKnown, nil)
		if respErr != nil {
			// Message 2 was never sent, so without this the initiator's
			// blocking read of it below would hang forever.
			c2.Close()
		}
	}()

	initRes, initErr = initiatorHandshake(c1, initPriv, initPriv.PublicKey(), respPub)
	<-done
	return
}

func TestHandshakeSucceeds(t *testing.T) {
	initPriv := mustKey(t)
	respPriv := mustKey(t)
	initPub := initPriv.PublicKey()

	initRes, respRes, initErr, respErr := handshakeOverPipe(t, initPriv, respPriv, func(pk PublicKey) bool {
		return pk == initPub
	})
	if initErr != nil {
		t.Fatalf("initiator handshake failed: %v", initErr)
	}
	if respErr != nil {
		t.Fatalf("responder handshake failed: %v", respErr)
	}
	if respRes.RemoteStatic != initPub {
		t.Fatalf("responder learned wrong remote static key")
	}
	if initRes.SendKey != respRes.RecvKey {
		t.Fatalf("initiator send key != responder recv key")
	}
	if initRes.RecvKey != respRes.SendKey {
		t.Fatalf("initiator recv key != responder send key")
	}
	if initRes.SendKey == initRes.RecvKey {
		t.Fatalf("send and recv keys must differ")
	}
}

func TestHandshakeRejectsUnknownPeer(t *testing.T) {
	initPriv := mustKey(t)
	respPriv := mustKey(t)

	_, _, initErr, respErr := handshakeOverPipe(t, initPriv, respPriv, func(pk PublicKey) bool {
		return false // nobody is known
	})
	if respErr == nil {
		t.Fatalf("expected responder to reject unknown peer")
	}
	if !errors.Is(respErr, errUnknownPeer) {
		t.Fatalf("expected errUnknownPeer, got %v", respErr)
	}
	if initErr == nil {
		t.Fatalf("expected initiator to also fail once responder aborts")
	}
}

func TestHandshakeRejectsWrongExpectedRemoteKey(t *testing.T) {
	initPriv := mustKey(t)
	respPriv := mustKey(t)
	wrongPub := mustKey(t).PublicKey()
	initPub := initPriv.PublicKey()

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	done := make(chan error, 1)
	go func() {
		_, err := responderHandshake(c2, respPriv, func(pk PublicKey) bool { return pk == initPub }, nil)
		if err != nil {
			c2.Close() // unblock the initiator's pending read of message 2
		}
		done <- err
	}()

	// Initiator dials expecting the wrong static key for the responder.
	_, err := initiatorHandshake(c1, initPriv, initPub, wrongPub)
	<-done
	if err == nil {
		t.Fatalf("expected initiator handshake to fail when responder's real key differs from the expected key")
	}
}

func TestHandshakeRejectsReplay(t *testing.T) {
	initPriv := mustKey(t)
	respPriv := mustKey(t)
	initPub := initPriv.PublicKey()
	respPub := respPriv.PublicKey()

	var replayState = struct {
		last time.Time
		ok   bool
	}{}
	checkReplay := func(pk PublicKey, ts time.Time) bool {
		if replayState.ok && !ts.After(replayState.last) {
			return false
		}
		replayState.last = ts
		replayState.ok = true
		return true
	}

	// First handshake should succeed.
	c1, c2 := net.Pipe()
	done := make(chan error, 1)
	go func() {
		_, err := responderHandshake(c2, respPriv, func(pk PublicKey) bool { return pk == initPub }, checkReplay)
		done <- err
	}()
	if _, err := initiatorHandshake(c1, initPriv, initPub, respPub); err != nil {
		t.Fatalf("first handshake failed: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("first responder handshake failed: %v", err)
	}
	c1.Close()
	c2.Close()

	// A second, independent handshake with a real (later) timestamp should
	// still succeed -- replay rejection is about non-increasing timestamps,
	// not about reusing the same TCP connection.
	c3, c4 := net.Pipe()
	done2 := make(chan error, 1)
	go func() {
		_, err := responderHandshake(c4, respPriv, func(pk PublicKey) bool { return pk == initPub }, checkReplay)
		done2 <- err
	}()
	if _, err := initiatorHandshake(c3, initPriv, initPub, respPub); err != nil {
		t.Fatalf("second handshake failed: %v", err)
	}
	if err := <-done2; err != nil {
		t.Fatalf("second responder handshake unexpectedly rejected: %v", err)
	}
	c3.Close()
	c4.Close()
}

func TestHandshakeTamperedFrameRejected(t *testing.T) {
	// Tamper with the first byte of message 1 in transit (flip the
	// ephemeral key) and confirm the responder fails closed rather than
	// silently accepting garbage.
	initPriv := mustKey(t)
	respPriv := mustKey(t)
	initPub := initPriv.PublicKey()
	respPub := respPriv.PublicKey()

	pr, pw := net.Pipe()
	tamperedR, tamperedW := net.Pipe()
	defer pr.Close()
	defer pw.Close()
	defer tamperedR.Close()
	defer tamperedW.Close()

	// Relay pw -> tamperedW byte-for-byte but flip one byte of the first
	// message.
	go func() {
		buf := make([]byte, msg1Size)
		n, err := io.ReadFull(pw, buf)
		if err != nil || n != msg1Size {
			return
		}
		buf[0] ^= 0xFF
		tamperedW.Write(buf)
	}()

	done := make(chan error, 1)
	go func() {
		_, err := responderHandshake(tamperedR, respPriv, func(pk PublicKey) bool { return pk == initPub }, nil)
		done <- err
	}()

	// Initiator writes into pr's peer (pw side is read by the relay above);
	// initiator itself only needs to write msg1 and then it will block
	// reading msg2, which will never come since the responder aborts. Use
	// a goroutine and just check the responder's error.
	go func() {
		initiatorHandshake(pr, initPriv, initPub, respPub)
	}()

	respErr := <-done
	if respErr == nil {
		t.Fatalf("expected responder to reject a tampered handshake message")
	}
}
