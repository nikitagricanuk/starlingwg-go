package control

import (
	"net"
	"testing"
	"time"
)

func TestDialAndAcceptOverTCPThenSendRecv(t *testing.T) {
	yPriv := mustKey(t) // initiator, always Y
	xPriv := mustKey(t) // responder, always X
	yPub := yPriv.PublicKey()
	xPub := xPriv.PublicKey()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	ep := NewEndpoint(xPriv, func(pk PublicKey) bool { return pk == yPub })

	connCh := make(chan *Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		err := ep.Serve(ln, func(c *Conn) { connCh <- c }, func(nc net.Conn, err error) { errCh <- err })
		if err != nil {
			// Listener closed at test teardown; not a failure.
			_ = err
		}
	}()

	yConn, err := Dial(ln.Addr().String(), yPriv, xPub)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer yConn.Close()

	var xConn *Conn
	select {
	case xConn = <-connCh:
	case err := <-errCh:
		t.Fatalf("Endpoint.Accept failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for X to accept the connection")
	}
	defer xConn.Close()

	if xConn.RemoteStatic != yPub {
		t.Fatalf("X's Conn.RemoteStatic = %x, want %x", xConn.RemoteStatic, yPub)
	}

	// Y -> X
	hello := Hello{Role: RoleY, WGPublicKey: yPub, ProtocolVersion: 1}
	if err := yConn.Send(hello); err != nil {
		t.Fatalf("Send(Hello): %v", err)
	}
	got, err := xConn.Recv()
	if err != nil {
		t.Fatalf("Recv(Hello) on X: %v", err)
	}
	gotHello, ok := got.(Hello)
	if !ok || gotHello != hello {
		t.Fatalf("X received %#v, want %#v", got, hello)
	}

	// X -> Y, a different message type, to exercise both directions with
	// independent nonce counters.
	info := XInfo{ProbePortA: 40001, ProbePortB: 40002, NativeListenPort: 51821, CloakedListenPort: 51820}
	if err := xConn.Send(info); err != nil {
		t.Fatalf("Send(XInfo): %v", err)
	}
	got2, err := yConn.Recv()
	if err != nil {
		t.Fatalf("Recv(XInfo) on Y: %v", err)
	}
	gotInfo, ok := got2.(XInfo)
	if !ok || gotInfo != info {
		t.Fatalf("Y received %#v, want %#v", got2, info)
	}

	// Several messages in a row on the same direction, to exercise the
	// nonce counter incrementing correctly.
	for i := uint64(0); i < 5; i++ {
		if err := yConn.Send(Ping{Nonce: i}); err != nil {
			t.Fatalf("Send(Ping %d): %v", i, err)
		}
	}
	for i := uint64(0); i < 5; i++ {
		got, err := xConn.Recv()
		if err != nil {
			t.Fatalf("Recv(Ping %d): %v", i, err)
		}
		p, ok := got.(Ping)
		if !ok || p.Nonce != i {
			t.Fatalf("Recv(Ping %d) got %#v", i, got)
		}
	}
}

func TestDialRejectsUnknownPeer(t *testing.T) {
	yPriv := mustKey(t)
	xPriv := mustKey(t)
	xPub := xPriv.PublicKey()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	ep := NewEndpoint(xPriv, func(pk PublicKey) bool { return false })
	go ep.Serve(ln, func(c *Conn) { c.Close() }, func(nc net.Conn, err error) {})

	_, err = Dial(ln.Addr().String(), yPriv, xPub)
	if err == nil {
		t.Fatalf("expected Dial to fail when X doesn't recognize Y's static key")
	}
}

func TestDialFailsAgainstWrongServer(t *testing.T) {
	yPriv := mustKey(t)
	xPriv := mustKey(t)
	yPub := yPriv.PublicKey()
	wrongXPub := mustKey(t).PublicKey() // Y expects a different X than what's actually listening

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	ep := NewEndpoint(xPriv, func(pk PublicKey) bool { return pk == yPub })
	go ep.Serve(ln, func(c *Conn) { c.Close() }, func(nc net.Conn, err error) {})

	_, err = Dial(ln.Addr().String(), yPriv, wrongXPub)
	if err == nil {
		t.Fatalf("expected Dial to fail when the expected remote static key doesn't match the real server")
	}
}
