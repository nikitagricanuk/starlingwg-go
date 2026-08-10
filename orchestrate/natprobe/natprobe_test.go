package natprobe

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

func startResponder(t *testing.T, resolve func(netip.AddrPort) netip.AddrPort) *Responder {
	t.Helper()
	r, err := NewResponder("127.0.0.1:0", nil, resolve)
	if err != nil {
		t.Fatalf("NewResponder: %v", err)
	}
	go r.Serve()
	t.Cleanup(func() { r.Close() })
	return r
}

func newTestClientConn(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func TestResponderEchoesRealObservedAddress(t *testing.T) {
	r := startResponder(t, nil)
	client := newTestClientConn(t)

	observed, err := probeOnce(client, r.LocalAddr().(*net.UDPAddr).AddrPort(), DefaultTimeout, 0)
	if err != nil {
		t.Fatalf("probeOnce: %v", err)
	}
	if observed.Addr() != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("observed addr = %s, want 127.0.0.1", observed.Addr())
	}
	if observed.Port() != uint16(client.LocalAddr().(*net.UDPAddr).Port) {
		t.Fatalf("observed port = %d, want %d", observed.Port(), client.LocalAddr().(*net.UDPAddr).Port)
	}
}

func TestResponderIgnoresNonProbeTraffic(t *testing.T) {
	r := startResponder(t, nil)
	client := newTestClientConn(t)

	if _, err := client.WriteToUDP([]byte("hello, not a probe"), r.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("WriteToUDP: %v", err)
	}
	client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 64)
	if _, _, err := client.ReadFrom(buf); err == nil {
		t.Fatalf("expected no response to non-probe traffic, got one")
	}
}

func TestCharacterizeConeWhenMappingsMatch(t *testing.T) {
	// Real loopback UDP, both responders honestly echo what they observe.
	// A single client socket naturally produces the same observed address
	// toward both, exactly like a cone-type NAT would.
	rA := startResponder(t, nil)
	rB := startResponder(t, nil)
	client := newTestClientConn(t)

	res, err := Characterize(client, rA.LocalAddr().(*net.UDPAddr).AddrPort(), rB.LocalAddr().(*net.UDPAddr).AddrPort(), DefaultTimeout, 0)
	if err != nil {
		t.Fatalf("Characterize: %v", err)
	}
	if res.Class != Cone {
		t.Fatalf("Class = %v, want Cone", res.Class)
	}
	if res.ExternalAddr.Port() != uint16(client.LocalAddr().(*net.UDPAddr).Port) {
		t.Fatalf("ExternalAddr = %s, doesn't match client's real local port", res.ExternalAddr)
	}
}

func TestCharacterizeSymmetricWhenMappingsDiverge(t *testing.T) {
	// Force the two responders to report different addresses regardless
	// of what they actually observed, simulating what a symmetric NAT's
	// per-destination remapping would look like from Y's perspective --
	// without needing real NAT hardware in a unit test.
	fakeA := netip.MustParseAddrPort("198.51.100.1:11111")
	fakeB := netip.MustParseAddrPort("198.51.100.1:22222")
	rA := startResponder(t, func(netip.AddrPort) netip.AddrPort { return fakeA })
	rB := startResponder(t, func(netip.AddrPort) netip.AddrPort { return fakeB })
	client := newTestClientConn(t)

	res, err := Characterize(client, rA.LocalAddr().(*net.UDPAddr).AddrPort(), rB.LocalAddr().(*net.UDPAddr).AddrPort(), DefaultTimeout, 0)
	if err != nil {
		t.Fatalf("Characterize: %v", err)
	}
	if res.Class != Symmetric {
		t.Fatalf("Class = %v, want Symmetric", res.Class)
	}
}

func TestCharacterizeUnknownWhenBothPortsUnreachable(t *testing.T) {
	client := newTestClientConn(t)

	// Bind and immediately close two ports so nothing answers, but the
	// addresses are still syntactically valid loopback destinations.
	closedA := allocateClosedUDPPort(t)
	closedB := allocateClosedUDPPort(t)

	start := time.Now()
	res, err := Characterize(client, closedA, closedB, 200*time.Millisecond, 0)
	elapsed := time.Since(start)

	if res.Class != Unknown {
		t.Fatalf("Class = %v, want Unknown", res.Class)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("Characterize blocked for %v against unreachable ports -- should never block indefinitely", elapsed)
	}
	_ = err // an error is expected here but Unknown is the load-bearing signal callers act on
}

func allocateClosedUDPPort(t *testing.T) netip.AddrPort {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	addr := conn.LocalAddr().(*net.UDPAddr).AddrPort()
	conn.Close()
	return addr
}
