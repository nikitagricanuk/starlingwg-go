package nativeflow

import (
	cryptorand "crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/orchestrate/xshared"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
)

func genKey(t *testing.T) (device.NoisePrivateKey, device.NoisePublicKey) {
	t.Helper()
	var priv device.NoisePrivateKey
	if _, err := cryptorand.Read(priv[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	priv[0] &= 248
	priv[31] = (priv[31] & 127) | 64
	var pub device.NoisePublicKey
	curve25519.ScalarBaseMult((*[32]byte)(&pub), (*[32]byte)(&priv))
	return priv, pub
}

func testLogger() *device.Logger { return device.NewLogger(device.LogLevelError, "") }

func namedLogger(name string) *device.Logger {
	return device.NewLogger(device.LogLevelError, name+": ")
}

func newLoopbackUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func hasPeer(t *testing.T, dev *device.Device, pub device.NoisePublicKey) bool {
	t.Helper()
	out, err := dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	return strings.Contains(out, "public_key="+hex.EncodeToString(pub[:]))
}

func TestFullNativeFlowXDialsY(t *testing.T) {
	xPriv, xPub := genKey(t)
	yPriv, yPub := genKey(t)
	xIP := netip.MustParseAddr("1.0.0.1")
	yIP := netip.MustParseAddr("1.0.0.2")

	// Y punches/probes on this exact socket, then hands it to its real
	// Device via PreboundBind -- no gap, no reopen.
	ySocket := newLoopbackUDP(t)
	yBind := NewPreboundBind(ySocket)
	yTUN := tuntest.NewChannelTUN()
	yDev, err := PreparePassiveDevice(yTUN.TUN(), yBind, YDeviceConfig{
		PrivateKey:      yPriv,
		RemotePublicKey: xPub,
		AllowedIPs:      []netip.Prefix{netip.PrefixFrom(xIP, 32)},
	}, namedLogger("Y"))
	if err != nil {
		t.Fatalf("PreparePassiveDevice: %v", err)
	}
	defer yDev.Close()

	if hasEndpoint := hasEndpointConfigured(t, yDev, xPub); hasEndpoint {
		t.Fatalf("Y's peer entry for X must never have an endpoint (fixed dial direction invariant)")
	}

	yExternal := ySocket.LocalAddr().(*net.UDPAddr).AddrPort()

	xTUN := tuntest.NewChannelTUN()
	// PersistentKeepalive is what makes AddPeer's endpoint= actually
	// trigger a handshake: handlePostConfig only flushes *already staged*
	// outbound packets (device/send.go SendStagedPackets does nothing
	// with an empty queue), so without a keepalive interval a freshly
	// added peer with no application traffic yet would never dial out at
	// all -- this is why the shared native Device always configures one.
	xNative, err := xshared.New(xshared.ModeNative, xTUN.TUN(), conn.NewDefaultBind(), xshared.Config{PrivateKey: xPriv, ListenPort: 0, PersistentKeepalive: time.Second}, namedLogger("X"))
	if err != nil {
		t.Fatalf("xshared.New: %v", err)
	}
	defer xNative.Close()

	// 10s (not a tighter bound) deliberately gives room for one lost
	// packet + WireGuard's own handshake retransmit to recover -- normal,
	// expected behavior for a UDP-based handshake, and consistent with
	// the plan's own suggested default NativeHandshakeTimeout of 8-10s.
	res := AttemptOnX(xNative, yPub, []netip.Prefix{netip.PrefixFrom(yIP, 32)}, yExternal, 10*time.Second)
	if !res.Success {
		t.Fatalf("AttemptOnX failed: %s", res.Reason)
	}

	// Confirm real data actually flows, both directions, once native mode
	// is established -- not just that a handshake timestamp appeared.
	msg := tuntest.Ping(yIP, xIP)
	xTUN.Outbound <- msg
	select {
	case got := <-yTUN.Inbound:
		if string(got) != string(msg) {
			t.Fatalf("Y received corrupted ping")
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("ping X->Y did not arrive after native handshake succeeded")
	}
}

func hasEndpointConfigured(t *testing.T, dev *device.Device, pub device.NoisePublicKey) bool {
	t.Helper()
	out, err := dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	inBlock := false
	want := "public_key=" + hex.EncodeToString(pub[:])
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "public_key=") {
			inBlock = line == want
			continue
		}
		if inBlock && strings.HasPrefix(line, "endpoint=") {
			return true
		}
	}
	return false
}

// TestHandshakeTimeStaleFromPriorAttemptIsNotMistakenForFresh is a
// regression test for a real, observed bug: AttemptOnX's poll used to
// accept any non-zero last_handshake_time_sec as proof of success. If a
// peer is ever reconfigured to a new endpoint without its prior handshake
// state actually being cleared first (e.g. RemovePeer silently not taking
// effect before the following AddPeer -- the scenario the comment on
// attemptOnX's RemovePeer call already warns about), that stale timestamp
// from the *previous* connection looks identical to a fresh one and gets
// reported as an immediate, false success -- observed live as "connected"
// showing tens of seconds before a real handshake at the new address
// actually completed. The fix requires the observed handshake time to be
// strictly newer than when this attempt started, so a leftover timestamp
// can never be mistaken for this attempt's own result, independent of
// whether RemovePeer's guarantee held.
func TestHandshakeTimeStaleFromPriorAttemptIsNotMistakenForFresh(t *testing.T) {
	xPriv, xPub := genKey(t)
	yPriv, yPub := genKey(t)
	xIP := netip.MustParseAddr("1.0.0.1")
	yIP := netip.MustParseAddr("1.0.0.2")

	ySocket := newLoopbackUDP(t)
	yBind := NewPreboundBind(ySocket)
	yTUN := tuntest.NewChannelTUN()
	yDev, err := PreparePassiveDevice(yTUN.TUN(), yBind, YDeviceConfig{
		PrivateKey:      yPriv,
		RemotePublicKey: xPub,
		AllowedIPs:      []netip.Prefix{netip.PrefixFrom(xIP, 32)},
	}, namedLogger("Y"))
	if err != nil {
		t.Fatalf("PreparePassiveDevice: %v", err)
	}
	defer yDev.Close()
	yExternal := ySocket.LocalAddr().(*net.UDPAddr).AddrPort()

	xTUN := tuntest.NewChannelTUN()
	xNative, err := xshared.New(xshared.ModeNative, xTUN.TUN(), conn.NewDefaultBind(), xshared.Config{PrivateKey: xPriv, ListenPort: 0, PersistentKeepalive: time.Second}, namedLogger("X"))
	if err != nil {
		t.Fatalf("xshared.New: %v", err)
	}
	defer xNative.Close()

	// Establish a genuine, working handshake first -- this timestamp is
	// the "stale" state a later, broken reconnect must not be fooled by.
	res := AttemptOnX(xNative, yPub, []netip.Prefix{netip.PrefixFrom(yIP, 32)}, yExternal, 10*time.Second)
	if !res.Success {
		t.Fatalf("initial AttemptOnX failed: %s", res.Reason)
	}
	staleHandshake, found := xNative.HandshakeTime(yPub)
	if !found || staleHandshake.IsZero() {
		t.Fatalf("expected a real handshake timestamp after the initial attempt")
	}

	// Simulate the suspected real-world failure mode directly: reconfigure
	// the same peer to a new, unreachable endpoint WITHOUT going through
	// RemovePeer first -- exactly what a silently-ineffective RemovePeer
	// before a reconnect's AddPeer would produce. The stale timestamp from
	// the working connection above is still sitting on the peer.
	attemptStart := time.Now()
	deadEnd := netip.MustParseAddrPort("127.0.0.1:1") // no listener
	if err := xNative.AddPeer(yPub, &deadEnd, []netip.Prefix{netip.PrefixFrom(yIP, 32)}); err != nil {
		t.Fatalf("AddPeer (reconfigure without RemovePeer): %v", err)
	}

	// Confirm this scenario is actually exercising the bug: the stale
	// timestamp must still read back as non-zero (what the old
	// `!t.IsZero()` check alone would have accepted as success).
	if t2, ok := xNative.HandshakeTime(yPub); !ok || t2.IsZero() {
		t.Fatalf("test setup bug: expected the stale handshake timestamp to still be readable")
	} else if t2.After(attemptStart) {
		t.Fatalf("test setup bug: stale handshake time must predate attemptStart")
	}

	// Poll using the same strict-recency comparison attemptOnX's fixed
	// code uses: it must never treat the stale timestamp as evidence that
	// *this* attempt succeeded. Since the new endpoint is unreachable, no
	// fresh handshake can occur either, so this must never see a time
	// after attemptStart within the window.
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		if t3, ok := xNative.HandshakeTime(yPub); ok && t3.After(attemptStart) {
			t.Fatalf("false success: observed handshake time %v was accepted as newer than attemptStart %v", t3, attemptStart)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestAttemptOnXTimesOutAndRemovesPeer(t *testing.T) {
	xPriv, _ := genKey(t)
	_, yPub := genKey(t)
	xTUN := tuntest.NewChannelTUN()
	xNative, err := xshared.New(xshared.ModeNative, xTUN.TUN(), conn.NewDefaultBind(), xshared.Config{PrivateKey: xPriv, ListenPort: 0}, testLogger())
	if err != nil {
		t.Fatalf("xshared.New: %v", err)
	}
	defer xNative.Close()

	// Point at a real-but-unreachable loopback address so nothing ever
	// answers, and drive the clock manually so the test doesn't have to
	// wait out a real multi-second timeout.
	deadEnd := netip.MustParseAddrPort("127.0.0.1:1") // no listener; well-known low port

	fakeNow := time.Now()
	fakeSleepCalls := 0
	res := attemptOnX(xNative, yPub, nil, deadEnd, 3*time.Second, 100*time.Millisecond,
		func() time.Time {
			t := fakeNow
			fakeNow = fakeNow.Add(200 * time.Millisecond)
			return t
		},
		func(time.Duration) { fakeSleepCalls++ },
	)

	if res.Success {
		t.Fatalf("expected AttemptOnX to time out, got success")
	}
	if res.Reason != "handshake-timeout" {
		t.Fatalf("Reason = %q, want handshake-timeout", res.Reason)
	}
	if fakeSleepCalls == 0 {
		t.Fatalf("expected at least one poll/sleep cycle before timing out")
	}
	if hasPeer(t, xNative.Device(), yPub) {
		t.Fatalf("expected peer to be removed from the shared native Device after timeout")
	}
}

func TestPreboundBindSendReceive(t *testing.T) {
	aSock := newLoopbackUDP(t)
	bSock := newLoopbackUDP(t)
	aBind := NewPreboundBind(aSock)
	bBind := NewPreboundBind(bSock)

	fns, port, err := bBind.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if port != uint16(bSock.LocalAddr().(*net.UDPAddr).Port) {
		t.Fatalf("Open returned port %d, want the pre-bound socket's real port %d", port, bSock.LocalAddr().(*net.UDPAddr).Port)
	}

	bAddrStr := bSock.LocalAddr().String()
	ep, err := aBind.ParseEndpoint(bAddrStr)
	if err != nil {
		t.Fatalf("ParseEndpoint: %v", err)
	}
	if err := aBind.Send([][]byte{[]byte("hello")}, ep); err != nil {
		t.Fatalf("Send: %v", err)
	}

	bufs := [][]byte{make([]byte, 64)}
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	bSock.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := fns[0](bufs, sizes, eps)
	if err != nil {
		t.Fatalf("receive func: %v", err)
	}
	if n != 1 || string(bufs[0][:sizes[0]]) != "hello" {
		t.Fatalf("received %q, want %q", bufs[0][:sizes[0]], "hello")
	}
	if eps[0].DstToString() != aSock.LocalAddr().String() {
		t.Fatalf("received endpoint = %s, want %s", eps[0].DstToString(), aSock.LocalAddr().String())
	}
}

func TestPunchSendsAPacket(t *testing.T) {
	dst := newLoopbackUDP(t)
	src := newLoopbackUDP(t)

	if err := Punch(src, dst.LocalAddr().(*net.UDPAddr).AddrPort()); err != nil {
		t.Fatalf("Punch: %v", err)
	}
	dst.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	n, _, err := dst.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("expected to receive the punch packet: %v", err)
	}
	if n == 0 {
		t.Fatalf("expected a non-empty punch packet")
	}
}

// TestPreparePassiveDeviceDefaultsToKeepalive is a regression test for a
// real, live-observed bug: Y's peer entry for X never carries an endpoint
// (Y only ever waits in native mode), so without a keepalive Y never sends
// X anything on its own. On a real mobile carrier this let Y's NAT mapping
// close within well under a minute of silence, after which X's own
// keepalives could no longer reach Y -- rx_bytes stalled, the orchestrator
// correctly detected staleness and reconnected, and stats reset to zero
// every cycle (observed live as "connected" with a permanently-empty
// statistics section). PreparePassiveDevice must configure a keepalive by
// default so Y keeps refreshing its own mapping.
func TestPreparePassiveDeviceDefaultsToKeepalive(t *testing.T) {
	priv, _ := genKey(t)
	_, remotePub := genKey(t)
	tunDev := tuntest.NewChannelTUN()
	sock := newLoopbackUDP(t)
	bind := NewPreboundBind(sock)

	dev, err := PreparePassiveDevice(tunDev.TUN(), bind, YDeviceConfig{
		PrivateKey:      priv,
		RemotePublicKey: remotePub,
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("1.0.0.1/32")},
	}, testLogger())
	if err != nil {
		t.Fatalf("PreparePassiveDevice: %v", err)
	}
	defer dev.Close()

	out, err := dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	want := fmt.Sprintf("persistent_keepalive_interval=%d", int(DefaultYKeepalive.Seconds()))
	if !strings.Contains(out, want) {
		t.Fatalf("IpcGet output missing %q (default keepalive not applied); got:\n%s", want, out)
	}
}

// TestPreparePassiveDeviceKeepaliveOverride confirms the override knobs
// (explicit positive value, and negative-to-disable) actually take effect,
// so a caller with a reason to deviate from DefaultYKeepalive isn't silently
// ignored.
func TestPreparePassiveDeviceKeepaliveOverride(t *testing.T) {
	priv, _ := genKey(t)
	_, remotePub := genKey(t)

	cases := []struct {
		name       string
		ka         time.Duration
		wantLine   string
		wantAbsent bool
	}{
		{name: "explicit positive", ka: 5 * time.Second, wantLine: "persistent_keepalive_interval=5"},
		// device/uapi.go's IpcGet only ever emits persistent_keepalive_interval
		// when it's non-zero (device/uapi.go:199), so "disabled" reads back as
		// the line being absent entirely, not present with a zero value.
		{name: "negative disables", ka: -1 * time.Second, wantAbsent: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tunDev := tuntest.NewChannelTUN()
			sock := newLoopbackUDP(t)
			bind := NewPreboundBind(sock)
			dev, err := PreparePassiveDevice(tunDev.TUN(), bind, YDeviceConfig{
				PrivateKey:          priv,
				RemotePublicKey:     remotePub,
				AllowedIPs:          []netip.Prefix{netip.MustParsePrefix("1.0.0.1/32")},
				PersistentKeepalive: tc.ka,
			}, testLogger())
			if err != nil {
				t.Fatalf("PreparePassiveDevice: %v", err)
			}
			defer dev.Close()

			out, err := dev.IpcGet()
			if err != nil {
				t.Fatalf("IpcGet: %v", err)
			}
			if tc.wantAbsent {
				if strings.Contains(out, "persistent_keepalive_interval=") {
					t.Fatalf("expected no persistent_keepalive_interval line; got:\n%s", out)
				}
				return
			}
			if !strings.Contains(out, tc.wantLine) {
				t.Fatalf("IpcGet output missing %q; got:\n%s", tc.wantLine, out)
			}
		})
	}
}
