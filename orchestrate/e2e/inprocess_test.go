// Package e2e_test exercises the whole orchestrate.Orchestrator wiring
// end-to-end: real Noise_IK control channel over loopback TCP, real NAT
// characterization over loopback UDP (which, with no real NAT in the way,
// always classifies as cone-type -- a genuine symmetric-NAT scenario needs
// real kernel NAT rules, see netns_test.go), real WireGuard handshakes over
// loopback UDP via nativeflow's PreboundBind/xshared.SharedDevice. This is
// the "does the whole thing actually work together" test the lower-level
// packages' own unit tests can't provide on their own.
package e2e_test

import (
	cryptorand "crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/orchestrate"
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

// freePort allocates and immediately releases a UDP port on 127.0.0.1,
// for use as either a UDP or TCP port number in test config -- small,
// accepted race window, standard Go testing practice.
func freePort(t *testing.T) uint16 {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("allocate free port: %v", err)
	}
	defer c.Close()
	return uint16(c.LocalAddr().(*net.UDPAddr).Port)
}

type testTopology struct {
	xPriv, yPriv device.NoisePrivateKey
	xPub, yPub   device.NoisePublicKey
	controlAddr  string
	xIP, yIP     netip.Addr
	xTUN, yTUN   *tuntest.ChannelTUN
	xCloakedTUN  *tuntest.ChannelTUN
}

func newTopology(t *testing.T, xIP, yIP netip.Addr) testTopology {
	t.Helper()
	xPriv, xPub := genKey(t)
	yPriv, yPub := genKey(t)
	return testTopology{
		xPriv: xPriv, yPriv: yPriv,
		xPub: xPub, yPub: yPub,
		controlAddr: fmt.Sprintf("127.0.0.1:%d", freePort(t)),
		xIP:         xIP, yIP: yIP,
		xTUN:        tuntest.NewChannelTUN(),
		yTUN:        tuntest.NewChannelTUN(),
		xCloakedTUN: tuntest.NewChannelTUN(),
	}
}

func (top testTopology) xConfig(t *testing.T) orchestrate.Config {
	return orchestrate.Config{
		Role:              orchestrate.RoleX,
		LocalPrivateKey:   top.xPriv,
		LocalPublicKey:    top.xPub,
		ControlListenAddr: top.controlAddr,
		PublicHost:        "127.0.0.1",
		ProbePortA:        freePort(t),
		ProbePortB:        freePort(t),
		NativeListenPort:  freePort(t),
		CloakedListenPort: freePort(t),
		AuthorizedPeers: []orchestrate.PeerAuthorization{
			{PublicKey: top.yPub, AllowedIPs: []string{top.yIP.String() + "/32"}},
		},
		NativeTUN:               top.xTUN.TUN(),
		CloakedTUN:              top.xCloakedTUN.TUN(),
		NativeHandshakeTimeout:  10 * time.Second,
		CloakedHandshakeTimeout: 10 * time.Second,
		Logger:                  testLogger(),
	}
}

func (top testTopology) yConfig(t *testing.T) orchestrate.Config {
	return orchestrate.Config{
		Role:            orchestrate.RoleY,
		LocalPrivateKey: top.yPriv,
		LocalPublicKey:  top.yPub,
		Peers: []orchestrate.PeerConfig{
			{RemotePublicKey: top.xPub, ControlAddr: top.controlAddr, AllowedIPs: []string{top.xIP.String() + "/32"}},
		},
		YTUN:                    top.yTUN.TUN(),
		NativeHandshakeTimeout:  10 * time.Second,
		CloakedHandshakeTimeout: 10 * time.Second,
		Logger:                  testLogger(),
	}
}

func startOrchestrator(t *testing.T, cfg orchestrate.Config) *orchestrate.Orchestrator {
	t.Helper()
	o, err := orchestrate.NewOrchestrator(cfg)
	if err != nil {
		t.Fatalf("NewOrchestrator(%v): %v", cfg.Role, err)
	}
	t.Cleanup(o.Stop)
	return o
}

// pingThrough sends a ping and waits for it to arrive, retrying a few
// times over a longer window. A single immediate attempt is sufficient
// once a tunnel has been up and passing traffic for a while (see the
// native-mode tests), but right after a fresh handshake -- particularly
// one that lands moments after a prior failed attempt's own goroutines
// and queues are still unwinding, as in the cloaked-fallback tests -- a
// brief queueing/scheduling delay before the first packet gets through is
// normal WireGuard behavior, not a correctness bug; retrying here matches
// how a real application would treat "give the tunnel a moment."
func pingThrough(t *testing.T, from, to *tuntest.ChannelTUN, fromIP, toIP netip.Addr) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var lastErr string
	for time.Now().Before(deadline) {
		msg := tuntest.Ping(toIP, fromIP)
		from.Outbound <- msg
		select {
		case got := <-to.Inbound:
			if string(got) != string(msg) {
				t.Fatalf("ping %s->%s delivered corrupted packet", fromIP, toIP)
			}
			return
		case <-time.After(1 * time.Second):
			lastErr = fmt.Sprintf("ping %s->%s did not arrive within 1s", fromIP, toIP)
		}
	}
	t.Fatalf("%s (retried until deadline)", lastErr)
}

func TestOrchestratorEstablishesNativeModeEndToEnd(t *testing.T) {
	xIP := netip.MustParseAddr("1.0.0.1")
	yIP := netip.MustParseAddr("1.0.0.2")
	top := newTopology(t, xIP, yIP)

	xOrch := startOrchestrator(t, top.xConfig(t))
	if err := xOrch.Start(); err != nil {
		t.Fatalf("X Start: %v", err)
	}

	yOrch := startOrchestrator(t, top.yConfig(t))
	if err := yOrch.Start(); err != nil {
		t.Fatalf("Y Start: %v", err)
	}

	yKey := top.controlAddr
	state, reason := yOrch.Session(yKey).State()
	if state != orchestrate.StateConnectedNative {
		t.Fatalf("Y session state = %v (%s), want ConnectedNative", state, reason)
	}

	xKey := fmt.Sprintf("%x", top.yPub[:])
	state, reason = xOrch.Session(xKey).State()
	if state != orchestrate.StateConnectedNative {
		t.Fatalf("X session state = %v (%s), want ConnectedNative", state, reason)
	}

	// The real proof: actual application traffic flows both directions
	// through the Devices the orchestrator itself stood up -- not just a
	// handshake timestamp.
	pingThrough(t, top.xTUN, top.yTUN, xIP, yIP)
	pingThrough(t, top.yTUN, top.xTUN, yIP, xIP)
}

// TestOrchestratorStatusAndEventsReflectRealConnection is a thin
// end-to-end check that Phase 6's Status()/Events() surface actually
// reflects a real orchestrator run, not just the unit-level bookkeeping
// events_test.go already covers in isolation.
func TestOrchestratorStatusAndEventsReflectRealConnection(t *testing.T) {
	xIP := netip.MustParseAddr("1.0.0.1")
	yIP := netip.MustParseAddr("1.0.0.2")
	top := newTopology(t, xIP, yIP)

	xOrch := startOrchestrator(t, top.xConfig(t))
	if err := xOrch.Start(); err != nil {
		t.Fatalf("X Start: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	interfaceUpCount := 0
	for time.Now().Before(deadline) && interfaceUpCount < 2 {
		select {
		case ev := <-xOrch.Events():
			if ev.Kind == orchestrate.EventInterfaceUp {
				interfaceUpCount++
			}
		case <-time.After(100 * time.Millisecond):
		}
	}
	if interfaceUpCount != 2 {
		t.Fatalf("received %d EventInterfaceUp, want 2 (native + cloaked)", interfaceUpCount)
	}

	yOrch := startOrchestrator(t, top.yConfig(t))
	if err := yOrch.Start(); err != nil {
		t.Fatalf("Y Start: %v", err)
	}

	deadline = time.Now().Add(5 * time.Second)
	var got orchestrate.Event
	found := false
	for time.Now().Before(deadline) && !found {
		select {
		case ev := <-yOrch.Events():
			if ev.Kind == orchestrate.EventConnected {
				got, found = ev, true
			}
		case <-time.After(50 * time.Millisecond):
		}
	}
	if !found {
		t.Fatalf("never received an EventConnected from Y")
	}
	if got.Mode != "native" {
		t.Fatalf("EventConnected.Mode = %q, want native", got.Mode)
	}
	if got.SessionKey != top.controlAddr {
		t.Fatalf("EventConnected.SessionKey = %q, want %q", got.SessionKey, top.controlAddr)
	}

	status := yOrch.Status()
	if len(status) != 1 {
		t.Fatalf("len(Status()) = %d, want 1", len(status))
	}
	if status[0].State != orchestrate.StateConnectedNative || status[0].Mode != "native" {
		t.Fatalf("Status()[0] = %+v, want State=ConnectedNative Mode=native", status[0])
	}
}

func TestOrchestratorMultipleYOnOneSharedNativeDevice(t *testing.T) {
	xIP := netip.MustParseAddr("1.0.0.1")
	y1IP := netip.MustParseAddr("1.0.0.2")
	y2IP := netip.MustParseAddr("1.0.0.3")

	xPriv, xPub := genKey(t)
	xTUN := tuntest.NewChannelTUN()
	controlAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))

	y1Priv, y1Pub := genKey(t)
	y2Priv, y2Pub := genKey(t)
	y1TUN := tuntest.NewChannelTUN()
	y2TUN := tuntest.NewChannelTUN()

	xCfg := orchestrate.Config{
		Role:              orchestrate.RoleX,
		LocalPrivateKey:   xPriv,
		LocalPublicKey:    xPub,
		ControlListenAddr: controlAddr,
		PublicHost:        "127.0.0.1",
		ProbePortA:        freePort(t),
		ProbePortB:        freePort(t),
		NativeListenPort:  freePort(t),
		CloakedListenPort: freePort(t),
		AuthorizedPeers: []orchestrate.PeerAuthorization{
			{PublicKey: y1Pub, AllowedIPs: []string{y1IP.String() + "/32"}},
			{PublicKey: y2Pub, AllowedIPs: []string{y2IP.String() + "/32"}},
		},
		NativeTUN:               xTUN.TUN(),
		CloakedTUN:              tuntest.NewChannelTUN().TUN(),
		NativeHandshakeTimeout:  10 * time.Second,
		CloakedHandshakeTimeout: 10 * time.Second,
		Logger:                  testLogger(),
	}
	xOrch := startOrchestrator(t, xCfg)
	if err := xOrch.Start(); err != nil {
		t.Fatalf("X Start: %v", err)
	}

	y1Cfg := orchestrate.Config{
		Role:            orchestrate.RoleY,
		LocalPrivateKey: y1Priv,
		LocalPublicKey:  y1Pub,
		Peers: []orchestrate.PeerConfig{
			{RemotePublicKey: xPub, ControlAddr: controlAddr, AllowedIPs: []string{xIP.String() + "/32"}},
		},
		YTUN:                    y1TUN.TUN(),
		NativeHandshakeTimeout:  10 * time.Second,
		CloakedHandshakeTimeout: 10 * time.Second,
		Logger:                  testLogger(),
	}
	y2Cfg := y1Cfg
	y2Cfg.LocalPrivateKey = y2Priv
	y2Cfg.LocalPublicKey = y2Pub
	y2Cfg.YTUN = y2TUN.TUN()

	y1Orch := startOrchestrator(t, y1Cfg)
	if err := y1Orch.Start(); err != nil {
		t.Fatalf("Y1 Start: %v", err)
	}
	y2Orch := startOrchestrator(t, y2Cfg)
	if err := y2Orch.Start(); err != nil {
		t.Fatalf("Y2 Start: %v", err)
	}

	// Both Y's connect independently through the same shared native
	// Device on X -- exactly the reconsidered "two interfaces total, not
	// N+1" design, now exercised through the real control-channel-driven
	// flow rather than direct xshared calls.
	pingThrough(t, xTUN, y1TUN, xIP, y1IP)
	pingThrough(t, xTUN, y2TUN, xIP, y2IP)

	x1Key := fmt.Sprintf("%x", y1Pub[:])
	x2Key := fmt.Sprintf("%x", y2Pub[:])
	if st, _ := xOrch.Session(x1Key).State(); st != orchestrate.StateConnectedNative {
		t.Fatalf("X's session for Y1 = %v, want ConnectedNative", st)
	}
	if st, _ := xOrch.Session(x2Key).State(); st != orchestrate.StateConnectedNative {
		t.Fatalf("X's session for Y2 = %v, want ConnectedNative", st)
	}
}

// TestOrchestratorFallsBackToCloakedOnNativeTimeout drives a real
// native-timeout -> cloaked-fallback transition through the full
// orchestrator (not just xshared/nativeflow in isolation): X's
// NativeHandshakeTimeout is set essentially to zero, so AttemptOnX always
// times out immediately regardless of what real connectivity would allow
// -- a deterministic way to exercise the fallback path without needing
// real NAT hardware (that's what netns_test.go is for). It then verifies
// the *whole* cloaked path: CloakedParams actually delivered, Y's device
// picks them up and matches X's obfuscation profile byte-for-byte, and
// real traffic flows over the resulting obfuscated tunnel.
func TestOrchestratorFallsBackToCloakedOnNativeTimeout(t *testing.T) {
	xIP := netip.MustParseAddr("1.0.0.1")
	yIP := netip.MustParseAddr("1.0.0.2")

	xPriv, xPub := genKey(t)
	yPriv, yPub := genKey(t)
	controlAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	xNativeTUN := tuntest.NewChannelTUN()
	xCloakedTUN := tuntest.NewChannelTUN()
	yTUN := tuntest.NewChannelTUN()

	obfProfile := orchestrate.ObfuscationProfile{
		S1: 15, S2: 18, S3: 20, S4: 25,
		H1Lo: 100, H1Hi: 200,
		H2Lo: 300, H2Hi: 400,
		H3Lo: 500, H3Hi: 600,
		H4Lo: 700, H4Hi: 800,
	}

	xCfg := orchestrate.Config{
		Role:              orchestrate.RoleX,
		LocalPrivateKey:   xPriv,
		LocalPublicKey:    xPub,
		ControlListenAddr: controlAddr,
		PublicHost:        "127.0.0.1",
		ProbePortA:        freePort(t),
		ProbePortB:        freePort(t),
		NativeListenPort:  freePort(t),
		CloakedListenPort: freePort(t),
		AuthorizedPeers: []orchestrate.PeerAuthorization{
			{PublicKey: yPub, AllowedIPs: []string{yIP.String() + "/32"}},
		},
		ObfuscationProfile: obfProfile,
		NativeTUN:          xNativeTUN.TUN(),
		CloakedTUN:         xCloakedTUN.TUN(),
		// Deliberately near-zero: guarantees AttemptOnX's deadline is
		// already passed before its first poll, forcing the fallback path
		// every time, independent of real network conditions.
		NativeHandshakeTimeout:  time.Nanosecond,
		CloakedHandshakeTimeout: 10 * time.Second,
		Logger:                  testLogger(),
	}
	xOrch := startOrchestrator(t, xCfg)
	if err := xOrch.Start(); err != nil {
		t.Fatalf("X Start: %v", err)
	}

	yCfg := orchestrate.Config{
		Role:            orchestrate.RoleY,
		LocalPrivateKey: yPriv,
		LocalPublicKey:  yPub,
		Peers: []orchestrate.PeerConfig{
			{RemotePublicKey: xPub, ControlAddr: controlAddr, AllowedIPs: []string{xIP.String() + "/32"}},
		},
		YTUN:                    yTUN.TUN(),
		NativeHandshakeTimeout:  10 * time.Second,
		CloakedHandshakeTimeout: 10 * time.Second,
		Logger:                  testLogger(),
	}
	yOrch := startOrchestrator(t, yCfg)
	if err := yOrch.Start(); err != nil {
		t.Fatalf("Y Start: %v", err)
	}

	if st, reason := yOrch.Session(controlAddr).State(); st != orchestrate.StateConnectedCloaked {
		t.Fatalf("Y session state = %v (%s), want ConnectedCloaked", st, reason)
	}
	xKey := fmt.Sprintf("%x", yPub[:])
	if st, reason := xOrch.Session(xKey).State(); st != orchestrate.StateConnectedCloaked {
		t.Fatalf("X session state = %v (%s), want ConnectedCloaked", st, reason)
	}

	// Real traffic over the obfuscated tunnel, through the Devices the
	// orchestrator itself stood up.
	pingThrough(t, xCloakedTUN, yTUN, xIP, yIP)
	pingThrough(t, yTUN, xCloakedTUN, yIP, xIP)

	// The native path must never have connected -- if it did, this test
	// isn't actually exercising the fallback.
	msg := tuntest.Ping(yIP, xIP)
	xNativeTUN.Outbound <- msg
	select {
	case <-yTUN.Inbound:
		t.Fatalf("native path unexpectedly delivered a packet -- fallback wasn't actually exercised")
	case <-time.After(500 * time.Millisecond):
		// expected: nothing arrives via the native (never-connected) path
	}
}
