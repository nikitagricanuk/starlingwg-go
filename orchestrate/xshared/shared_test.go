package xshared

import (
	"bytes"
	cryptorand "crypto/rand"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
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

// devicePort reads back the actual bound listen_port from a live Device
// via IpcGet -- needed in tests since device.net.port is unexported and
// this package (unlike device_test.go) is outside package device.
func devicePort(t *testing.T, dev *device.Device) uint16 {
	t.Helper()
	out, err := dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "listen_port=") {
			var port uint16
			fmt.Sscanf(strings.TrimPrefix(line, "listen_port="), "%d", &port)
			return port
		}
	}
	t.Fatalf("listen_port not found in IpcGet output: %q", out)
	return 0
}

// plainPeer is a minimal, directly-configured Device standing in for a Y
// in these tests -- deliberately not using SharedDevice, since Y-side
// device management belongs to a later phase; here we only need something
// that speaks real WireGuard on a real loopback socket to exercise X's
// SharedDevice against.
type plainPeer struct {
	dev  *device.Device
	tun  *tuntest.ChannelTUN
	ip   netip.Addr
	priv device.NoisePrivateKey
	pub  device.NoisePublicKey
	port uint16
}

func newPlainPeer(t *testing.T, ip netip.Addr, remotePub device.NoisePublicKey) *plainPeer {
	t.Helper()
	priv, pub := genKey(t)
	ct := tuntest.NewChannelTUN()
	dev := device.NewDevice(ct.TUN(), conn.NewDefaultBind(), testLogger())
	t.Cleanup(dev.Close)

	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(priv[:]))
	fmt.Fprintf(&b, "listen_port=0\n")
	fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(remotePub[:]))
	fmt.Fprintf(&b, "replace_allowed_ips=true\n")
	fmt.Fprintf(&b, "allowed_ip=%s/32\n", peerRoute(ip))
	if err := dev.IpcSet(b.String()); err != nil {
		t.Fatalf("configure plain peer: %v", err)
	}
	if err := dev.Up(); err != nil {
		t.Fatalf("bring up plain peer: %v", err)
	}
	return &plainPeer{dev: dev, tun: ct, ip: ip, priv: priv, pub: pub, port: devicePort(t, dev)}
}

// peerRoute returns the AllowedIPs value a peer's *own* device should use
// to describe X's route (1.0.0.1), independent of this peer's own IP --
// callers pass whichever "other side" address is relevant.
func peerRoute(ip netip.Addr) string { return ip.String() }

func pingAndExpect(t *testing.T, from, to *tuntest.ChannelTUN, fromIP, toIP netip.Addr, wantDeliver bool) {
	t.Helper()
	msg := tuntest.Ping(toIP, fromIP)
	from.Outbound <- msg
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	select {
	case got := <-to.Inbound:
		if !wantDeliver {
			t.Fatalf("ping %s->%s unexpectedly delivered after removal", fromIP, toIP)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("ping %s->%s delivered corrupted packet", fromIP, toIP)
		}
	case <-timer.C:
		if wantDeliver {
			t.Fatalf("ping %s->%s did not arrive within timeout", fromIP, toIP)
		}
	}
}

func TestSharedDeviceNativeAddPeerAndPing(t *testing.T) {
	xPriv, xPub := genKey(t)
	xIP := netip.MustParseAddr("1.0.0.1")
	y1IP := netip.MustParseAddr("1.0.0.2")

	xTUN := tuntest.NewChannelTUN()
	sd, err := New(ModeNative, xTUN.TUN(), conn.NewDefaultBind(), Config{PrivateKey: xPriv, ListenPort: 0}, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { sd.Close() })

	y1 := newPlainPeer(t, xIP, xPub) // Y1's device: peer=X, no endpoint (Y never dials in native mode)

	y1Addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), y1.port)
	if err := sd.AddPeer(y1.pub, &y1Addr, []netip.Prefix{netip.PrefixFrom(y1IP, 32)}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	// X always dials Y in native mode: the first packet must originate
	// from X's side, since Y1's peer entry for X has no endpoint and can't
	// send until it has learned X's address from an inbound packet.
	pingAndExpect(t, xTUN, y1.tun, xIP, y1IP, true)
	pingAndExpect(t, y1.tun, xTUN, y1IP, xIP, true)
}

func TestSharedDeviceNativeRemovePeerIsolatesOthers(t *testing.T) {
	xPriv, xPub := genKey(t)
	xIP := netip.MustParseAddr("1.0.0.1")
	y1IP := netip.MustParseAddr("1.0.0.2")
	y2IP := netip.MustParseAddr("1.0.0.3")

	xTUN := tuntest.NewChannelTUN()
	sd, err := New(ModeNative, xTUN.TUN(), conn.NewDefaultBind(), Config{PrivateKey: xPriv, ListenPort: 0}, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { sd.Close() })

	y1 := newPlainPeer(t, xIP, xPub)
	y2 := newPlainPeer(t, xIP, xPub)

	y1Addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), y1.port)
	y2Addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), y2.port)
	if err := sd.AddPeer(y1.pub, &y1Addr, []netip.Prefix{netip.PrefixFrom(y1IP, 32)}); err != nil {
		t.Fatalf("AddPeer(y1): %v", err)
	}
	if err := sd.AddPeer(y2.pub, &y2Addr, []netip.Prefix{netip.PrefixFrom(y2IP, 32)}); err != nil {
		t.Fatalf("AddPeer(y2): %v", err)
	}

	// Both connect independently on the one shared native Device.
	pingAndExpect(t, xTUN, y1.tun, xIP, y1IP, true)
	pingAndExpect(t, xTUN, y2.tun, xIP, y2IP, true)

	if err := sd.RemovePeer(y1.pub); err != nil {
		t.Fatalf("RemovePeer(y1): %v", err)
	}

	// y2 is completely unaffected by y1's removal -- the core isolation
	// guarantee, expressed as a peer-level test on one shared Device.
	pingAndExpect(t, xTUN, y2.tun, xIP, y2IP, true)
	// y1 can no longer be reached: X has no route/peer for it anymore.
	pingAndExpect(t, xTUN, y1.tun, xIP, y1IP, false)
}

func TestSharedDeviceRejectsObfuscationOnNativeMode(t *testing.T) {
	xPriv, _ := genKey(t)
	xTUN := tuntest.NewChannelTUN()
	_, err := New(ModeNative, xTUN.TUN(), conn.NewDefaultBind(), Config{
		PrivateKey:      xPriv,
		ListenPort:      0,
		ObfuscationUAPI: "jc=5\n",
	}, testLogger())
	if err == nil {
		t.Fatalf("expected New to reject obfuscation config on ModeNative")
	}
}

func TestSharedDeviceCloakedAppliesObfuscationProfile(t *testing.T) {
	xPriv, _ := genKey(t)
	_, yPub := genKey(t)
	yIP := netip.MustParseAddr("1.0.0.2")

	xTUN := tuntest.NewChannelTUN()
	obf := "jc=5\njmin=10\njmax=20\ns1=15\ns2=18\ns3=20\ns4=25\nh1=100-200\nh2=300-400\nh3=500-600\nh4=700-800\n"
	sd, err := New(ModeCloaked, xTUN.TUN(), conn.NewDefaultBind(), Config{PrivateKey: xPriv, ListenPort: 0, ObfuscationUAPI: obf}, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { sd.Close() })

	out, err := sd.Device().IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	for _, want := range []string{"jc=5", "s1=15", "h1=100-200"} {
		if !strings.Contains(out, want) {
			t.Errorf("IpcGet output missing %q; full output:\n%s", want, out)
		}
	}

	// Cloaked mode: X waits passively (no endpoint) -- AddPeer with
	// endpoint=nil must succeed and must not write an endpoint= line.
	if err := sd.AddPeer(yPub, nil, []netip.Prefix{netip.PrefixFrom(yIP, 32)}); err != nil {
		t.Fatalf("AddPeer with nil endpoint: %v", err)
	}
	out2, err := sd.Device().IpcGet()
	if err != nil {
		t.Fatalf("IpcGet after AddPeer: %v", err)
	}
	if strings.Contains(out2, "endpoint=") {
		t.Errorf("cloaked-mode peer unexpectedly has an endpoint configured (X must wait passively):\n%s", out2)
	}
}
