package nativeflow

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// DefaultYKeepalive is the PersistentKeepalive PreparePassiveDevice applies
// when YDeviceConfig.PersistentKeepalive is left zero. Y's peer entry for X
// never carries an endpoint (native mode's fixed dial direction: X always
// dials Y), so without a keepalive Y never sends anything to X on its own
// -- the initial punch only opens Y's NAT mapping once, and real mobile
// carrier NATs have been observed to close that mapping in well under a
// minute of silence, well before ordinary application traffic would
// naturally refresh it. Once the mapping closes, X's own keepalives (see
// xshared.Config.PersistentKeepalive) can no longer reach Y, rx_bytes stops
// progressing, and the orchestrator's staleness check (superviseY,
// StaleAfter default 30s) correctly -- but repeatedly -- tears the session
// down and reconnects. 15s leaves comfortable margin under that observed
// mapping lifetime while still being an ordinary, unremarkable keepalive
// cadence (WireGuard's own convention is 25s).
const DefaultYKeepalive = 15 * time.Second

// YDeviceConfig configures Y's own Device for native mode.
type YDeviceConfig struct {
	PrivateKey      device.NoisePrivateKey
	RemotePublicKey device.NoisePublicKey // X
	AllowedIPs      []netip.Prefix
	// PersistentKeepalive keeps Y's NAT mapping toward X alive even though
	// Y itself never dials out in native mode. Zero uses DefaultYKeepalive;
	// to disable entirely (e.g. in tests against a Bind with no real NAT
	// in the path), use a negative value.
	PersistentKeepalive time.Duration
}

// PreparePassiveDevice brings up Y's Device with its peer entry for X
// carrying no endpoint -- Y only ever waits in native mode, matching the
// fixed dial-direction invariant (X always dials Y, never the reverse).
// bind should wrap the exact socket Y already punched its NAT on (see
// PreboundBind), so the pinhole state lines up with what the Device
// actually listens on. Must be brought up (and therefore ready to
// complete a handshake) *before* Y reports its punched address to X over
// the control channel, so there's no race where X's first packet arrives
// before Y is listening.
func PreparePassiveDevice(tunDev tun.Device, bind conn.Bind, cfg YDeviceConfig, logger *device.Logger) (*device.Device, error) {
	dev := device.NewDevice(tunDev, bind, logger)

	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(cfg.PrivateKey[:]))
	fmt.Fprintf(&b, "listen_port=0\n") // PreboundBind.Open ignores this; the socket is already bound
	fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(cfg.RemotePublicKey[:]))
	fmt.Fprintf(&b, "replace_allowed_ips=true\n")
	keepalive := cfg.PersistentKeepalive
	if keepalive == 0 {
		keepalive = DefaultYKeepalive
	}
	if keepalive > 0 {
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", int(keepalive.Seconds()))
	}
	for _, p := range cfg.AllowedIPs {
		fmt.Fprintf(&b, "allowed_ip=%s\n", p.String())
	}
	// Deliberately no endpoint= line: Y never dials X in native mode.

	if err := dev.IpcSet(b.String()); err != nil {
		dev.Close()
		return nil, fmt.Errorf("nativeflow: configure Y device: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("nativeflow: bring up Y device: %w", err)
	}
	return dev, nil
}

// Punch sends a single raw UDP packet from conn toward X's native listen
// port to open (and, called periodically, keep alive) Y's NAT pinhole in
// that exact direction. It deliberately does not go through the Device --
// at this point in the flow the Device carrying real traffic may not exist
// yet -- and is not itself a WireGuard packet, so X's native Device (or
// any other listener on that port) will not recognize it as one; that's
// fine, its only job is to leave a mapping in Y's NAT.
func Punch(udpConn *net.UDPConn, xNativeAddr netip.AddrPort) error {
	_, err := udpConn.WriteToUDPAddrPort([]byte{0}, xNativeAddr)
	return err
}
