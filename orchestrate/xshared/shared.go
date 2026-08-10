// Package xshared implements X's per-mode shared Device: exactly two
// persistent Device instances exist on X, ever -- one carrying every
// native-mode Y (no obfuscation, each peer individually dialed via its own
// endpoint=) and one carrying every cloaked-mode Y (X's obfuscation
// profile, peers wait passively) -- rather than one Device per connected
// Y. See the plan's "Per-Y isolation on X, reconsidered" note: AWG
// obfuscation is device-scoped, so native and cloaked can never share a
// Device, but nothing requires each native Y to have its own Device, since
// device/peer.go's endpoint semantics are already per-Peer, not
// per-Device.
package xshared

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// Mode selects whether a SharedDevice carries native (unobfuscated) or
// cloaked (obfuscated) traffic. It only affects what AddPeer does with the
// endpoint parameter and what obfuscation config New applies -- SharedDevice
// itself is one implementation for both.
type Mode int

const (
	ModeNative Mode = iota
	ModeCloaked
)

func (m Mode) String() string {
	if m == ModeCloaked {
		return "cloaked"
	}
	return "native"
}

// Config configures a SharedDevice.
type Config struct {
	PrivateKey device.NoisePrivateKey
	ListenPort uint16
	// ObfuscationUAPI is a pre-built block of UAPI device-config lines
	// (e.g. "jc=5\njmin=500\njmax=1000\n...") applied after the private
	// key/listen port. Must be empty for ModeNative (native mode never
	// carries obfuscation, per requirement #4); for ModeCloaked it's the
	// operator's configured obfuscation profile.
	ObfuscationUAPI string
	// PersistentKeepalive, when non-zero, is applied to every peer added
	// via AddPeer -- the mechanism that keeps a native-mode NAT pinhole
	// open once punched.
	PersistentKeepalive time.Duration
}

// SharedDevice wraps one device.Device plus the bookkeeping to add/remove
// peers dynamically according to Mode.
type SharedDevice struct {
	mode Mode
	dev  *device.Device
	cfg  Config
	mu   sync.Mutex // serializes AddPeer/RemovePeer calls against each other
}

// New brings up a SharedDevice: configures private key, listen port, and
// (for ModeCloaked) the obfuscation profile, then starts the Device. No
// peers are configured yet -- use AddPeer.
func New(mode Mode, tunDev tun.Device, bind conn.Bind, cfg Config, logger *device.Logger) (*SharedDevice, error) {
	if mode == ModeNative && cfg.ObfuscationUAPI != "" {
		return nil, fmt.Errorf("xshared: ModeNative must never carry obfuscation config, got: %q", cfg.ObfuscationUAPI)
	}

	dev := device.NewDevice(tunDev, bind, logger)

	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(cfg.PrivateKey[:]))
	fmt.Fprintf(&b, "listen_port=%d\n", cfg.ListenPort)
	if cfg.ObfuscationUAPI != "" {
		b.WriteString(cfg.ObfuscationUAPI)
		if !strings.HasSuffix(cfg.ObfuscationUAPI, "\n") {
			b.WriteByte('\n')
		}
	}
	if err := dev.IpcSet(b.String()); err != nil {
		dev.Close()
		return nil, fmt.Errorf("xshared: configure device: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("xshared: bring device up: %w", err)
	}

	return &SharedDevice{mode: mode, dev: dev, cfg: cfg}, nil
}

// Mode reports which mode this SharedDevice carries.
func (s *SharedDevice) Mode() Mode { return s.mode }

// Device exposes the underlying device.Device for callers that need
// lower-level access (e.g. IpcGet for diagnostics); prefer the typed
// methods below where they suffice.
func (s *SharedDevice) Device() *device.Device { return s.dev }

// AddPeer adds or reconfigures a peer. endpoint set means this Device will
// actively dial out to it (native mode's "X always dials Y" invariant);
// endpoint nil means it waits passively (cloaked mode, or a native peer
// mid-punch before its address is known). Safe to call concurrently with
// other AddPeer/RemovePeer calls; concurrent traffic handling on the
// Device itself is unaffected (device.Device's own locking covers that).
func (s *SharedDevice) AddPeer(pk device.NoisePublicKey, endpoint *netip.AddrPort, allowedIPs []netip.Prefix) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var b strings.Builder
	fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(pk[:]))
	fmt.Fprintf(&b, "replace_allowed_ips=true\n")
	if endpoint != nil {
		fmt.Fprintf(&b, "endpoint=%s\n", endpoint.String())
	}
	if s.cfg.PersistentKeepalive > 0 {
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", int(s.cfg.PersistentKeepalive.Seconds()))
	}
	for _, p := range allowedIPs {
		fmt.Fprintf(&b, "allowed_ip=%s\n", p.String())
	}
	if err := s.dev.IpcSet(b.String()); err != nil {
		return fmt.Errorf("xshared: add peer %x: %w", pk[:4], err)
	}
	return nil
}

// RemovePeer removes exactly one peer. Per the isolation guarantee this
// package exists to provide, this can never affect any other peer on the
// same SharedDevice, nor (since native and cloaked are always separate
// Device instances) the other SharedDevice.
func (s *SharedDevice) RemovePeer(pk device.NoisePublicKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var b strings.Builder
	fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(pk[:]))
	fmt.Fprintf(&b, "remove=true\n")
	if err := s.dev.IpcSet(b.String()); err != nil {
		return fmt.Errorf("xshared: remove peer %x: %w", pk[:4], err)
	}
	return nil
}

// HandshakeTime reports the last completed handshake time for pk, and
// whether that peer is currently configured on this Device at all. Used
// by the native-mode establishment flow's bounded timeout poll (see
// nativeflow) rather than adding a new exported Device method, since
// IpcGet already exposes this over the existing UAPI text protocol.
func (s *SharedDevice) HandshakeTime(pk device.NoisePublicKey) (t time.Time, found bool) {
	out, err := s.dev.IpcGet()
	if err != nil {
		return time.Time{}, false
	}
	return parseHandshakeTime(out, pk)
}

// parseHandshakeTime scans IpcGet's output for pk's peer block and reads
// its last_handshake_time_sec/nsec fields (device/uapi.go's
// IpcGetOperation always emits both, in that order, for every peer -- see
// device/uapi.go:190-195). found is true whenever pk's block was located
// at all, even if no handshake has completed yet (all-zero timestamp).
func parseHandshakeTime(uapi string, pk device.NoisePublicKey) (t time.Time, found bool) {
	want := hex.EncodeToString(pk[:])
	inBlock := false
	var sec, nsec int64

	// asTime reports the zero time.Time{} (not time.Unix(0,0), the Unix
	// epoch) for an all-zero timestamp, so callers can use t.IsZero() to
	// mean "known peer, no handshake yet" the idiomatic way.
	asTime := func() time.Time {
		if sec == 0 && nsec == 0 {
			return time.Time{}
		}
		return time.Unix(sec, nsec)
	}

	for _, line := range bytes.Split([]byte(uapi), []byte("\n")) {
		key, value, ok := strings.Cut(string(line), "=")
		if !ok {
			continue
		}
		switch key {
		case "public_key":
			if inBlock {
				// We were in the target block and just reached the next
				// peer's block without seeing it end any other way --
				// nothing left to find.
				return asTime(), true
			}
			inBlock = value == want
		case "last_handshake_time_sec":
			if inBlock {
				fmt.Sscanf(value, "%d", &sec)
			}
		case "last_handshake_time_nsec":
			if inBlock {
				fmt.Sscanf(value, "%d", &nsec)
			}
		}
	}
	if inBlock {
		return asTime(), true
	}
	return time.Time{}, false
}

// Close tears down the Device.
func (s *SharedDevice) Close() error {
	s.dev.Close()
	return nil
}
