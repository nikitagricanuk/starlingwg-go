// Package orchestrate is the dual-mode connectivity orchestration layer for
// amneziawg-go: it lets a publicly-reachable peer ("X") and a NATed peer
// ("Y") automatically negotiate, over an authenticated out-of-band control
// channel (see the control subpackage), whether to connect in native mode
// (direct, unobfuscated, X dials Y once Y's NAT is punched) or fall back to
// cloaked mode (standard AWG client/server connectivity with X's
// obfuscation profile). It drives device.Device/conn.Bind/tun.Device
// directly as a library, with no external processes or config-file
// rewriting, so it can run inside process-constrained sandboxes such as an
// iOS Network Extension.
//
// Both X and Y run this same package; which role a given process plays is
// runtime configuration (Config.Role), not a code fork. See
// /Users/nikitagricanuk/.claude/plans/implementation-plan-native-cloaked-dual-synthetic-mist.md
// for the full design.
package orchestrate

import (
	"fmt"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/orchestrate/control"
	"github.com/amnezia-vpn/amneziawg-go/v3/orchestrate/netchange"
	"github.com/amnezia-vpn/amneziawg-go/v3/orchestrate/persist"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// Role identifies which side of a dual-mode relationship this process
// plays. It is explicit configuration, never inferred, per requirement #1.
type Role int

const (
	// RoleX is the publicly-reachable side: it listens for the control
	// channel, answers NAT probes, and (in native mode) dials out to each
	// Y once its punched address is known.
	RoleX Role = iota
	// RoleY is the possibly-NATed side: it dials X's control channel,
	// characterizes its own NAT, punches it, and either waits for X to
	// dial in (native mode) or dials X itself (cloaked mode).
	RoleY
)

func (r Role) String() string {
	switch r {
	case RoleX:
		return "X"
	case RoleY:
		return "Y"
	default:
		return fmt.Sprintf("Role(%d)", int(r))
	}
}

func (r Role) toControl() control.Role {
	if r == RoleX {
		return control.RoleX
	}
	return control.RoleY
}

// ObfuscationProfile is X's own AWG obfuscation configuration for its
// shared cloaked Device -- the same jc/jmin/jmax/s1-s4/h1-h4/header-
// protection-key/i1-i5/content-padding-addition settings that already
// exist as UAPI keys (device/uapi.go); this is not new obfuscation
// machinery, just the subset of it X needs to hold onto and apply.
type ObfuscationProfile struct {
	Jc, Jmin, Jmax uint32

	S1, S2, S3, S4 uint32
	H1Lo, H1Hi     uint32
	H2Lo, H2Hi     uint32
	H3Lo, H3Hi     uint32
	H4Lo, H4Hi     uint32

	HasHeaderProtectionKey bool
	HeaderProtectionKey    [32]byte

	I1, I2, I3, I4, I5 string // raw obfuscation-chain spec strings, as accepted by the i1-i5 UAPI keys

	ContentPaddingAdditionLo, ContentPaddingAdditionHi uint32
}

// PeerConfig describes one X relationship from Y's point of view: which X
// to talk to, over the control channel, and the WireGuard-level peer
// parameters used once a mode is established.
type PeerConfig struct {
	// RemotePublicKey is X's WireGuard static public key -- also the
	// identity X's control channel Endpoint authenticates against, and
	// what Y dials Noise_IK against as X's expected key.
	RemotePublicKey device.NoisePublicKey
	// ControlAddr is X's control-channel listen address (host:port),
	// distinct from the AWG data ports.
	ControlAddr string
	AllowedIPs  []string // CIDR strings, as accepted by the allowed_ip UAPI key
}

// PeerAuthorization is X's side of a Y relationship: which Y public keys
// are allowed to negotiate a tunnel at all (the control channel's Noise_IK
// responder rejects anything else before creating any state for it), and
// what AllowedIPs that Y gets routed once connected.
type PeerAuthorization struct {
	PublicKey  device.NoisePublicKey
	AllowedIPs []string
}

// Config configures one Orchestrator. Which fields apply depends on Role;
// unused fields for a given role are simply left zero.
type Config struct {
	Role Role

	// LocalPrivateKey/LocalPublicKey are this process's own WireGuard
	// static keypair, reused as the control channel's Noise_IK identity so
	// no separate key provisioning step is needed (both sides already know
	// each other's WireGuard public key from ordinary peer config).
	LocalPrivateKey device.NoisePrivateKey
	LocalPublicKey  device.NoisePublicKey

	// --- X-only ---

	// ControlListenAddr is where X's control channel Endpoint listens
	// (host:port), e.g. ":41820".
	ControlListenAddr string
	// PublicHost is X's externally-reachable hostname or IP -- the value
	// Y is told to dial for the shared cloaked Device's ListenEndpoint.
	// Deliberately explicit operator configuration rather than derived
	// from ControlListenAddr (which is typically a wildcard bind address,
	// not a dialable one), mirroring how a real WireGuard server config
	// always states its own public Endpoint explicitly.
	PublicHost string
	// ProbePortA/ProbePortB are X's two distinguishable NAT-probe echo
	// ports (see natprobe package).
	ProbePortA, ProbePortB uint16
	// NativeListenPort is the single fixed local port X's shared native
	// Device binds; every native-mode Y is told this port (via XInfo) and
	// aims its punch/expected-return traffic at it, since X only ever
	// dials out from this one shared Device/socket.
	NativeListenPort uint16
	// CloakedListenPort is the fixed local port X's shared cloaked Device
	// binds, exactly like an ordinary AWG server's listen_port.
	CloakedListenPort uint16
	// ObfuscationProfile is applied to X's shared cloaked Device only;
	// the shared native Device never has any obfuscation configured.
	ObfuscationProfile ObfuscationProfile
	// AuthorizedPeers lists every Y allowed to connect at all, and the
	// AllowedIPs each gets. X's control-channel Endpoint rejects any
	// static key not in this list during the Noise_IK handshake itself,
	// before any peer state exists for it.
	AuthorizedPeers []PeerAuthorization
	// NativeTUN backs X's one shared native-mode Device (phase 3/4 scope:
	// a single caller-supplied tun.Device, not yet the dynamic
	// OS-interface lifecycle management planned for a later phase).
	NativeTUN tun.Device
	// CloakedTUN backs X's one shared cloaked-mode Device.
	CloakedTUN tun.Device

	// --- Y-only ---

	// Peers is one entry per X relationship Y maintains.
	Peers []PeerConfig
	// YTUN backs Y's own Device -- the one real interface all of Y's
	// traffic flows through, regardless of which mode ends up active.
	YTUN tun.Device
	// ProtectFn, if non-nil, is called on every raw socket Y creates
	// (control-channel dial, NAT-probe/native-punch UDP sockets) before
	// it's connected/used -- see control.ProtectFn's doc for why this is
	// required on Android specifically (a deterministic self-routing-loop
	// otherwise, not a rare race) and a no-op everywhere else. Nil is the
	// correct value for every non-Android embedder.
	ProtectFn control.ProtectFn

	// --- shared ---

	// NativeHandshakeTimeout bounds how long X waits for a native
	// handshake to complete against a reported address before giving up
	// and falling back to cloaked (requirement #4).
	NativeHandshakeTimeout time.Duration
	// CloakedHandshakeTimeout bounds how long each side waits to confirm
	// the cloaked-mode handshake completed. Deliberately separate from
	// NativeHandshakeTimeout: they bound two different handshakes with
	// potentially different appropriate budgets, and conflating them
	// would make it impossible to tune (or, in tests, force) one without
	// affecting the other.
	CloakedHandshakeTimeout time.Duration

	// Store persists each session's last-known mode so a fresh process
	// (Y-only: X's sessions are recreated per inbound control connection
	// regardless of X's own restarts, so it has nothing to resume) can
	// seed RetryLastMode instead of starting cold at Probing -- and so a
	// supervisor-driven reconnect after a transient, non-network-change
	// connectivity loss can retry the same mode directly rather than
	// re-running full NAT characterization. Nil disables persistence
	// entirely (every start is a cold Probing start).
	Store persist.Store
	// NetworkChange is a host-supplied signal for local network
	// attachment changes (Y-only in practice -- see the netchange
	// package's doc). Firing forces a full re-probe (re-characterize NAT,
	// re-attempt native from scratch) rather than retrying the last mode,
	// since NAT behavior is a property of the network path and may have
	// changed along with it. Nil is treated the same as netchange.Never{}.
	NetworkChange netchange.Detector
	// LivenessCheckInterval is how often a connected Y session's
	// data-tunnel liveness (last observed handshake recency) is checked.
	// Zero uses a sane default (5s).
	LivenessCheckInterval time.Duration
	// StaleAfter is how long a connected Y session's rx_bytes counter (see
	// nativeflow.DeviceRxBytes -- keepalive traffic keeps this climbing
	// even with no application data, unlike last_handshake_time, which
	// only updates on a full rekey roughly every couple of minutes) can go
	// without any progress before the session is considered to have
	// transiently lost connectivity, triggering an immediate reconnect in
	// the same mode (not a full re-probe -- that's NetworkChange's job).
	// Zero uses a sane default (30s).
	StaleAfter time.Duration
	// BackgroundNativeRetryInterval is how often a Y connected in cloaked
	// mode retries native mode in the background, via a throwaway
	// probe-only Device that never touches the live cloaked Device,
	// cutting over only on confirmed success. Zero uses a sane default
	// (2m); a negative value disables background re-attempt entirely.
	BackgroundNativeRetryInterval time.Duration

	Logger *device.Logger
}

func (c Config) livenessCheckInterval() time.Duration {
	if c.LivenessCheckInterval > 0 {
		return c.LivenessCheckInterval
	}
	return 5 * time.Second
}

func (c Config) staleAfter() time.Duration {
	if c.StaleAfter > 0 {
		return c.StaleAfter
	}
	return 30 * time.Second
}

func (c Config) backgroundNativeRetryInterval() time.Duration {
	if c.BackgroundNativeRetryInterval != 0 {
		return c.BackgroundNativeRetryInterval
	}
	return 2 * time.Minute
}

func (c Config) validate() error {
	if c.Logger == nil {
		return fmt.Errorf("orchestrate: Config.Logger must not be nil")
	}
	switch c.Role {
	case RoleX:
		if c.ControlListenAddr == "" {
			return fmt.Errorf("orchestrate: RoleX requires ControlListenAddr")
		}
		if c.PublicHost == "" {
			return fmt.Errorf("orchestrate: RoleX requires PublicHost")
		}
		if c.ProbePortA == 0 || c.ProbePortB == 0 {
			return fmt.Errorf("orchestrate: RoleX requires ProbePortA and ProbePortB")
		}
		if c.ProbePortA == c.ProbePortB {
			return fmt.Errorf("orchestrate: ProbePortA and ProbePortB must differ")
		}
		if c.NativeListenPort == 0 {
			return fmt.Errorf("orchestrate: RoleX requires NativeListenPort")
		}
		if c.CloakedListenPort == 0 {
			return fmt.Errorf("orchestrate: RoleX requires CloakedListenPort")
		}
		if c.NativeListenPort == c.CloakedListenPort {
			return fmt.Errorf("orchestrate: NativeListenPort and CloakedListenPort must differ")
		}
		if c.NativeTUN == nil {
			return fmt.Errorf("orchestrate: RoleX requires NativeTUN")
		}
		if c.CloakedTUN == nil {
			return fmt.Errorf("orchestrate: RoleX requires CloakedTUN")
		}
	case RoleY:
		if len(c.Peers) == 0 {
			return fmt.Errorf("orchestrate: RoleY requires at least one entry in Peers")
		}
		for i, p := range c.Peers {
			if p.ControlAddr == "" {
				return fmt.Errorf("orchestrate: Peers[%d] missing ControlAddr", i)
			}
		}
		if c.YTUN == nil {
			return fmt.Errorf("orchestrate: RoleY requires YTUN")
		}
	default:
		return fmt.Errorf("orchestrate: unknown Role %v", c.Role)
	}
	if c.NativeHandshakeTimeout <= 0 {
		return fmt.Errorf("orchestrate: NativeHandshakeTimeout must be positive")
	}
	if c.CloakedHandshakeTimeout <= 0 {
		return fmt.Errorf("orchestrate: CloakedHandshakeTimeout must be positive")
	}
	return nil
}

func toControlPrivateKey(k device.NoisePrivateKey) control.PrivateKey {
	return control.PrivateKey(k)
}

func toControlPublicKey(k device.NoisePublicKey) control.PublicKey {
	return control.PublicKey(k)
}
