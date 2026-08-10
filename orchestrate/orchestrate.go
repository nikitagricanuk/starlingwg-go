package orchestrate

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/orchestrate/control"
	"github.com/amnezia-vpn/amneziawg-go/v3/orchestrate/nativeflow"
	"github.com/amnezia-vpn/amneziawg-go/v3/orchestrate/natprobe"
	"github.com/amnezia-vpn/amneziawg-go/v3/orchestrate/netchange"
	"github.com/amnezia-vpn/amneziawg-go/v3/orchestrate/xshared"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// modeHint tells runY whether to run the full probing flow from scratch
// (hintNone) or skip straight to cloaked setup (hintCloaked) -- used both
// for resume-on-restart (a persisted LastMode of "cloaked") and for a
// supervising reconnect after a transient, non-network-change
// connectivity loss (Lifecycle, requirement #6 bullet 3). There is no
// hintNative: native is already always attempted first by hintNone's
// normal flow, so "retry native" and "full re-probe" are the same
// sequence -- only skipping straight to cloaked saves anything (avoiding
// a doomed probe+punch cycle for a Y that's already known to need cloaked
// mode).
type modeHint int

const (
	hintNone modeHint = iota
	hintCloaked
)

// Orchestrator drives dual-mode connectivity for one role (X or Y): native
// mode is always attempted first; a Y that can't reach it (symmetric NAT,
// or a native handshake timeout) falls back to cloaked mode automatically,
// with X delivering the exact obfuscation parameters Y must use.
type Orchestrator struct {
	cfg Config

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup // Y-only: outstanding superviseY goroutines

	events chan Event

	mu       sync.Mutex
	sessions map[string]*Session // keyed by remote control addr (Y) or hex pubkey (X)

	// X-only
	native       nativeflow.SharedDevice
	cloaked      nativeflow.SharedDevice
	probeA       *natprobe.Responder
	probeB       *natprobe.Responder
	ctrlListener net.Listener
	ctrlEndpoint *control.Endpoint

	// Y-only: the real, persistent TUN shared across mode switches -- see
	// sharedTUN's doc.
	yTUN *sharedTUN
}

// NewOrchestrator validates cfg and constructs an Orchestrator. Nothing is
// started (no sockets opened, no Devices brought up) until Start.
func NewOrchestrator(cfg Config) (*Orchestrator, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Orchestrator{
		cfg:      cfg,
		sessions: make(map[string]*Session),
		events:   make(chan Event, 32),
		ctx:      ctx,
		cancel:   cancel,
	}, nil
}

// Session returns the Session for a given key (a Y's hex-encoded public
// key on X, or a peer's ControlAddr on Y), or nil if unknown.
func (o *Orchestrator) Session(key string) *Session {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.sessions[key]
}

func (o *Orchestrator) sessionFor(key string) *Session {
	o.mu.Lock()
	defer o.mu.Unlock()
	s, ok := o.sessions[key]
	if !ok {
		s = newSession(func(prev, next State, reason string) { o.emitSessionEvent(key, prev, next, reason) })
		o.sessions[key] = s
	}
	return s
}

// emitSessionEvent translates a Session's state transition into an Event
// (see events.go): entering a Connected* state emits EventConnected with
// the corresponding Mode; actually leaving one (not merely never having
// reached one -- e.g. plain Idle->Probing produces no event) emits
// EventDisconnected.
func (o *Orchestrator) emitSessionEvent(key string, prev, next State, reason string) {
	if mode := modeForState(next); mode != "" {
		o.emit(Event{Kind: EventConnected, SessionKey: key, Mode: mode, Reason: reason})
		return
	}
	if modeForState(prev) != "" {
		o.emit(Event{Kind: EventDisconnected, SessionKey: key, Reason: reason})
	}
}

// Start brings the Orchestrator up: on X, starts the NAT-probe responders,
// the shared native Device, and the control-channel listener; on Y, dials
// every configured X and drives each one's Session to completion (or
// failure) once, synchronously. See runX/runY.
func (o *Orchestrator) Start() error {
	if o.cfg.Role == RoleX {
		return o.startX()
	}
	return o.startY()
}

// Stop tears down everything Start brought up.
func (o *Orchestrator) Stop() {
	o.cancel()
	o.wg.Wait() // let every superviseY goroutine unwind before tearing down Devices/TUN under it
	if o.probeA != nil {
		o.probeA.Close()
	}
	if o.probeB != nil {
		o.probeB.Close()
	}
	if o.ctrlListener != nil {
		o.ctrlListener.Close()
	}
	if o.native != nil {
		o.native.Close()
		o.emit(Event{Kind: EventInterfaceDown, InterfaceName: interfaceName(o.cfg.NativeTUN)})
	}
	if o.cloaked != nil {
		o.cloaked.Close()
		o.emit(Event{Kind: EventInterfaceDown, InterfaceName: interfaceName(o.cfg.CloakedTUN)})
	}
	o.mu.Lock()
	for _, s := range o.sessions {
		s.closeDevice()
	}
	o.mu.Unlock()
	if o.cfg.Role == RoleY && o.yTUN != nil {
		o.yTUN.Shutdown()
	}
}

// interfaceName reads tunDev's real OS interface name for an
// EventInterfaceUp/Down's InterfaceName field, falling back to a
// descriptive placeholder if the TUN can't report one (e.g. a test
// double) rather than leaving the event's most useful field silently
// empty.
func interfaceName(tunDev tun.Device) string {
	if tunDev == nil {
		return ""
	}
	name, err := tunDev.Name()
	if err != nil || name == "" {
		return "(unknown)"
	}
	return name
}

func randomSessionID() control.SessionID {
	var id control.SessionID
	cryptorand.Read(id[:])
	return id
}

func parsePrefixes(cidrs []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("orchestrate: invalid AllowedIPs entry %q: %w", c, err)
		}
		out = append(out, p)
	}
	return out, nil
}

// --- X side ---

func (o *Orchestrator) startX() error {
	probeAAddr := fmt.Sprintf("0.0.0.0:%d", o.cfg.ProbePortA)
	probeBAddr := fmt.Sprintf("0.0.0.0:%d", o.cfg.ProbePortB)
	var err error
	if o.probeA, err = natprobe.NewResponder(probeAAddr, o.cfg.Logger, nil); err != nil {
		return fmt.Errorf("orchestrate: start NAT probe responder A: %w", err)
	}
	if o.probeB, err = natprobe.NewResponder(probeBAddr, o.cfg.Logger, nil); err != nil {
		o.probeA.Close()
		return fmt.Errorf("orchestrate: start NAT probe responder B: %w", err)
	}
	go o.probeA.Serve()
	go o.probeB.Serve()

	nativeName := interfaceName(o.cfg.NativeTUN)
	if o.cfg.NativeDataPlane != nil {
		// A caller that already built its own native-mode SharedDevice
		// (e.g. one driving a real kernel WireGuard interface instead of
		// this package's in-process Go device.Device) takes precedence
		// over constructing the default xshared/tun.Device-backed one --
		// see nativeflow.SharedDevice's doc for why any implementation of
		// that small interface is interchangeable here.
		o.native = o.cfg.NativeDataPlane
		if o.cfg.NativeInterfaceName != "" {
			nativeName = o.cfg.NativeInterfaceName
		}
	} else {
		o.native, err = xshared.New(xshared.ModeNative, o.cfg.NativeTUN, conn.NewDefaultBind(), xshared.Config{
			PrivateKey: o.cfg.LocalPrivateKey,
			ListenPort: o.cfg.NativeListenPort,
			// PersistentKeepalive is required, not optional, on the shared
			// native Device: without it, a freshly added peer with endpoint=
			// set never actually dials out until *some* trigger fires (see
			// nativeflow's AttemptOnX doc and the test that caught this).
			PersistentKeepalive: nativeflow.DefaultPollInterval * 4,
		}, o.cfg.Logger)
		if err != nil {
			o.probeA.Close()
			o.probeB.Close()
			return fmt.Errorf("orchestrate: bring up shared native Device: %w", err)
		}
	}

	cloakedName := interfaceName(o.cfg.CloakedTUN)
	if o.cfg.CloakedDataPlane != nil {
		o.cloaked = o.cfg.CloakedDataPlane
		if o.cfg.CloakedInterfaceName != "" {
			cloakedName = o.cfg.CloakedInterfaceName
		}
	} else {
		o.cloaked, err = xshared.New(xshared.ModeCloaked, o.cfg.CloakedTUN, conn.NewDefaultBind(), xshared.Config{
			PrivateKey:      o.cfg.LocalPrivateKey,
			ListenPort:      o.cfg.CloakedListenPort,
			ObfuscationUAPI: o.cfg.ObfuscationProfile.uapi(),
		}, o.cfg.Logger)
		if err != nil {
			o.Stop()
			return fmt.Errorf("orchestrate: bring up shared cloaked Device: %w", err)
		}
	}

	o.emit(Event{Kind: EventInterfaceUp, InterfaceName: nativeName})
	o.emit(Event{Kind: EventInterfaceUp, InterfaceName: cloakedName})

	ln, err := net.Listen("tcp", o.cfg.ControlListenAddr)
	if err != nil {
		o.Stop()
		return fmt.Errorf("orchestrate: listen on ControlListenAddr: %w", err)
	}
	o.ctrlListener = ln

	authorized := make(map[control.PublicKey]PeerAuthorization, len(o.cfg.AuthorizedPeers))
	for _, p := range o.cfg.AuthorizedPeers {
		authorized[toControlPublicKey(p.PublicKey)] = p
	}
	o.ctrlEndpoint = control.NewEndpoint(toControlPrivateKey(o.cfg.LocalPrivateKey), func(pk control.PublicKey) bool {
		_, ok := authorized[pk]
		return ok
	})

	go o.ctrlEndpoint.Serve(ln, func(c *control.Conn) {
		auth := authorized[c.RemoteStatic]
		o.handleXConn(c, auth)
	}, func(nc net.Conn, err error) {
		nc.Close()
		o.cfg.Logger.Verbosef("orchestrate: rejected control connection: %v", err)
	})

	return nil
}

func (o *Orchestrator) handleXConn(c *control.Conn, auth PeerAuthorization) {
	defer c.Close()
	remotePub := device.NoisePublicKey(c.RemoteStatic)
	key := fmt.Sprintf("%x", remotePub[:])
	sess := o.sessionFor(key)
	sess.setState(StateProbing, "")

	hello := control.Hello{Role: control.RoleX, WGPublicKey: [32]byte(o.cfg.LocalPublicKey), ProtocolVersion: 1}
	if err := c.Send(hello); err != nil {
		return
	}
	info := control.XInfo{
		ProbePortA:        o.cfg.ProbePortA,
		ProbePortB:        o.cfg.ProbePortB,
		NativeListenPort:  o.cfg.NativeListenPort,
		CloakedListenPort: o.cfg.CloakedListenPort,
	}
	if err := c.Send(info); err != nil {
		return
	}

	allowedIPs, err := parsePrefixes(auth.AllowedIPs)
	if err != nil {
		o.cfg.Logger.Errorf("orchestrate: %v", err)
		return
	}

	for {
		msg, err := c.Recv()
		if err != nil {
			return
		}
		switch m := msg.(type) {
		case control.NativeEndpointReport:
			sess.setState(StateNativeAttempting, "")
			res := nativeflow.AttemptOnX(o.native, remotePub, allowedIPs, m.ExternalAddr, o.cfg.NativeHandshakeTimeout)
			if res.Success {
				sess.setDevice(o.native.Device(), nil)
				sess.setState(StateConnectedNative, "")
				c.Send(control.NativeReady{SessionID: m.SessionID})
				continue
			}
			if err := c.Send(control.NativeFailed{SessionID: m.SessionID, Reason: res.Reason}); err != nil {
				return
			}
			// Native didn't work out -- fall back to cloaked automatically,
			// in the same exchange, rather than making Y ask for it
			// separately (requirement: fallback must be transparent, no
			// user/extra-round-trip intervention).
			o.fallbackToCloaked(c, sess, remotePub, allowedIPs)
		case control.ModeDecision:
			// Y determined up front (symmetric NAT) that native is
			// hopeless and skipped straight here.
			if m.Mode == control.ModeCloaked {
				o.fallbackToCloaked(c, sess, remotePub, allowedIPs)
			}
		case control.Ping:
			c.Send(control.Pong{Nonce: m.Nonce})
		case control.Bye:
			return
		}
	}
}

// fallbackToCloaked adds remotePub to X's shared cloaked Device and sends
// it the exact obfuscation parameters it must use (requirement #5). Called
// either right after a native timeout or in response to Y's own
// symmetric-NAT ModeDecision -- both converge on the same cloaked setup.
func (o *Orchestrator) fallbackToCloaked(c *control.Conn, sess *Session, remotePub device.NoisePublicKey, allowedIPs []netip.Prefix) {
	sess.setState(StateProbing, "cloaked-setup")
	if err := o.cloaked.AddPeer(remotePub, nil, allowedIPs); err != nil {
		sess.setState(StateFailed, fmt.Sprintf("cloaked AddPeer failed: %v", err))
		return
	}
	xAddr, err := resolvePublicHost(o.cfg.PublicHost)
	if err != nil {
		sess.setState(StateFailed, err.Error())
		return
	}
	listenEndpoint := netip.AddrPortFrom(xAddr, o.cfg.CloakedListenPort)
	params := o.cfg.ObfuscationProfile.toWireParams(listenEndpoint)
	if err := c.Send(params); err != nil {
		sess.setState(StateFailed, err.Error())
		return
	}
	sess.setDevice(o.cloaked.Device(), nil)
	// X is passive in cloaked mode -- it can't "dial" to confirm success
	// the way AttemptOnX does for native, but it can still poll for the
	// same handshake-completion signal Y's own connect attempt will
	// produce, so "connected" here means an observed handshake, not just
	// "peer configured and hoping."
	deadline := time.Now().Add(o.cfg.CloakedHandshakeTimeout)
	for time.Now().Before(deadline) {
		if t, found := o.cloaked.HandshakeTime(remotePub); found && !t.IsZero() {
			sess.setState(StateConnectedCloaked, "")
			return
		}
		time.Sleep(nativeflow.DefaultPollInterval)
	}
	sess.setState(StateFailed, "cloaked-handshake-timeout")
}

// --- Y side ---

func (o *Orchestrator) startY() error {
	o.yTUN = newSharedTUN(o.cfg.YTUN)
	o.cfg.Logger.Verbosef("orchestrate: startY: %d configured peer(s)", len(o.cfg.Peers))
	var firstErr error
	for _, pc := range o.cfg.Peers {
		hint := hintNone
		if rec, ok := o.loadSession(pc.ControlAddr); ok && rec.LastMode == "cloaked" {
			hint = hintCloaked
		}
		o.cfg.Logger.Verbosef("orchestrate: startY: starting session with %s (hint=%v)", pc.ControlAddr, hint)
		if err := o.runY(pc, hint); err != nil {
			o.cfg.Logger.Errorf("orchestrate: session with %s failed: %v", pc.ControlAddr, err)
			if firstErr == nil {
				firstErr = err
			}
			// Deliberately not `continue`-ing past superviseY: a failed
			// *first* attempt (e.g. a cloaked handshake that didn't
			// complete in time) must retry just like a connection that
			// succeeded and later went stale does -- see superviseY's
			// StateFailed/StateIdle handling. Without this, any transient
			// failure on the very first attempt stranded the session
			// permanently, since supervision (all retry logic) previously
			// only ever started after an initial success.
		}
		o.wg.Add(1)
		go o.superviseY(pc)
	}
	return firstErr
}

// connectXInfo dials pc's control channel and completes the Hello/XInfo
// exchange every flow that talks to X needs before it can do anything
// else -- the primary connection attempt (runY) and the background
// native re-attempt (attemptBackgroundNative) both start here. The
// returned Conn is the caller's to Close.
func (o *Orchestrator) connectXInfo(pc PeerConfig) (cc *control.Conn, info control.XInfo, xAddr netip.Addr, err error) {
	cc, err = control.DialProtected(pc.ControlAddr, toControlPrivateKey(o.cfg.LocalPrivateKey), toControlPublicKey(pc.RemotePublicKey), o.cfg.ProtectFn)
	if err != nil {
		return nil, control.XInfo{}, netip.Addr{}, fmt.Errorf("dial control channel: %w", err)
	}
	if err = cc.Send(control.Hello{Role: control.RoleY, WGPublicKey: [32]byte(o.cfg.LocalPublicKey), ProtocolVersion: 1}); err != nil {
		cc.Close()
		return nil, control.XInfo{}, netip.Addr{}, err
	}
	helloMsg, err := cc.Recv()
	if err != nil {
		cc.Close()
		return nil, control.XInfo{}, netip.Addr{}, fmt.Errorf("receive Hello: %w", err)
	}
	if _, ok := helloMsg.(control.Hello); !ok {
		cc.Close()
		return nil, control.XInfo{}, netip.Addr{}, fmt.Errorf("expected Hello, got %T", helloMsg)
	}
	infoMsg, err := cc.Recv()
	if err != nil {
		cc.Close()
		return nil, control.XInfo{}, netip.Addr{}, fmt.Errorf("receive XInfo: %w", err)
	}
	info, ok := infoMsg.(control.XInfo)
	if !ok {
		cc.Close()
		return nil, control.XInfo{}, netip.Addr{}, fmt.Errorf("expected XInfo, got %T", infoMsg)
	}

	xHost, _, err := net.SplitHostPort(pc.ControlAddr)
	if err != nil {
		cc.Close()
		return nil, control.XInfo{}, netip.Addr{}, fmt.Errorf("parse X host from ControlAddr: %w", err)
	}
	xAddr, err = netip.ParseAddr(xHost)
	if err != nil {
		xAddr, err = resolveHost(xHost)
		if err != nil {
			cc.Close()
			return nil, control.XInfo{}, netip.Addr{}, fmt.Errorf("resolve X host: %w", err)
		}
	}
	return cc, info, xAddr, nil
}

// singleFamilyUDP binds a UDP socket matching addr's address family. A
// bare "udp"/nil-IP listen creates a dual-stack wildcard socket whose
// LocalAddr() (and, on some platforms, whose outbound routing) reports as
// an IPv6 wildcard even when only ever talking IPv4 -- which then
// confuses the peer trying to dial back an address derived from it.
//
// protect, if non-nil, is applied to the fd before it's used -- see
// control.ProtectFn's doc; required on Android for the same
// self-routing-loop reason as the control-channel dial, since this socket
// is used for NAT probing and (in native mode) the punch/data path itself.
func singleFamilyUDP(addr netip.Addr, protect control.ProtectFn) (*net.UDPConn, error) {
	network, bindIP := "udp4", "0.0.0.0"
	if addr.Is6() && !addr.Is4In6() {
		network, bindIP = "udp6", "::"
	}
	lc := net.ListenConfig{}
	if protect != nil {
		lc.Control = func(_, _ string, c syscall.RawConn) error {
			var protectErr error
			if err := c.Control(func(fd uintptr) {
				if !protect(int(fd)) {
					protectErr = fmt.Errorf("orchestrate: protect failed for fd %d", fd)
				}
			}); err != nil {
				return err
			}
			return protectErr
		}
	}
	pc, err := lc.ListenPacket(context.Background(), network, fmt.Sprintf("%s:0", bindIP))
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

// runY drives one full connection attempt for pc to completion: dial,
// negotiate, and either land Connected(Native) or Connected(Cloaked) (or
// fail outright). hint skips straight to cloaked setup when the caller
// already knows (from persisted state, or from a prior connection in this
// same process) that native isn't going to work -- see modeHint's doc.
// Called both for the initial connection (from startY) and for every
// reconnect a supervising superviseY drives afterward.
func (o *Orchestrator) runY(pc PeerConfig, hint modeHint) error {
	o.cfg.Logger.Verbosef("orchestrate: runY(%s): entered, dialing control channel", pc.ControlAddr)
	sess := o.sessionFor(pc.ControlAddr)
	sess.setState(StateProbing, "")

	cc, info, xAddr, err := o.connectXInfo(pc)
	if err != nil {
		o.cfg.Logger.Errorf("orchestrate: runY(%s): connectXInfo failed: %v", pc.ControlAddr, err)
		sess.setState(StateFailed, err.Error())
		return err
	}
	o.cfg.Logger.Verbosef("orchestrate: runY(%s): control channel connected, XInfo=%+v, xAddr=%s", pc.ControlAddr, info, xAddr)
	defer cc.Close()

	allowedIPs, err := parsePrefixes(pc.AllowedIPs)
	if err != nil {
		o.cfg.Logger.Errorf("orchestrate: runY(%s): parsePrefixes failed: %v", pc.ControlAddr, err)
		sess.setState(StateFailed, err.Error())
		return err
	}

	if hint == hintCloaked {
		o.cfg.Logger.Verbosef("orchestrate: runY(%s): hint=cloaked, skipping native probe", pc.ControlAddr)
		sess.setState(StateProbing, "cloaked-setup")
		if err := cc.Send(control.ModeDecision{Mode: control.ModeCloaked, Reason: "retry-last-mode"}); err != nil {
			o.cfg.Logger.Errorf("orchestrate: runY(%s): send ModeDecision failed: %v", pc.ControlAddr, err)
			sess.setState(StateFailed, err.Error())
			return err
		}
		return o.runYCloaked(cc, sess, pc, allowedIPs)
	}

	ySocket, err := singleFamilyUDP(xAddr, o.cfg.ProtectFn)
	if err != nil {
		o.cfg.Logger.Errorf("orchestrate: runY(%s): open Y socket failed: %v", pc.ControlAddr, err)
		sess.setState(StateFailed, err.Error())
		return fmt.Errorf("open Y socket: %w", err)
	}
	o.cfg.Logger.Verbosef("orchestrate: runY(%s): Y socket open (local %s), characterizing NAT", pc.ControlAddr, ySocket.LocalAddr())

	portA := netip.AddrPortFrom(xAddr, info.ProbePortA)
	portB := netip.AddrPortFrom(xAddr, info.ProbePortB)
	result, err := natprobe.Characterize(ySocket, portA, portB, natprobe.DefaultTimeout, natprobe.DefaultRetries)
	o.cfg.Logger.Verbosef("orchestrate: runY(%s): NAT characterize result=%+v err=%v", pc.ControlAddr, result, err)
	if err != nil || result.Class != natprobe.Cone {
		ySocket.Close()
		reason := "symmetric-or-unknown-nat"
		if err != nil {
			reason = err.Error()
		}
		o.cfg.Logger.Verbosef("orchestrate: runY(%s): NAT not cone-type (%s), falling back to cloaked", pc.ControlAddr, reason)
		sess.setState(StateFailed, reason)
		if err := cc.Send(control.ModeDecision{Mode: control.ModeCloaked, Reason: reason}); err != nil {
			o.cfg.Logger.Errorf("orchestrate: runY(%s): send ModeDecision failed: %v", pc.ControlAddr, err)
			return fmt.Errorf("send ModeDecision: %w", err)
		}
		return o.runYCloaked(cc, sess, pc, allowedIPs)
	}

	sess.setState(StateNativeAttempting, "")

	nativeAddr := netip.AddrPortFrom(xAddr, info.NativeListenPort)
	o.cfg.Logger.Verbosef("orchestrate: runY(%s): cone-type NAT, punching %s", pc.ControlAddr, nativeAddr)
	if err := nativeflow.Punch(ySocket, nativeAddr); err != nil {
		ySocket.Close()
		o.cfg.Logger.Errorf("orchestrate: runY(%s): punch failed: %v", pc.ControlAddr, err)
		sess.setState(StateFailed, err.Error())
		return fmt.Errorf("punch: %w", err)
	}

	yBind := nativeflow.NewPreboundBind(ySocket)
	yDev, err := nativeflow.PreparePassiveDevice(o.yTUN.attach(), yBind, nativeflow.YDeviceConfig{
		PrivateKey:      o.cfg.LocalPrivateKey,
		RemotePublicKey: pc.RemotePublicKey,
		AllowedIPs:      allowedIPs,
	}, o.cfg.Logger)
	if err != nil {
		ySocket.Close()
		o.cfg.Logger.Errorf("orchestrate: runY(%s): prepare Y device failed: %v", pc.ControlAddr, err)
		sess.setState(StateFailed, err.Error())
		return fmt.Errorf("prepare Y device: %w", err)
	}

	sid := randomSessionID()
	o.cfg.Logger.Verbosef("orchestrate: runY(%s): reporting external addr %s to X, waiting for native result", pc.ControlAddr, result.ExternalAddr)
	if err := cc.Send(control.NativeEndpointReport{SessionID: sid, ExternalAddr: result.ExternalAddr}); err != nil {
		o.cfg.Logger.Errorf("orchestrate: runY(%s): send NativeEndpointReport failed: %v", pc.ControlAddr, err)
		yDev.Close()
		sess.setState(StateFailed, err.Error())
		return err
	}

	for {
		msg, err := cc.Recv()
		if err != nil {
			o.cfg.Logger.Errorf("orchestrate: runY(%s): receive native result failed: %v", pc.ControlAddr, err)
			yDev.Close()
			sess.setState(StateFailed, err.Error())
			return fmt.Errorf("receive native result: %w", err)
		}
		o.cfg.Logger.Verbosef("orchestrate: runY(%s): received %T while waiting for native result", pc.ControlAddr, msg)
		switch m := msg.(type) {
		case control.NativeReady:
			if m.SessionID != sid {
				continue
			}
			o.cfg.Logger.Verbosef("orchestrate: runY(%s): native connected", pc.ControlAddr)
			// ySocket is the real fd PreboundBind wraps but never closes
			// itself (see its doc) -- Session tracks it as an extra closer
			// so Orchestrator.Stop()'s teardown actually frees it instead
			// of leaking one socket per native-mode session.
			sess.setDevice(yDev, ySocket)
			sess.setState(StateConnectedNative, "")
			o.saveSession(pc.ControlAddr, "native", result.ExternalAddr.String())
			return nil
		case control.NativeFailed:
			if m.SessionID != sid {
				continue
			}
			o.cfg.Logger.Verbosef("orchestrate: runY(%s): native failed (%s), falling back to cloaked", pc.ControlAddr, m.Reason)
			// The native passive Device never completed a handshake --
			// tear it down and fall back to cloaked, transparently, on
			// this same control connection (X sends CloakedParams right
			// after NativeFailed, no extra round trip needed).
			//
			// yDev.Close() returns promptly: PreboundBind.Close() still
			// doesn't truly close ySocket (see its doc -- a real close
			// risks the same silent-breakage race the TUN side has, if a
			// spurious BindUpdate() churn ever follows), but it now
			// reports the interrupted read as net.ErrClosed rather than a
			// bare deadline error, so device/receive.go's
			// RoutineReceiveIncoming recognizes it as terminal instead of
			// retrying it as transient.
			// Once Close() has fully returned here, though, we know for
			// certain no further Open() will ever be called on this bind
			// again (Device.Close() is terminal) -- so it's safe to
			// actually close the socket now and free its fd for real,
			// which PreboundBind itself never does.
			yDev.Close()
			ySocket.Close()
			sess.setState(StateFailed, m.Reason)
			return o.runYCloaked(cc, sess, pc, allowedIPs)
		}
	}
}

// runYCloaked waits for X's CloakedParams (sent either right after
// NativeFailed or in response to Y's own symmetric-NAT ModeDecision) and
// connects as a standard AWG client using them -- Y is the client here,
// standard role, exactly like ordinary WireGuard/AWG connectivity from
// this point on.
func (o *Orchestrator) runYCloaked(cc *control.Conn, sess *Session, pc PeerConfig, allowedIPs []netip.Prefix) error {
	o.cfg.Logger.Verbosef("orchestrate: runYCloaked(%s): entered, waiting for CloakedParams", pc.ControlAddr)
	sess.setState(StateProbing, "cloaked-setup")

	for {
		msg, err := cc.Recv()
		if err != nil {
			o.cfg.Logger.Errorf("orchestrate: runYCloaked(%s): receive CloakedParams failed: %v", pc.ControlAddr, err)
			sess.setState(StateFailed, err.Error())
			return fmt.Errorf("receive CloakedParams: %w", err)
		}
		params, ok := msg.(control.CloakedParams)
		if !ok {
			o.cfg.Logger.Verbosef("orchestrate: runYCloaked(%s): received %T while waiting for CloakedParams, ignoring", pc.ControlAddr, msg)
			continue // e.g. a stray Ping while we're waiting -- ignore
		}
		o.cfg.Logger.Verbosef("orchestrate: runYCloaked(%s): got CloakedParams, endpoint=%s", pc.ControlAddr, params.ListenEndpoint)

		dev := device.NewDevice(o.yTUN.attach(), conn.NewDefaultBind(), o.cfg.Logger)
		var b strings.Builder
		fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(o.cfg.LocalPrivateKey[:]))
		fmt.Fprintf(&b, "listen_port=0\n")
		b.WriteString(cloakedParamsUAPI(params))
		fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(pc.RemotePublicKey[:]))
		fmt.Fprintf(&b, "endpoint=%s\n", params.ListenEndpoint.String())
		// Same reasoning as the shared native Device's PersistentKeepalive
		// (see xshared.Config's doc): handlePostConfig only flushes
		// *already staged* outbound packets, so without a keepalive
		// interval a freshly configured peer with no application traffic
		// yet would never actually dial out at all.
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", int(nativeflow.DefaultPollInterval.Seconds()*4)+1)
		fmt.Fprintf(&b, "replace_allowed_ips=true\n")
		for _, p := range allowedIPs {
			fmt.Fprintf(&b, "allowed_ip=%s\n", p.String())
		}
		if err := dev.IpcSet(b.String()); err != nil {
			o.cfg.Logger.Errorf("orchestrate: runYCloaked(%s): IpcSet failed: %v", pc.ControlAddr, err)
			dev.Close()
			sess.setState(StateFailed, err.Error())
			return fmt.Errorf("configure cloaked Y device: %w", err)
		}
		if err := dev.Up(); err != nil {
			o.cfg.Logger.Errorf("orchestrate: runYCloaked(%s): dev.Up() failed: %v", pc.ControlAddr, err)
			dev.Close()
			sess.setState(StateFailed, err.Error())
			return fmt.Errorf("bring up cloaked Y device: %w", err)
		}
		o.cfg.Logger.Verbosef("orchestrate: runYCloaked(%s): cloaked device up, polling for handshake (timeout=%s)", pc.ControlAddr, o.cfg.CloakedHandshakeTimeout)

		deadline := time.Now().Add(o.cfg.CloakedHandshakeTimeout)
		for time.Now().Before(deadline) {
			if t, found := nativeflow.DeviceHandshakeTime(dev, pc.RemotePublicKey); found && !t.IsZero() {
				o.cfg.Logger.Verbosef("orchestrate: runYCloaked(%s): cloaked handshake confirmed at %s", pc.ControlAddr, t)
				sess.setDevice(dev, nil) // conn.NewDefaultBind() owns and closes its own socket
				sess.setState(StateConnectedCloaked, "")
				o.saveSession(pc.ControlAddr, "cloaked", "")
				return nil
			}
			time.Sleep(nativeflow.DefaultPollInterval)
		}
		o.cfg.Logger.Verbosef("orchestrate: runYCloaked(%s): cloaked handshake timed out after %s", pc.ControlAddr, o.cfg.CloakedHandshakeTimeout)
		dev.Close()
		sess.setState(StateFailed, "cloaked-handshake-timeout")
		return fmt.Errorf("cloaked mode handshake timed out")
	}
}

// superviseY keeps pc's session alive after runY's initial connection
// attempt succeeds: it watches for network-change events (forcing a full
// re-probe, since NAT behavior may have changed along with the network
// path), watches the live Device's handshake recency for a transient
// connectivity loss (triggering an immediate reconnect in the same mode,
// no re-probe), and -- while Connected(Cloaked) -- periodically retries
// native mode in the background, cutting over only on confirmed success.
// Runs until o.ctx is canceled (by Stop).
func (o *Orchestrator) superviseY(pc PeerConfig) {
	defer o.wg.Done()
	sess := o.sessionFor(pc.ControlAddr)

	var netChangeCh <-chan netchange.ChangeEvent
	if o.cfg.NetworkChange != nil {
		if ch, err := o.cfg.NetworkChange.Subscribe(o.ctx); err == nil {
			netChangeCh = ch
		} else {
			o.cfg.Logger.Errorf("orchestrate: network-change Subscribe failed for %s: %v", pc.ControlAddr, err)
		}
	}

	livenessTicker := time.NewTicker(o.cfg.livenessCheckInterval())
	defer livenessTicker.Stop()

	bgInterval := o.cfg.backgroundNativeRetryInterval()
	var lastBgAttempt time.Time

	// rx_bytes progress tracking for the staleness check below -- reset
	// (via lastDev's mismatch check) every time sess.Device() changes,
	// i.e. every reconnect, so a brand-new Device's initially-lower
	// rx_bytes is never mistaken for "no progress."
	var lastDev *device.Device
	var lastRx uint64
	var lastProgress time.Time

	for {
		select {
		case <-o.ctx.Done():
			return

		case ev, ok := <-netChangeCh:
			if !ok {
				netChangeCh = nil
				continue
			}
			o.cfg.Logger.Verbosef("orchestrate: network change (%s) for %s -- forcing full re-probe", ev.Reason, pc.ControlAddr)
			sess.closeDevice()
			if err := o.runY(pc, hintNone); err != nil {
				o.cfg.Logger.Verbosef("orchestrate: re-probe for %s failed: %v", pc.ControlAddr, err)
			}
			lastDev = nil

		case <-livenessTicker.C:
			state, _ := sess.State()
			switch state {
			case StateConnectedNative, StateConnectedCloaked:
				dev := sess.Device()
				rx, found := nativeflow.DeviceRxBytes(dev, pc.RemotePublicKey)
				if dev != lastDev || rx != lastRx || lastProgress.IsZero() {
					lastDev, lastRx, lastProgress = dev, rx, time.Now()
				}
				if !found || time.Since(lastProgress) >= o.cfg.staleAfter() {
					o.cfg.Logger.Verbosef("orchestrate: %s connection to %s went stale -- retrying last mode", state, pc.ControlAddr)
					hint := hintNone
					if state == StateConnectedCloaked {
						hint = hintCloaked
					}
					sess.closeDevice()
					if err := o.runY(pc, hint); err != nil {
						o.cfg.Logger.Verbosef("orchestrate: reconnect for %s failed: %v", pc.ControlAddr, err)
					}
					lastDev = nil
					continue
				}
				if state == StateConnectedCloaked && bgInterval > 0 &&
					(lastBgAttempt.IsZero() || time.Since(lastBgAttempt) >= bgInterval) {
					lastBgAttempt = time.Now()
					if o.attemptBackgroundNative(pc, sess) {
						o.cfg.Logger.Verbosef("orchestrate: background native re-attempt for %s succeeded -- upgraded from cloaked", pc.ControlAddr)
						lastDev = nil
					}
				}

			case StateFailed, StateIdle:
				// Retry a session that never connected in the first place
				// (StateFailed: the initial attempt's native+cloaked
				// handshakes both failed/timed out) or never got started
				// (StateIdle) -- the same runY call the network-change and
				// staleness branches above already use for every other
				// kind of reconnect. This naturally rate-limits itself:
				// runY blocks synchronously for up to
				// NativeHandshakeTimeout+CloakedHandshakeTimeout before
				// returning, so retries are spaced by however long each
				// full attempt actually takes, not by the ticker interval.
				o.cfg.Logger.Verbosef("orchestrate: retrying %s connection to %s", state, pc.ControlAddr)
				if err := o.runY(pc, hintNone); err != nil {
					o.cfg.Logger.Verbosef("orchestrate: retry for %s failed: %v", pc.ControlAddr, err)
				}
				lastDev = nil
			}
		}
	}
}

// attemptBackgroundNative is Y's background native re-attempt while
// already Connected(Cloaked) (requirement #6 bullet 2): it dials a fresh,
// separate control connection and drives the same characterize -> punch
// -> report -> wait-for-NativeReady sequence runY's primary flow uses,
// but on a throwaway socket and a Device backed by
// nativeflow.NewNoopTUN instead of Y's real shared TUN, so a failed trial
// never touches the live, traffic-carrying cloaked Device or steals its
// TUN session. Only a confirmed NativeReady triggers the cutover: build
// the real native Device (attached to o.yTUN) on the same now-proven
// socket, swap it into sess, and only then close the old cloaked Device.
func (o *Orchestrator) attemptBackgroundNative(pc PeerConfig, sess *Session) bool {
	cc, info, xAddr, err := o.connectXInfo(pc)
	if err != nil {
		return false
	}
	defer cc.Close()

	allowedIPs, err := parsePrefixes(pc.AllowedIPs)
	if err != nil {
		return false
	}

	probeSocket, err := singleFamilyUDP(xAddr, o.cfg.ProtectFn)
	if err != nil {
		return false
	}
	succeeded := false
	defer func() {
		if !succeeded {
			probeSocket.Close()
		}
	}()

	portA := netip.AddrPortFrom(xAddr, info.ProbePortA)
	portB := netip.AddrPortFrom(xAddr, info.ProbePortB)
	result, err := natprobe.Characterize(probeSocket, portA, portB, natprobe.DefaultTimeout, natprobe.DefaultRetries)
	if err != nil || result.Class != natprobe.Cone {
		return false
	}

	nativeAddr := netip.AddrPortFrom(xAddr, info.NativeListenPort)
	if err := nativeflow.Punch(probeSocket, nativeAddr); err != nil {
		return false
	}

	probeDev, err := nativeflow.PreparePassiveDevice(nativeflow.NewNoopTUN(1420), nativeflow.NewPreboundBind(probeSocket), nativeflow.YDeviceConfig{
		PrivateKey:      o.cfg.LocalPrivateKey,
		RemotePublicKey: pc.RemotePublicKey,
		AllowedIPs:      allowedIPs,
	}, o.cfg.Logger)
	if err != nil {
		return false
	}
	defer func() {
		if !succeeded {
			probeDev.Close()
		}
	}()

	sid := randomSessionID()
	if err := cc.Send(control.NativeEndpointReport{SessionID: sid, ExternalAddr: result.ExternalAddr}); err != nil {
		return false
	}

	deadline := time.Now().Add(o.cfg.NativeHandshakeTimeout)
	for time.Now().Before(deadline) {
		msg, err := cc.Recv()
		if err != nil {
			return false
		}
		switch m := msg.(type) {
		case control.NativeReady:
			if m.SessionID != sid {
				continue
			}
			// The handshake X just confirmed belongs to the throwaway probe
			// Device's own Noise session (keypairs live on whichever Device
			// actually did the handshake) -- a fresh device.Device sharing
			// the same socket starts with none, so simply swapping in a new
			// Device here would leave X happily encrypting traffic to a
			// session realDev has no way to decrypt. probeDev confirmed
			// reachability only; the real Device needs its own, second,
			// fresh handshake before it can be trusted.
			//
			// probeDev.Close() blocks a few seconds (PreboundBind.Close only
			// interrupts the pending read via a deadline; device/receive.go
			// treats the resulting timeout as transient and retries with
			// backoff before giving up -- the same bounded, non-fatal cost
			// documented on runY's NativeFailed path) but never closes
			// probeSocket itself, so it's safe to build the real Device on
			// that same socket immediately after.
			probeDev.Close()
			realDev, err := nativeflow.PreparePassiveDevice(o.yTUN.attach(), nativeflow.NewPreboundBind(probeSocket), nativeflow.YDeviceConfig{
				PrivateKey:      o.cfg.LocalPrivateKey,
				RemotePublicKey: pc.RemotePublicKey,
				AllowedIPs:      allowedIPs,
			}, o.cfg.Logger)
			if err != nil {
				return false
			}

			sid2 := randomSessionID()
			if err := cc.Send(control.NativeEndpointReport{SessionID: sid2, ExternalAddr: result.ExternalAddr}); err != nil {
				realDev.Close()
				return false
			}
			if !waitForNativeReady(cc, sid2, o.cfg.NativeHandshakeTimeout) {
				realDev.Close()
				// Reachability was proven moments ago, but this specific
				// handoff didn't complete. Attaching realDev to o.yTUN
				// already superseded the live cloaked session's TUN
				// delivery, so leaving things here would strand the
				// session -- restore cloaked mode via the same hint path
				// resume-on-restart and stale-retry already use, rather
				// than inventing bespoke revert logic.
				if err := o.runY(pc, hintCloaked); err != nil {
					o.cfg.Logger.Errorf("orchestrate: restoring cloaked mode for %s after failed native handoff: %v", pc.ControlAddr, err)
				}
				return false
			}

			succeeded = true
			// Old is always the cloaked Device here (attemptBackgroundNative
			// is only ever called while state == StateConnectedCloaked),
			// which owns a real bind and has no extraCloser -- closeDevice
			// still goes through the same single teardown path as every
			// other Device replacement, so that stays true even if this
			// ever changes.
			sess.closeDevice()
			// realDev's PreboundBind wraps probeSocket but never closes it
			// (see PreboundBind's doc) -- track it so a later teardown
			// actually frees the fd instead of leaking it.
			sess.setDevice(realDev, probeSocket)
			sess.setState(StateConnectedNative, "background-native-upgrade")
			o.saveSession(pc.ControlAddr, "native", result.ExternalAddr.String())
			return true
		case control.NativeFailed:
			if m.SessionID != sid {
				continue
			}
			return false
		}
	}
	return false
}

// waitForNativeReady blocks (reading further messages off cc) until a
// NativeReady or NativeFailed carrying sid arrives, timeout elapses, or cc
// errors -- the same wait AttemptOnX's caller performs inline in runY,
// factored out here since attemptBackgroundNative needs it twice (once
// implicitly via its own loop for the probe handshake, once explicitly
// here for the real handoff's second handshake).
func waitForNativeReady(cc *control.Conn, sid control.SessionID, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		msg, err := cc.Recv()
		if err != nil {
			return false
		}
		switch m := msg.(type) {
		case control.NativeReady:
			if m.SessionID == sid {
				return true
			}
		case control.NativeFailed:
			if m.SessionID == sid {
				return false
			}
		}
	}
	return false
}

// resolvePublicHost parses cfg.PublicHost as a literal IP, falling back to
// DNS resolution for an actual hostname (e.g. "vpn.example.com").
func resolvePublicHost(host string) (netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr, nil
	}
	return resolveHost(host)
}

func resolveHost(host string) (netip.Addr, error) {
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("resolve %q: %w", host, err)
	}
	addr, ok := netip.AddrFromSlice(ips[0])
	if !ok {
		return netip.Addr{}, fmt.Errorf("resolve %q: invalid address", host)
	}
	return addr.Unmap(), nil
}
