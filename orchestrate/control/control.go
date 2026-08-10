// Package control implements the out-of-band, authenticated control
// channel used to coordinate dual-mode connectivity between an X (publicly
// reachable) and Y (possibly-NATed) amneziawg-go peer: NAT/endpoint
// exchange, mode negotiation, and (for cloaked mode) delivery of the exact
// obfuscation parameters Y must use. It is deliberately role-agnostic --
// the same Conn/Dial/Listen/message set is used by both X and Y; role-
// specific behavior lives entirely in the orchestrate package, which is the
// only thing that imports both control and device.
package control

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
)

// Endpoint is the responder (X) side: it accepts inbound TCP connections
// and authenticates each one via the Noise_IK handshake before handing it
// back as a Conn.
type Endpoint struct {
	localPriv PrivateKey
	isKnown   func(PublicKey) bool

	mu       sync.Mutex
	lastSeen map[PublicKey]time.Time
}

// NewEndpoint constructs a responder-side Endpoint. isKnownPeer must report
// whether a given remote static key is a configured peer; unknown keys are
// rejected before any further state is created for them.
func NewEndpoint(localPriv PrivateKey, isKnownPeer func(PublicKey) bool) *Endpoint {
	return &Endpoint{
		localPriv: localPriv,
		isKnown:   isKnownPeer,
		lastSeen:  make(map[PublicKey]time.Time),
	}
}

func (e *Endpoint) checkReplay(remote PublicKey, ts time.Time) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if last, ok := e.lastSeen[remote]; ok && !ts.After(last) {
		return false
	}
	e.lastSeen[remote] = ts
	return true
}

// Accept performs the responder side of the handshake on an already-
// accepted net.Conn (e.g. from a net.Listener.Accept loop) and returns the
// authenticated Conn plus the confirmed remote static key.
func (e *Endpoint) Accept(nc net.Conn) (*Conn, error) {
	hr, err := responderHandshake(nc, e.localPriv, e.isKnown, e.checkReplay)
	if err != nil {
		nc.Close()
		return nil, err
	}
	c, err := newConn(nc, hr)
	if err != nil {
		nc.Close()
		return nil, err
	}
	return c, nil
}

// Serve runs an accept loop on ln, handing each successfully-authenticated
// connection to onConn (called in its own goroutine). It blocks until ln is
// closed or an unrecoverable Accept error occurs.
func (e *Endpoint) Serve(ln net.Listener, onConn func(*Conn), onError func(net.Conn, error)) error {
	for {
		nc, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			c, err := e.Accept(nc)
			if err != nil {
				if onError != nil {
					onError(nc, err)
				}
				return
			}
			onConn(c)
		}()
	}
}

var errRemoteMismatch = errors.New("control: responder's static key does not match the expected peer")

// DialTimeout is the default TCP connect timeout used by Dial.
const DialTimeout = 10 * time.Second

// Dial performs the initiator side (always Y): establishes a TCP
// connection to addr and runs the Noise_IK handshake against the known
// remoteStatic key.
func Dial(addr string, localPriv PrivateKey, remoteStatic PublicKey) (*Conn, error) {
	return DialProtected(addr, localPriv, remoteStatic, nil)
}

// ProtectFn marks a raw socket fd so its traffic bypasses the platform's
// own VPN routing -- on Android, a thin wrapper around
// android.net.VpnService.protect(fd), called via JNI; nil everywhere else
// (iOS's NEPacketTunnelProvider exempts the extension process's own
// traffic automatically, no equivalent call needed). Without this, a
// dial made from inside the same process that just brought up the VPN
// tunnel gets captured by that tunnel's own routing and never reaches the
// real network -- see DialProtected's doc.
type ProtectFn func(fd int) bool

// DialProtected is Dial, but routes the dial through protect (if non-nil)
// before the connect(2) syscall runs, via net.Dialer's Control hook --
// the only point in a plain net.Dial where a raw fd is available before
// it's connected. This matters specifically on Android: by the time
// owgTurnOn's caller invokes Start(), VpnService.Builder.establish() has
// already redirected the device's default route through the
// not-yet-connected tunnel, so an unprotected dial here would loop back
// into the TUN this same process owns instead of reaching the real
// network -- deterministically, not as a rare race, since the routing is
// already in place before this is ever called.
func DialProtected(addr string, localPriv PrivateKey, remoteStatic PublicKey, protect ProtectFn) (*Conn, error) {
	dialer := net.Dialer{Timeout: DialTimeout}
	if protect != nil {
		dialer.Control = func(_, _ string, c syscall.RawConn) error {
			var protectErr error
			if err := c.Control(func(fd uintptr) {
				if !protect(int(fd)) {
					protectErr = fmt.Errorf("control: protect failed for fd %d", fd)
				}
			}); err != nil {
				return err
			}
			return protectErr
		}
	}
	nc, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("control: dial %s: %w", addr, err)
	}
	return handshakeOverConn(nc, localPriv, remoteStatic)
}

// handshakeOverConn runs the initiator handshake over an already-open
// connection (real TCP from Dial, or a net.Pipe() end in tests).
func handshakeOverConn(nc net.Conn, localPriv PrivateKey, remoteStatic PublicKey) (*Conn, error) {
	localPub := localPriv.PublicKey()
	hr, err := initiatorHandshake(nc, localPriv, localPub, remoteStatic)
	if err != nil {
		nc.Close()
		return nil, err
	}
	if hr.RemoteStatic != remoteStatic {
		nc.Close()
		return nil, errRemoteMismatch
	}
	return newConn(nc, hr)
}
