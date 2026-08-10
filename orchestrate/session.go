package orchestrate

import (
	"io"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
)

// State is a Session's connectivity state. Phase 3 scope: native-mode only
// (Idle -> Probing -> NativeAttempting -> Connected|Failed); cloaked
// fallback, background re-attempt, and retry-last-mode extend this same
// table in later phases without changing its shape.
type State int

const (
	StateIdle State = iota
	StateProbing
	StateNativeAttempting
	StateConnectedNative
	StateConnectedCloaked
	StateFailed
)

func (s State) String() string {
	switch s {
	case StateIdle:
		return "idle"
	case StateProbing:
		return "probing"
	case StateNativeAttempting:
		return "native-attempting"
	case StateConnectedNative:
		return "connected-native"
	case StateConnectedCloaked:
		return "connected-cloaked"
	case StateFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// Session tracks one Y<->X relationship's connectivity state. On X it
// represents one connected Y; on Y it represents one configured X peer.
// The state machine and its transitions are role-agnostic -- role only
// determines which of nativeflow's two entry points (AttemptOnX vs.
// PreparePassiveDevice+Punch) actually drives a given Session forward; see
// orchestrate.go.
type Session struct {
	mu     sync.Mutex
	state  State
	reason string
	dev    *device.Device // the live Device carrying this session's traffic, once connected
	// extraCloser is an OS resource dev's Bind wraps but does not itself
	// own or close -- specifically, Y's native-mode nativeflow.PreboundBind
	// deliberately never closes the raw *net.UDPConn it wraps (see its
	// doc), so whoever creates that socket must close it separately once
	// the Device is really done with it. Every teardown path must go
	// through closeDevice rather than calling Device().Close() directly,
	// or this gets forgotten and the socket leaks -- exactly the bug that
	// motivated adding this field (Orchestrator.Stop() and superviseY's
	// reconnect paths each had their own dev.Close()-only teardown that
	// never closed the underlying native-mode socket).
	extraCloser io.Closer

	// onChange, if set, is invoked (outside the lock, with the state just
	// replaced and the one now current) after every actual state or reason
	// change -- how Orchestrator.Events gets notified without every
	// runY/superviseY call site needing its own event-emitting logic
	// alongside setState. Passing both lets the callback tell "just
	// entered Connected" from "was never connected, still isn't" without
	// tracking its own history.
	onChange func(prev, next State, reason string)
}

func newSession(onChange func(prev, next State, reason string)) *Session {
	return &Session{state: StateIdle, onChange: onChange}
}

func (s *Session) setState(st State, reason string) {
	s.mu.Lock()
	prev := s.state
	changed := s.state != st || s.reason != reason
	s.state = st
	s.reason = reason
	cb := s.onChange
	s.mu.Unlock()
	if changed && cb != nil {
		cb(prev, st, reason)
	}
}

// setDevice installs dev as the session's live Device. extraCloser, if
// non-nil, is an OS resource dev's Bind wraps but does not itself close
// (see the field's doc) -- pass nil when dev's Bind owns and closes its
// own socket normally (every case except Y's native-mode PreboundBind).
func (s *Session) setDevice(dev *device.Device, extraCloser io.Closer) {
	s.mu.Lock()
	s.dev = dev
	s.extraCloser = extraCloser
	s.mu.Unlock()
}

// closeDevice closes the session's current Device, along with its
// extraCloser if one is tracked, and clears both -- the one teardown path
// every caller that's replacing or shutting down a session's Device must
// use instead of fetching Device() and closing it directly, so a
// native-mode session's underlying socket is never forgotten and leaked.
func (s *Session) closeDevice() {
	s.mu.Lock()
	dev := s.dev
	closer := s.extraCloser
	s.dev = nil
	s.extraCloser = nil
	s.mu.Unlock()
	if dev != nil {
		dev.Close()
	}
	if closer != nil {
		closer.Close()
	}
}

// State returns the current state and, for StateFailed, the failure reason.
func (s *Session) State() (State, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state, s.reason
}

// Device returns the live Device carrying this session's traffic, or nil
// if not currently connected.
func (s *Session) Device() *device.Device {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dev
}
