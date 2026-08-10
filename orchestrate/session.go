package orchestrate

import (
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

func (s *Session) setDevice(dev *device.Device) {
	s.mu.Lock()
	s.dev = dev
	s.mu.Unlock()
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
