package orchestrate

import "sort"

// EventKind identifies what happened in an Event -- see Orchestrator.Events.
type EventKind int

const (
	// EventConnected fires whenever a session transitions into
	// Connected(Native) or Connected(Cloaked); Event.Mode says which. A
	// background-native upgrade (Connected(Cloaked) -> Connected(Native)
	// with no intervening disconnect) is represented as a fresh
	// EventConnected with the new Mode -- there is no separate
	// "mode changed" kind, since a host UI only ever needs "what is the
	// current mode," which the latest EventConnected for that key answers
	// directly.
	EventConnected EventKind = iota
	// EventDisconnected fires whenever a session leaves a Connected state
	// (handshake timeout, transient loss before a retry lands, etc).
	EventDisconnected
	// EventInterfaceUp/EventInterfaceDown fire once each, X-only, when
	// Orchestrator.Start/Stop bring X's two shared interfaces up or down
	// -- a Go analogue of wg-quick's PostUp/PostDown, letting host
	// automation react once per interface rather than once per Y.
	EventInterfaceUp
	EventInterfaceDown
)

func (k EventKind) String() string {
	switch k {
	case EventConnected:
		return "connected"
	case EventDisconnected:
		return "disconnected"
	case EventInterfaceUp:
		return "interface-up"
	case EventInterfaceDown:
		return "interface-down"
	default:
		return "unknown"
	}
}

// Event is one lifecycle notification from an Orchestrator -- see Events.
type Event struct {
	Kind EventKind
	// SessionKey identifies the session for EventConnected/Disconnected
	// (the same key Session/Status use: a Y's hex-encoded public key on
	// X, or a peer's ControlAddr on Y). Empty for interface events.
	SessionKey string
	// Mode is "native" or "cloaked" for EventConnected; empty otherwise.
	Mode string
	// InterfaceName is the OS interface name for EventInterfaceUp/Down
	// (X only); empty otherwise.
	InterfaceName string
	Reason        string
}

// Events returns a channel of lifecycle notifications: connect/disconnect
// per session, and (X only) interface up/down. Best-effort and
// non-blocking to produce -- a slow or absent consumer never blocks
// orchestration itself, so a full channel silently drops the oldest-style
// backpressure (the event is skipped, not queued indefinitely); callers
// that need a complete history should poll Status() instead, which always
// reflects current state exactly.
func (o *Orchestrator) Events() <-chan Event {
	return o.events
}

func (o *Orchestrator) emit(ev Event) {
	select {
	case o.events <- ev:
	default:
	}
}

func modeForState(st State) string {
	switch st {
	case StateConnectedNative:
		return "native"
	case StateConnectedCloaked:
		return "cloaked"
	default:
		return ""
	}
}

// SessionStatus is one session's point-in-time snapshot -- see Status.
type SessionStatus struct {
	Key    string
	State  State
	Reason string
	// Mode is "native" or "cloaked" while State is one of the Connected*
	// states, and "" otherwise -- the field a host UI displaying "current
	// mode" should read.
	Mode string
}

// Status returns a snapshot of every known session (on X: one per Y that
// has ever connected; on Y: one per configured Peer), sorted by Key for
// deterministic output. Unlike Events, this always reflects the current
// state exactly -- there is nothing to miss by not having subscribed
// earlier.
func (o *Orchestrator) Status() []SessionStatus {
	o.mu.Lock()
	keys := make([]string, 0, len(o.sessions))
	sessions := make(map[string]*Session, len(o.sessions))
	for k, s := range o.sessions {
		keys = append(keys, k)
		sessions[k] = s
	}
	o.mu.Unlock()

	sort.Strings(keys)
	out := make([]SessionStatus, 0, len(keys))
	for _, k := range keys {
		st, reason := sessions[k].State()
		out = append(out, SessionStatus{Key: k, State: st, Reason: reason, Mode: modeForState(st)})
	}
	return out
}
