// Package netchange lets the host application tell the orchestrator about
// local network attachment changes (Wi-Fi <-> cellular, any detectable
// change in local network attachment) -- since NAT behavior is a property
// of the network path and may differ from the previous attachment, this is
// what triggers a full re-probe (re-run NAT characterization, re-attempt
// native mode from scratch) rather than just retrying the last known mode.
//
// Detecting network changes is unavoidably platform-specific (NWPathMonitor
// on iOS/macOS, ConnectivityManager on Android, netlink on Linux, ...), so
// this is an injected interface: the portable orchestration logic never
// needs to know how the signal was produced, only that it happened.
package netchange

import "context"

// ChangeEvent is informational only -- Reason is a short, human-readable
// description (e.g. "wifi-to-cellular", "interface-changed") for logging;
// no orchestration decision depends on its exact value, only on the event
// having fired at all.
type ChangeEvent struct {
	Reason string
}

// Detector is the host-supplied network-change signal source.
type Detector interface {
	// Subscribe returns a channel that receives one ChangeEvent per
	// detected network change. The channel should be closed (or ctx
	// canceled) to unsubscribe; implementations must not block Subscribe
	// itself waiting for the first event.
	Subscribe(ctx context.Context) (<-chan ChangeEvent, error)
}

// Never is a Detector that never fires -- the default for platforms or
// tests with no network-change signal available. A nil Detector is treated
// the same way by the orchestrator, so this exists mainly to let callers
// be explicit, and for direct use in tests.
type Never struct{}

var _ Detector = Never{}

func (Never) Subscribe(ctx context.Context) (<-chan ChangeEvent, error) {
	ch := make(chan ChangeEvent)
	go func() {
		<-ctx.Done()
		close(ch)
	}()
	return ch, nil
}
