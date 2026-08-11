// Package nativeflow implements requirement #4's native-mode establishment
// flow. Direction is fixed and asymmetric, always: X dials Y, never the
// reverse -- Y punches its NAT and waits; X actively initiates the
// WireGuard handshake toward the address Y reports. AttemptOnX is the X
// side of this (add Y as a peer with endpoint= set on the shared native
// Device, poll for a completed handshake, remove the peer again on
// timeout); PreparePassiveDevice is the Y side (bring up a Device whose
// peer entry for X has no endpoint, so it only ever waits).
package nativeflow

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
)

// DefaultPollInterval is how often AttemptOnX polls for a completed
// handshake while waiting out the timeout.
const DefaultPollInterval = 250 * time.Millisecond

// SharedDevice is the minimal surface AttemptOnX (and orchestrate.Orchestrator's
// X-role code) needs from one of X's two per-mode shared devices. Satisfied
// implicitly (no explicit "implements" needed, per Go's structural typing) by
// xshared.SharedDevice's in-process, Go device.Device-backed implementation --
// and equally by any alternative backend that drives a real OS/kernel network
// interface instead (e.g. shelling out to a kernel module's own CLI/netlink
// surface), as long as it can add/remove a peer and report that peer's last
// handshake time. Device() may return nil for a backend with no in-process
// device.Device to report (status/diagnostic use only -- see its call sites in
// orchestrate.go, none of which are on a path required for correctness).
type SharedDevice interface {
	AddPeer(pk device.NoisePublicKey, endpoint *netip.AddrPort, allowedIPs []netip.Prefix) error
	RemovePeer(pk device.NoisePublicKey) error
	HandshakeTime(pk device.NoisePublicKey) (time.Time, bool)
	Device() *device.Device
	Close() error
}

// AttemptResult is the outcome of one native-mode establishment attempt,
// from X's point of view.
type AttemptResult struct {
	Success bool
	Reason  string
}

// AttemptOnX is the X side of native-mode establishment (requirement #4,
// steps 4-7 of the plan's flow): it adds remotePub as a peer on the shared
// native Device with endpoint set to externalAddr -- the only thing that
// makes X, despite being the publicly-reachable side, act as the
// WireGuard client here -- then polls for a completed handshake up to
// timeout. On timeout it removes the peer again (leaving every other Y on
// the shared Device untouched, per the isolation guarantee) rather than
// leaving a half-connected peer lingering.
func AttemptOnX(
	native SharedDevice,
	remotePub device.NoisePublicKey,
	allowedIPs []netip.Prefix,
	externalAddr netip.AddrPort,
	timeout time.Duration,
) AttemptResult {
	return attemptOnX(native, remotePub, allowedIPs, externalAddr, timeout, DefaultPollInterval, time.Now, time.Sleep)
}

// attemptOnX takes now/sleep as parameters so tests can run the timeout
// path without actually waiting out a multi-second real timer.
func attemptOnX(
	native SharedDevice,
	remotePub device.NoisePublicKey,
	allowedIPs []netip.Prefix,
	externalAddr netip.AddrPort,
	timeout, pollInterval time.Duration,
	now func() time.Time,
	sleep func(time.Duration),
) AttemptResult {
	// A prior attempt for this same peer may still be configured on the
	// shared Device -- e.g. a supervising reconnect (network-change
	// re-probe, or a stale-connection retry) redials X on a fresh control
	// connection without X ever having been told the old attempt is dead.
	// AddPeer's IpcSet would then reconfigure (not replace) the existing,
	// already-*running* Peer, racing its still-live timer goroutines
	// against a fresh Start(). RemovePeer first guarantees a clean slate:
	// it synchronously stops and removes any existing peer (device/peer.go's
	// Peer.Stop() blocks until its goroutines have actually exited), and is
	// a safe no-op when the peer isn't configured yet (the ordinary,
	// first-ever-attempt case).
	if err := native.RemovePeer(remotePub); err != nil {
		return AttemptResult{Success: false, Reason: fmt.Sprintf("remove-stale-peer-failed: %v", err)}
	}

	// attemptStart is taken before AddPeer reconfigures the peer, and is
	// compared against below using the >= check (not just "non-zero"):
	// RemovePeer above is meant to guarantee no prior handshake state
	// survives, but relying on that alone makes this poll fragile to any
	// gap in that guarantee (e.g. a stale peer entry that RemovePeer
	// silently failed to actually tear down). Requiring the observed
	// handshake time to be at or after this attempt's own start means a
	// leftover timestamp from a materially earlier attempt can never be
	// mistaken for evidence that *this* attempt's handshake completed,
	// regardless of why it's still there.
	//
	// attemptFloor, not attemptStart itself, is what the poll actually
	// compares against -- truncated to the start of attemptStart's own
	// wall-clock second. Confirmed live: a SharedDevice whose
	// HandshakeTime only has whole-second precision (xkernel's `awg show
	// ... latest-handshakes` CLI output, unlike the in-process
	// device.Device's UAPI sec+nsec pair) can genuinely complete a fresh
	// handshake within the same second attemptStart was captured in, yet
	// report a truncated timestamp that reads as earlier than
	// attemptStart's own nanosecond precision -- a real handshake wrongly
	// rejected as "not yet newer," 100% reproducible on a fast/local
	// connection. Comparing against the floor of that second instead
	// keeps the real protection (rejecting anything from a materially
	// earlier attempt) while tolerating the up-to-~1s slop a
	// lower-precision backend can introduce.
	attemptStart := now()
	attemptFloor := attemptStart.Truncate(time.Second)

	ep := externalAddr
	if err := native.AddPeer(remotePub, &ep, allowedIPs); err != nil {
		return AttemptResult{Success: false, Reason: fmt.Sprintf("add-peer-failed: %v", err)}
	}

	deadline := attemptStart.Add(timeout)
	for now().Before(deadline) {
		if t, found := native.HandshakeTime(remotePub); found && !t.Before(attemptFloor) {
			return AttemptResult{Success: true}
		}
		sleep(pollInterval)
	}

	if err := native.RemovePeer(remotePub); err != nil {
		// Still report the timeout as the primary failure; a failed
		// cleanup here is a secondary problem the caller should log, not
		// something that should mask "native mode didn't work."
		return AttemptResult{Success: false, Reason: fmt.Sprintf("handshake-timeout (cleanup also failed: %v)", err)}
	}
	return AttemptResult{Success: false, Reason: "handshake-timeout"}
}
