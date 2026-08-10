// lifecycle_test.go exercises Phase 5's additions on top of the Phase
// 3/4 wiring inprocess_test.go already covers: resume-on-restart via
// persist.Store, network-change-triggered re-probe, transient-loss
// retry-last-mode, and the background native re-attempt that upgrades an
// already-Connected(Cloaked) session without dropping it.
package e2e_test

import (
	"context"
	"fmt"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/orchestrate"
	"github.com/amnezia-vpn/amneziawg-go/v3/orchestrate/netchange"
	"github.com/amnezia-vpn/amneziawg-go/v3/orchestrate/persist"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
)

// TestOrchestratorResumesLastModeFromStore seeds a Store with a persisted
// "cloaked" record for Y's session *before* Y ever connects, in an
// environment where native mode would otherwise succeed (plain loopback,
// no real NAT -- see inprocess_test.go's package doc). If Y lands in
// ConnectedCloaked anyway, that can only be because the persisted
// LastMode was honored (Config.Store's doc: "seed RetryLastMode instead
// of cold Probing"), not because native was actually unreachable.
func TestOrchestratorResumesLastModeFromStore(t *testing.T) {
	xIP := netip.MustParseAddr("1.0.0.1")
	yIP := netip.MustParseAddr("1.0.0.2")
	top := newTopology(t, xIP, yIP)

	xOrch := startOrchestrator(t, top.xConfig(t))
	if err := xOrch.Start(); err != nil {
		t.Fatalf("X Start: %v", err)
	}

	store := persist.NewMemoryStore()
	// The exact wire format persistence.go's persistedSession marshals --
	// a black-box test of the real, documented format, not a reach into
	// an unexported type.
	if err := store.Save(context.Background(), top.controlAddr, []byte(`{"last_mode":"cloaked"}`)); err != nil {
		t.Fatalf("seed store: %v", err)
	}

	yCfg := top.yConfig(t)
	yCfg.Store = store
	yOrch := startOrchestrator(t, yCfg)
	if err := yOrch.Start(); err != nil {
		t.Fatalf("Y Start: %v", err)
	}

	if st, reason := yOrch.Session(top.controlAddr).State(); st != orchestrate.StateConnectedCloaked {
		t.Fatalf("Y session state = %v (%s), want ConnectedCloaked (resume-last-mode should have skipped native entirely)", st, reason)
	}
}

// fakeNetworkChangeDetector is a netchange.Detector the test controls
// directly, so it can fire a ChangeEvent on demand and observe (via
// delivered) that the orchestrator actually consumed it.
type fakeNetworkChangeDetector struct {
	events    chan netchange.ChangeEvent
	delivered atomic.Bool
}

func newFakeNetworkChangeDetector() *fakeNetworkChangeDetector {
	return &fakeNetworkChangeDetector{events: make(chan netchange.ChangeEvent, 1)}
}

func (f *fakeNetworkChangeDetector) Subscribe(ctx context.Context) (<-chan netchange.ChangeEvent, error) {
	out := make(chan netchange.ChangeEvent)
	go func() {
		defer close(out)
		for {
			select {
			case ev := <-f.events:
				f.delivered.Store(true)
				select {
				case out <- ev:
				case <-ctx.Done():
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, nil
}

// TestOrchestratorNetworkChangeTriggersReProbe fires a fake network-change
// event at an already-Connected(Native) Y and confirms: the event is
// actually consumed (proving the Subscribe wiring works), and the session
// survives (self-heals back to ConnectedNative and keeps passing traffic)
// -- the whole point of forcing a full re-probe rather than just dropping
// the connection.
func TestOrchestratorNetworkChangeTriggersReProbe(t *testing.T) {
	xIP := netip.MustParseAddr("1.0.0.1")
	yIP := netip.MustParseAddr("1.0.0.2")
	top := newTopology(t, xIP, yIP)

	xOrch := startOrchestrator(t, top.xConfig(t))
	if err := xOrch.Start(); err != nil {
		t.Fatalf("X Start: %v", err)
	}

	detector := newFakeNetworkChangeDetector()
	yCfg := top.yConfig(t)
	yCfg.NetworkChange = detector
	yOrch := startOrchestrator(t, yCfg)
	if err := yOrch.Start(); err != nil {
		t.Fatalf("Y Start: %v", err)
	}
	if st, reason := yOrch.Session(top.controlAddr).State(); st != orchestrate.StateConnectedNative {
		t.Fatalf("Y session state = %v (%s), want ConnectedNative", st, reason)
	}
	pingThrough(t, top.xTUN, top.yTUN, xIP, yIP)

	detector.events <- netchange.ChangeEvent{Reason: "test-network-change"}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !detector.delivered.Load() {
		time.Sleep(10 * time.Millisecond)
	}
	if !detector.delivered.Load() {
		t.Fatalf("orchestrator never consumed the network-change event")
	}

	// Loopback's NAT is still (and only ever) cone-type, so the forced
	// re-probe should land back on native -- confirming the session
	// actually recovered, not just that the event was read.
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if st, _ := yOrch.Session(top.controlAddr).State(); st == orchestrate.StateConnectedNative {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if st, reason := yOrch.Session(top.controlAddr).State(); st != orchestrate.StateConnectedNative {
		t.Fatalf("after network change, Y session state = %v (%s), want ConnectedNative again", st, reason)
	}
	pingThrough(t, top.xTUN, top.yTUN, xIP, yIP)
}

// TestOrchestratorRetriesLastModeOnTransientLoss forces X's shared
// cloaked Device's peer connection to go quiet (without any network
// change) and confirms Y's supervisor notices the stale rx_bytes counter
// and reconnects -- in cloaked mode again, without ever re-probing NAT
// (Lifecycle, requirement #6 bullet 3: transient loss retries the same
// mode directly).
func TestOrchestratorRetriesLastModeOnTransientLoss(t *testing.T) {
	xIP := netip.MustParseAddr("1.0.0.1")
	yIP := netip.MustParseAddr("1.0.0.2")

	xPriv, xPub := genKey(t)
	yPriv, yPub := genKey(t)
	controlAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	xNativeTUN := tuntest.NewChannelTUN()
	xCloakedTUN := tuntest.NewChannelTUN()
	yTUN := tuntest.NewChannelTUN()

	xCfg := orchestrate.Config{
		Role:              orchestrate.RoleX,
		LocalPrivateKey:   xPriv,
		LocalPublicKey:    xPub,
		ControlListenAddr: controlAddr,
		PublicHost:        "127.0.0.1",
		ProbePortA:        freePort(t),
		ProbePortB:        freePort(t),
		NativeListenPort:  freePort(t),
		CloakedListenPort: freePort(t),
		AuthorizedPeers: []orchestrate.PeerAuthorization{
			{PublicKey: yPub, AllowedIPs: []string{yIP.String() + "/32"}},
		},
		NativeTUN:  xNativeTUN.TUN(),
		CloakedTUN: xCloakedTUN.TUN(),
		// Forces every native attempt (initial *and* any retry) into
		// cloaked, so the test's later stale-triggered reconnect has only
		// one possible mode to land on, making the assertion unambiguous.
		NativeHandshakeTimeout:  time.Nanosecond,
		CloakedHandshakeTimeout: 10 * time.Second,
		Logger:                  testLogger(),
	}
	xOrch := startOrchestrator(t, xCfg)
	if err := xOrch.Start(); err != nil {
		t.Fatalf("X Start: %v", err)
	}

	yCfg := orchestrate.Config{
		Role:            orchestrate.RoleY,
		LocalPrivateKey: yPriv,
		LocalPublicKey:  yPub,
		Peers: []orchestrate.PeerConfig{
			{RemotePublicKey: xPub, ControlAddr: controlAddr, AllowedIPs: []string{xIP.String() + "/32"}},
		},
		YTUN:                    yTUN.TUN(),
		NativeHandshakeTimeout:  10 * time.Second,
		CloakedHandshakeTimeout: 10 * time.Second,
		LivenessCheckInterval:   20 * time.Millisecond,
		StaleAfter:              80 * time.Millisecond,
		Logger:                  testLogger(),
	}
	yOrch := startOrchestrator(t, yCfg)
	if err := yOrch.Start(); err != nil {
		t.Fatalf("Y Start: %v", err)
	}
	if st, reason := yOrch.Session(controlAddr).State(); st != orchestrate.StateConnectedCloaked {
		t.Fatalf("Y session state = %v (%s), want ConnectedCloaked", st, reason)
	}
	firstDev := yOrch.Session(controlAddr).Device()

	// Simulate a transient loss: kill Y's current data-path Device
	// directly, without any network-change signal. superviseY's liveness
	// check (rx_bytes stalls, since the Device carrying it is now closed)
	// is the only thing that can notice and recover from this.
	firstDev.Close()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if st, _ := yOrch.Session(controlAddr).State(); st == orchestrate.StateConnectedCloaked && yOrch.Session(controlAddr).Device() != firstDev {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	st, reason := yOrch.Session(controlAddr).State()
	if st != orchestrate.StateConnectedCloaked {
		t.Fatalf("after transient loss, Y session state = %v (%s), want ConnectedCloaked again", st, reason)
	}
	if yOrch.Session(controlAddr).Device() == firstDev {
		t.Fatalf("session never actually reconnected -- still the same (dead) Device")
	}

	pingThrough(t, xCloakedTUN, yTUN, xIP, yIP)
}

// TestOrchestratorBackgroundNativeUpgradesFromCloaked seeds Y's Store
// with a persisted "cloaked" record (so, per
// TestOrchestratorResumesLastModeFromStore, Y's initial connection skips
// native and lands directly in ConnectedCloaked despite native being
// fully reachable on this loopback topology), then confirms
// superviseY's background native re-attempt notices native actually
// works and upgrades the session to ConnectedNative -- entirely on its
// own, with a short BackgroundNativeRetryInterval standing in for what
// would otherwise be a multi-minute wait -- without ever dropping
// connectivity in between.
func TestOrchestratorBackgroundNativeUpgradesFromCloaked(t *testing.T) {
	xIP := netip.MustParseAddr("1.0.0.1")
	yIP := netip.MustParseAddr("1.0.0.2")
	top := newTopology(t, xIP, yIP)

	xOrch := startOrchestrator(t, top.xConfig(t))
	if err := xOrch.Start(); err != nil {
		t.Fatalf("X Start: %v", err)
	}

	store := persist.NewMemoryStore()
	if err := store.Save(context.Background(), top.controlAddr, []byte(`{"last_mode":"cloaked"}`)); err != nil {
		t.Fatalf("seed store: %v", err)
	}

	yCfg := top.yConfig(t)
	yCfg.Store = store
	yCfg.LivenessCheckInterval = 20 * time.Millisecond
	yCfg.BackgroundNativeRetryInterval = 50 * time.Millisecond
	yOrch := startOrchestrator(t, yCfg)
	if err := yOrch.Start(); err != nil {
		t.Fatalf("Y Start: %v", err)
	}
	if st, reason := yOrch.Session(top.controlAddr).State(); st != orchestrate.StateConnectedCloaked {
		t.Fatalf("Y session state = %v (%s), want ConnectedCloaked", st, reason)
	}

	// A background attempt cycle costs more than BackgroundNativeRetryInterval
	// itself: natprobe.Characterize's own timeout/retry budget, the
	// documented ~3.3s PreboundBind.Close()/RoutineReceiveIncoming teardown
	// cost paid when the throwaway probe Device is torn down, and a second,
	// fresh handshake against the real Device (see attemptBackgroundNative's
	// doc: the probe's own handshake can't be reused for real traffic) --
	// generous under -race, where goroutine-heavy Device teardown is
	// substantially slower.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if st, _ := yOrch.Session(top.controlAddr).State(); st == orchestrate.StateConnectedNative {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	st, reason := yOrch.Session(top.controlAddr).State()
	if st != orchestrate.StateConnectedNative {
		t.Fatalf("Y session state = %v (%s), want ConnectedNative after background upgrade", st, reason)
	}
	if reason != "background-native-upgrade" {
		t.Fatalf("reason = %q, want %q", reason, "background-native-upgrade")
	}

	pingThrough(t, top.xTUN, top.yTUN, xIP, yIP)
}
