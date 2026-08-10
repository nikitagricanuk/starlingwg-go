package orchestrate

import (
	"testing"
	"time"
)

// newTestOrchestrator builds a bare Orchestrator with just enough wiring
// (sessions map + events channel) for sessionFor/Status/emit to work,
// bypassing NewOrchestrator's Config validation and ctx/cancel setup --
// this file only exercises the event/status bookkeeping itself, not
// Start/Stop or any real Device.
func newTestOrchestrator() *Orchestrator {
	return &Orchestrator{sessions: make(map[string]*Session), events: make(chan Event, 8)}
}

func TestOrchestratorEmitsConnectedAndDisconnectedEvents(t *testing.T) {
	o := newTestOrchestrator()
	sess := o.sessionFor("k1")

	// An ordinary non-connected transition (the very first one, even)
	// must not produce a spurious "disconnected" event.
	sess.setState(StateProbing, "")
	select {
	case ev := <-o.events:
		t.Fatalf("unexpected event for a plain non-connected transition: %+v", ev)
	default:
	}

	sess.setState(StateConnectedNative, "")
	ev := <-o.events
	if ev.Kind != EventConnected || ev.Mode != "native" || ev.SessionKey != "k1" {
		t.Fatalf("got %+v, want Connected/native for k1", ev)
	}

	// A direct Connected(Native) -> Connected(Cloaked) transition (mirrors
	// nothing in the real flow today, but Status/Events must handle it
	// correctly regardless) reports as another Connected, not a
	// Disconnected+Connected pair.
	sess.setState(StateConnectedCloaked, "")
	ev = <-o.events
	if ev.Kind != EventConnected || ev.Mode != "cloaked" {
		t.Fatalf("got %+v, want Connected/cloaked", ev)
	}

	sess.setState(StateFailed, "boom")
	ev = <-o.events
	if ev.Kind != EventDisconnected || ev.SessionKey != "k1" || ev.Reason != "boom" {
		t.Fatalf("got %+v, want Disconnected(boom) for k1", ev)
	}

	// Failed -> Failed (same reason) is not a change at all.
	sess.setState(StateFailed, "boom")
	select {
	case ev := <-o.events:
		t.Fatalf("unexpected event for a no-op state update: %+v", ev)
	default:
	}
}

func TestOrchestratorStatusSnapshotSortedByKey(t *testing.T) {
	o := newTestOrchestrator()
	o.sessionFor("zzz").setState(StateConnectedCloaked, "")
	o.sessionFor("aaa").setState(StateProbing, "")

	st := o.Status()
	if len(st) != 2 {
		t.Fatalf("len(Status()) = %d, want 2", len(st))
	}
	if st[0].Key != "aaa" || st[1].Key != "zzz" {
		t.Fatalf("Status() not sorted by key: %+v", st)
	}
	if st[0].Mode != "" {
		t.Fatalf("st[0] (Probing).Mode = %q, want empty", st[0].Mode)
	}
	if st[1].Mode != "cloaked" {
		t.Fatalf("st[1] (ConnectedCloaked).Mode = %q, want cloaked", st[1].Mode)
	}
}

func TestOrchestratorEventsChannelNeverBlocksProducer(t *testing.T) {
	o := newTestOrchestrator()
	sess := o.sessionFor("k1")
	// events has capacity 8; alternate Connected/Disconnected well past
	// that without ever draining -- emit (and thus setState) must not
	// block just because nobody's listening.
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			sess.setState(StateConnectedNative, "")
			sess.setState(StateFailed, "")
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("emitting events blocked with a full, undrained channel")
	}
}
