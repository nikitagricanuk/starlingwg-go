package netchange

import (
	"context"
	"testing"
	"time"
)

func TestNeverNeverFires(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch, err := (Never{}).Subscribe(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	select {
	case ev, ok := <-ch:
		if ok {
			t.Fatalf("Never{} unexpectedly fired: %+v", ev)
		}
		// ok=false is fine only once ctx is canceled; here it's not yet,
		// so a closed channel this early would also be wrong.
		t.Fatalf("Never{} channel closed before context cancellation")
	case <-time.After(200 * time.Millisecond):
		// expected: nothing happens
	}
}

func TestNeverClosesChannelOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ch, err := (Never{}).Subscribe(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	cancel()
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatalf("expected channel to be closed, got a value instead")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("channel was not closed promptly after context cancellation")
	}
}

// fakeDetector is a minimal test double confirming the Detector interface
// shape is usable by an independent implementation, not just Never{}.
type fakeDetector struct {
	events chan ChangeEvent
}

func newFakeDetector() *fakeDetector {
	return &fakeDetector{events: make(chan ChangeEvent, 1)}
}

func (f *fakeDetector) Subscribe(ctx context.Context) (<-chan ChangeEvent, error) {
	return f.events, nil
}

func TestFakeDetectorDeliversEvent(t *testing.T) {
	var d Detector = newFakeDetector()
	ch, err := d.Subscribe(context.Background())
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	d.(*fakeDetector).events <- ChangeEvent{Reason: "wifi-to-cellular"}

	select {
	case ev := <-ch:
		if ev.Reason != "wifi-to-cellular" {
			t.Fatalf("Reason = %q, want %q", ev.Reason, "wifi-to-cellular")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("did not receive the fake event")
	}
}
