package orchestrate

import (
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
)

// bsdOffsetTUN wraps a real tun.Device and reproduces the BSD family's
// (tun_darwin.go/tun_freebsd.go/tun_openbsd.go) actual Read behavior --
// bufs[0][offset-4:] -- so a regression of the real bug this test file
// exists to catch (sharedTUN.pump calling Read with too little headroom,
// which panics with a negative slice bound on those platforms) fails loudly
// in CI on any OS, not only when someone happens to test on a Mac.
type bsdOffsetTUN struct {
	tun.Device
}

func (b bsdOffsetTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	// This is the exact expression real BSD implementations use; it
	// panics with a negative slice bound if offset < 4, precisely
	// reproducing the crash a real macOS run hit.
	_ = bufs[0][offset-4:]
	return b.Device.Read(bufs, sizes, offset)
}

// TestSharedTUNPumpReadOffsetSatisfiesBSDMinimum is a regression test for a
// real bug caught by an actual cross-machine run on macOS: pump() used to
// call the real TUN's Read with offset=0, but tun_darwin.go (and the other
// BSD-family Read implementations) compute bufs[0][offset-4:] to make room
// for the 4-byte protocol-family prefix utun sockets carry, which panics
// with a negative slice bound for any offset < 4. bsdOffsetTUN reproduces
// that exact check against a fake, so this fails on every platform's CI,
// not only when someone happens to test on a Mac.
func TestSharedTUNPumpReadOffsetSatisfiesBSDMinimum(t *testing.T) {
	real := tuntest.NewChannelTUN()
	shared := newSharedTUN(bsdOffsetTUN{real.TUN()})
	sess := shared.attach()

	real.Outbound <- []byte("does not panic")
	buf := [][]byte{make([]byte, 64)}
	sizes := make([]int, 1)
	n, err := sess.Read(buf, sizes, 0)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if n != 1 || string(buf[0][:sizes[0]]) != "does not panic" {
		t.Fatalf("Read returned %q, want %q", buf[0][:sizes[0]], "does not panic")
	}
}

func TestSharedTUNReadWriteRoundTrip(t *testing.T) {
	real := tuntest.NewChannelTUN()
	shared := newSharedTUN(real.TUN())
	sess := shared.attach()

	real.Outbound <- []byte("hello")
	buf := [][]byte{make([]byte, 64)}
	sizes := make([]int, 1)
	n, err := sess.Read(buf, sizes, 0)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if n != 1 || string(buf[0][:sizes[0]]) != "hello" {
		t.Fatalf("Read returned %q, want %q", buf[0][:sizes[0]], "hello")
	}

	// chTun.Write's underlying send to Inbound is unbuffered and blocks
	// until received, so the receive must run concurrently with Write,
	// not after it returns.
	writeErr := make(chan error, 1)
	go func() {
		_, err := sess.Write([][]byte{[]byte("world")}, 0)
		writeErr <- err
	}()
	select {
	case got := <-real.Inbound:
		if string(got) != "world" {
			t.Fatalf("Inbound = %q, want %q", got, "world")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Write did not reach the real TUN's Inbound")
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("Write: %v", err)
	}
}

func TestSharedTUNReadRespectsOffset(t *testing.T) {
	real := tuntest.NewChannelTUN()
	shared := newSharedTUN(real.TUN())
	sess := shared.attach()

	real.Outbound <- []byte("payload")
	buf := [][]byte{make([]byte, 64)}
	sizes := make([]int, 1)
	const offset = 10
	if _, err := sess.Read(buf, sizes, offset); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got := string(buf[0][offset : offset+sizes[0]]); got != "payload" {
		t.Fatalf("Read with offset=%d wrote %q at the wrong position", offset, got)
	}
}

func TestSharedTUNCloseUnblocksReadPromptly(t *testing.T) {
	real := tuntest.NewChannelTUN()
	shared := newSharedTUN(real.TUN())
	sess := shared.attach()

	done := make(chan error, 1)
	go func() {
		buf := [][]byte{make([]byte, 64)}
		sizes := make([]int, 1)
		_, err := sess.Read(buf, sizes, 0)
		done <- err
	}()

	// Give the goroutine a moment to actually enter the blocking Read.
	time.Sleep(50 * time.Millisecond)
	sess.Close()

	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("expected an error from Read after Close, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("session.Close() did not unblock a pending Read promptly")
	}
}

func TestSharedTUNCloseDoesNotCloseRealTUN(t *testing.T) {
	real := tuntest.NewChannelTUN()
	shared := newSharedTUN(real.TUN())
	sess := shared.attach()
	sess.Close()

	// The real TUN must still be usable -- e.g. by a second session --
	// after the first session's Close(), which is the entire point of
	// sharedTUN: individual internal Device teardowns must never destroy
	// Y's one persistent interface.
	sess2 := shared.attach()
	real.Outbound <- []byte("still alive")
	buf := [][]byte{make([]byte, 64)}
	sizes := make([]int, 1)
	n, err := sess2.Read(buf, sizes, 0)
	if err != nil {
		t.Fatalf("Read on second session: %v", err)
	}
	if n != 1 || string(buf[0][:sizes[0]]) != "still alive" {
		t.Fatalf("second session did not receive data via the still-open real TUN")
	}
}

func TestSharedTUNSecondSessionSupersedesFirst(t *testing.T) {
	real := tuntest.NewChannelTUN()
	shared := newSharedTUN(real.TUN())
	sess1 := shared.attach()
	sess1.Close()
	sess2 := shared.attach()

	real.Outbound <- []byte("routed to sess2")

	buf := [][]byte{make([]byte, 64)}
	sizes := make([]int, 1)

	// sess1 must never receive anything post-Close -- its Read should
	// return promptly with the closed error, not the data meant for sess2.
	done1 := make(chan error, 1)
	go func() {
		_, err := sess1.Read(buf, sizes, 0)
		done1 <- err
	}()
	select {
	case err := <-done1:
		if err == nil {
			t.Fatalf("closed session1 unexpectedly returned a successful Read")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("closed session1's Read should return immediately")
	}

	buf2 := [][]byte{make([]byte, 64)}
	sizes2 := make([]int, 1)
	if _, err := sess2.Read(buf2, sizes2, 0); err != nil {
		t.Fatalf("sess2 Read: %v", err)
	}
	if string(buf2[0][:sizes2[0]]) != "routed to sess2" {
		t.Fatalf("sess2 got %q, want %q", buf2[0][:sizes2[0]], "routed to sess2")
	}
}

func TestSharedTUNShutdownClosesRealTUN(t *testing.T) {
	real := tuntest.NewChannelTUN()
	shared := newSharedTUN(real.TUN())
	sess := shared.attach()
	_ = sess

	if err := shared.Shutdown(); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	// Writing to the real TUN's Inbound (i.e. delivering "up the stack")
	// after a genuine close should fail, confirming Shutdown really did
	// close the underlying interface -- unlike a session's own Close().
	if _, err := real.TUN().Write([][]byte{[]byte("x")}, 0); err == nil {
		t.Fatalf("expected Write to fail after Shutdown closed the real TUN")
	}
}

func TestSharedTUNDeliverDropsWhenNoActiveSession(t *testing.T) {
	real := tuntest.NewChannelTUN()
	shared := newSharedTUN(real.TUN())
	sess := shared.attach()
	sess.Close() // no session active now

	// Should not panic or block forever; the pump just keeps running with
	// nowhere to deliver.
	real.Outbound <- []byte("dropped")
	time.Sleep(100 * time.Millisecond)

	// A fresh session attached afterwards should not see the stale packet
	// (it was already consumed and dropped by the pump, not queued).
	sess2 := shared.attach()
	real.Outbound <- []byte("fresh")
	buf := [][]byte{make([]byte, 64)}
	sizes := make([]int, 1)
	n, err := sess2.Read(buf, sizes, 0)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[0][:sizes[0]]) != "fresh" {
		t.Fatalf("expected only the fresh packet, got %q", buf[0][:n])
	}
}
