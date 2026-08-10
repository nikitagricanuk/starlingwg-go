package orchestrate

import (
	"os"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// sharedTUN lets a sequence of device.Device instances take turns owning
// Y's one real TUN interface across a mode switch (e.g. native's passive
// Device failing and being replaced by a cloaked Device), without any of
// them ever actually closing the real interface.
//
// This is necessary, not just tidy: device.Device.Close() unconditionally
// calls its tun.Device's Close() (device/device.go:430) and then blocks
// (device.state.stopping.Wait(), device.go:443) until its own
// RoutineReadFromTUN goroutine exits -- which only happens once the TUN's
// Read() call unblocks, which normally only happens by *closing* the TUN.
// For both a real OS TUN and tuntest.ChannelTUN, closing is one-shot and
// non-reusable, so a naive "just don't close it" wrapper (an earlier
// version of this file) leaves Close() hanging forever on a Read() that
// will never return, and Y only has one real interface for its whole
// lifetime -- it can't just get a fresh one for every mode switch either.
//
// The fix: only one goroutine (owned by sharedTUN, started once) ever
// calls the real TUN's Read(); every packet it reads is handed to
// whichever tunSession is currently "active". Each session has its own
// local closed channel that its Read() also selects on, so a session's
// Close() always has a real, immediate way to unblock its Device's read
// loop -- without needing to touch, and thus without ever destroying, the
// real underlying TUN.
type sharedTUN struct {
	real tun.Device

	pumpOnce sync.Once

	mu     sync.Mutex
	active *tunSession
}

func newSharedTUN(real tun.Device) *sharedTUN {
	return &sharedTUN{real: real}
}

type tunReadResult struct {
	data []byte
	err  error
}

func (s *sharedTUN) startPump() {
	s.pumpOnce.Do(func() { go s.pump() })
}

// pumpReadOffset is the headroom every real tun.Device.Read implementation
// in this repo's tun/ package needs before the packet data it returns: the
// BSD family (tun_darwin.go, tun_freebsd.go, tun_openbsd.go) computes
// bufs[0][offset-4:] to make room for a 4-byte protocol-family prefix
// utun/tunfd sockets carry, so offset must be >= 4 there or the slice
// expression panics with a negative bound; Linux is fine with offset=0.
// device/send.go's own RoutineReadFromTUN never hits this because it
// always calls Read with offset = MessageTransportHeaderSize (16) or more
// -- pump() is the one place in this package that calls Read directly with
// a bare scratch buffer, so it needs to reserve the same kind of headroom
// itself. 16 comfortably covers every platform's real minimum of 4.
const pumpReadOffset = 16

func (s *sharedTUN) pump() {
	mtu, err := s.real.MTU()
	if err != nil || mtu <= 0 {
		mtu = 1500
	}
	buf := make([]byte, pumpReadOffset+mtu+256)
	bufs := [][]byte{buf}
	sizes := make([]int, 1)
	for {
		n, err := s.real.Read(bufs, sizes, pumpReadOffset)
		if err != nil {
			s.deliver(tunReadResult{err: err})
			return
		}
		if n == 0 {
			continue
		}
		pkt := make([]byte, sizes[0])
		copy(pkt, buf[pumpReadOffset:pumpReadOffset+sizes[0]])
		s.deliver(tunReadResult{data: pkt})
	}
}

func (s *sharedTUN) deliver(r tunReadResult) {
	s.mu.Lock()
	sess := s.active
	s.mu.Unlock()
	if sess == nil {
		return // no session currently attached -- drop, matches "device down"
	}
	select {
	case sess.rx <- r:
	case <-sess.closed:
	}
}

// attach starts (once) the background pump and returns a new session that
// becomes the active one. The caller is expected to have already detached
// (Close()d) any previous session before attaching a new one -- this
// codebase's actual usage (one mode active at a time) always does.
func (s *sharedTUN) attach() *tunSession {
	s.startPump()
	sess := &tunSession{
		shared: s,
		rx:     make(chan tunReadResult),
		closed: make(chan struct{}),
		events: make(chan tun.Event, 1),
	}
	sess.events <- tun.EventUp
	s.mu.Lock()
	s.active = sess
	s.mu.Unlock()
	return sess
}

// tunSession implements tun.Device, standing in for the real TUN for the
// lifetime of exactly one device.Device.
type tunSession struct {
	shared *sharedTUN

	rx     chan tunReadResult
	closed chan struct{}
	events chan tun.Event

	closeOnce sync.Once
}

var _ tun.Device = (*tunSession)(nil)

func (t *tunSession) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case r := <-t.rx:
		if r.err != nil {
			return 0, r.err
		}
		n := copy(bufs[0][offset:], r.data)
		sizes[0] = n
		return 1, nil
	case <-t.closed:
		return 0, os.ErrClosed
	}
}

// Write passes straight through to the real TUN -- only one session is
// ever meant to be actively writing at a time (the currently-active one),
// which this codebase's flow already guarantees by fully tearing down one
// Device before building the next.
func (t *tunSession) Write(bufs [][]byte, offset int) (int, error) {
	return t.shared.real.Write(bufs, offset)
}

func (t *tunSession) MTU() (int, error)        { return t.shared.real.MTU() }
func (t *tunSession) Name() (string, error)    { return t.shared.real.Name() }
func (t *tunSession) Events() <-chan tun.Event { return t.events }
func (t *tunSession) BatchSize() int           { return 1 }
func (t *tunSession) File() *os.File           { return nil }

// Close unblocks this session's Read() and detaches it from the shared
// pump -- it never touches the real underlying TUN.
func (t *tunSession) Close() error {
	t.closeOnce.Do(func() {
		close(t.closed)
		close(t.events)
		t.shared.mu.Lock()
		if t.shared.active == t {
			t.shared.active = nil
		}
		t.shared.mu.Unlock()
	})
	return nil
}

// Shutdown closes the real underlying TUN. Call it once, when the
// Orchestrator itself is torn down -- never as part of an individual
// session's lifecycle.
func (s *sharedTUN) Shutdown() error {
	if s.real == nil {
		return nil
	}
	return s.real.Close()
}
