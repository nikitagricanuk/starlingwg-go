package nativeflow

import (
	"os"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// noopTUN is a tun.Device that carries no real traffic: Read blocks until
// Close, Write silently discards. It backs Y's background native
// re-attempt trial Device (see requirement #6 bullet 2's "throwaway
// probe-only Device"), which must never touch Y's real, live,
// traffic-carrying TUN while it's still just testing whether native mode
// would even work -- attaching a trial session to the real shared TUN
// would immediately steal packet delivery from whatever mode is actually
// carrying traffic (the sharedTUN multiplexer routes every read to
// whichever session most recently attached).
type noopTUN struct {
	mtu    int
	events chan tun.Event
	closed chan struct{}

	closeOnce sync.Once
}

// NewNoopTUN returns a tun.Device that discards all traffic -- see
// noopTUN's doc.
func NewNoopTUN(mtu int) tun.Device {
	t := &noopTUN{mtu: mtu, events: make(chan tun.Event, 1), closed: make(chan struct{})}
	t.events <- tun.EventUp
	return t
}

func (t *noopTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	<-t.closed
	return 0, os.ErrClosed
}

func (t *noopTUN) Write(bufs [][]byte, offset int) (int, error) {
	return len(bufs), nil
}

func (t *noopTUN) MTU() (int, error)        { return t.mtu, nil }
func (t *noopTUN) Name() (string, error)    { return "awg-probe", nil }
func (t *noopTUN) Events() <-chan tun.Event { return t.events }
func (t *noopTUN) BatchSize() int           { return 1 }
func (t *noopTUN) File() *os.File           { return nil }

func (t *noopTUN) Close() error {
	t.closeOnce.Do(func() {
		close(t.closed)
		close(t.events)
	})
	return nil
}

var _ tun.Device = (*noopTUN)(nil)
