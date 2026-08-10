package nativeflow

import (
	"net"
	"net/netip"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
)

// PreboundBind is a conn.Bind that reuses an already-open *net.UDPConn
// instead of opening a fresh socket in Open(). This is what lets Y probe
// its NAT and punch a pinhole on one socket, then hand that *same* socket
// (same local port, so the punched mapping still applies) to the Device
// that carries real traffic -- with no gap where the socket is closed and
// reopened, which could lose the exact mapping just established,
// particularly on a port-restricted-cone NAT that only forwards from the
// specific port it was punched toward.
//
// device.Device calls Close() then Open() on its bind any time it rebinds
// -- not just on a genuine listen_port change, but also, asynchronously,
// whenever the underlying tun.Device reports an EventUp (RoutineTUNEventReader
// calls device.Up() itself, which triggers exactly this cycle -- confirmed
// via tuntest.ChannelTUN, which emits an initial EventUp on construction,
// racing against an explicit Up() call the same way a real host-supplied
// TUN legitimately can). A normal Bind tolerates this because it creates
// a brand new real socket on every Open(); PreboundBind wraps a single
// socket that cannot be closed and reopened, so Close() here does not
// close the socket at all -- it only unblocks the *current* receive
// goroutine's pending read (via an immediately-expired read deadline),
// exactly the signal device.Device needs to consider the old bind cleanly
// stopped before it calls Open() again. The real socket is only ever
// closed by whoever owns it (the nativeflow caller that created it),
// entirely independent of the Device's own bind lifecycle.
type PreboundBind struct {
	conn *net.UDPConn
}

var _ conn.Bind = (*PreboundBind)(nil)

// NewPreboundBind wraps an already-bound *net.UDPConn (e.g. the exact
// socket natprobe.Characterize just ran on) as a conn.Bind.
func NewPreboundBind(udpConn *net.UDPConn) *PreboundBind {
	return &PreboundBind{conn: udpConn}
}

// Open ignores port -- the socket is already bound -- and returns its
// actual local port. It clears any read deadline a prior Close() left in
// place, so reads block normally again.
func (b *PreboundBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	if err := b.conn.SetReadDeadline(time.Time{}); err != nil {
		return nil, 0, err
	}

	fn := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, addrPort, err := b.conn.ReadFromUDPAddrPort(bufs[0])
		if err != nil {
			if isDeadlineExceeded(err) {
				// device/receive.go's RoutineReceiveIncoming treats any
				// net.Error with Temporary()==true (which a deadline error
				// is) as transient and retries after a brief sleep, up to
				// 10 times, before giving up -- appropriate for a real,
				// still-open socket hitting a genuine transient read
				// error, but wrong here: this deadline only ever fires
				// because Close() just set it, and nothing re-arms it
				// (only Open() does), so every one of those 10 retries
				// hits the exact same already-expired deadline and just
				// burns ~3.3s before the routine finally exits. Reporting
				// net.ErrClosed instead makes RoutineReceiveIncoming's
				// existing errors.Is(err, net.ErrClosed) fast-path return
				// immediately, matching how a normal Bind's Close()
				// behaves -- device.Device.Close() (and, in turn,
				// Orchestrator.Stop()'s per-session cleanup) no longer
				// blocks for seconds tearing down a native-mode session.
				return 0, net.ErrClosed
			}
			return 0, err
		}
		sizes[0] = n
		eps[0] = udpEndpoint(addrPort)
		return 1, nil
	}
	return []conn.ReceiveFunc{fn}, uint16(b.conn.LocalAddr().(*net.UDPAddr).Port), nil
}

// Close does not close the underlying socket -- see the type doc. It only
// interrupts a currently-blocked read so device.Device's internal rebind
// bookkeeping (which waits for the old receive goroutine to exit) doesn't
// hang.
func (b *PreboundBind) Close() error {
	return b.conn.SetReadDeadline(time.Now())
}

// isDeadlineExceeded reports whether err is (or wraps) a read deadline
// expiring, as opposed to some other I/O failure. Open() clears any read
// deadline before installing this ReceiveFunc and nothing else in normal
// operation ever sets one, so by construction the only way a read can time
// out is the exact one Close() just triggered.
func isDeadlineExceeded(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

func (b *PreboundBind) SetMark(uint32) error { return nil }
func (b *PreboundBind) BatchSize() int       { return 1 }

func (b *PreboundBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	dst := netip.AddrPort(ep.(udpEndpoint))
	for _, buf := range bufs {
		if _, err := b.conn.WriteToUDPAddrPort(buf, dst); err != nil {
			return err
		}
	}
	return nil
}

func (b *PreboundBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return udpEndpoint(ap), nil
}

// udpEndpoint is the conn.Endpoint implementation for PreboundBind.
type udpEndpoint netip.AddrPort

func (e udpEndpoint) ClearSrc()           {}
func (e udpEndpoint) SrcToString() string { return "" }
func (e udpEndpoint) DstToString() string { return netip.AddrPort(e).String() }
func (e udpEndpoint) DstIP() netip.Addr   { return netip.AddrPort(e).Addr() }
func (e udpEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

func (e udpEndpoint) DstToBytes() []byte {
	ap := netip.AddrPort(e)
	b, _ := ap.MarshalBinary()
	return b
}
