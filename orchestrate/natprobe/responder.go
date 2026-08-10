package natprobe

import (
	"net"
	"net/netip"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
)

// Responder is X's side of NAT characterization: a trivial UDP echo
// service that reports back whatever source (ip, port) it observed for a
// request. X runs two of these, on two distinguishable ports, so Y can
// compare the mappings it gets on each and tell cone-type from
// symmetric-type NAT. No third-party STUN service is used or needed.
type Responder struct {
	conn    net.PacketConn
	resolve func(netip.AddrPort) netip.AddrPort
	logger  *device.Logger
	done    chan struct{}
}

// NewResponder starts listening on addr (e.g. "0.0.0.0:40001") and returns
// a Responder ready to Serve. resolve, if non-nil, transforms the observed
// source address before it's echoed back -- production always leaves this
// nil (identity); tests use it to simulate what a symmetric NAT's per-
// destination remapping would look like from Y's perspective, without
// needing real NAT hardware.
func NewResponder(addr string, logger *device.Logger, resolve func(netip.AddrPort) netip.AddrPort) (*Responder, error) {
	// Bind strictly to the family addr actually specifies. The generic
	// "udp" network, given an unspecified-looking address like
	// "0.0.0.0:PORT", can resolve to a dual-stack IPv6 socket on some
	// platforms -- which then reports every IPv4 sender's address back as
	// a 4-in-6 mapped form ("[::ffff:127.0.0.1]:PORT"). That address gets
	// echoed to Y, reported back to X as Y's "external address", and
	// configured as a peer endpoint -- and sending to a 4-in-6 endpoint
	// can genuinely fail ("no route to host") depending on the sending
	// socket's own dual-stack configuration. Binding "udp4"/"udp6"
	// explicitly keeps observed addresses in their real, unambiguous
	// family throughout.
	network := "udp4"
	if host, _, err := net.SplitHostPort(addr); err == nil {
		if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
			network = "udp6"
		}
	}
	conn, err := net.ListenPacket(network, addr)
	if err != nil {
		return nil, err
	}
	if resolve == nil {
		resolve = func(a netip.AddrPort) netip.AddrPort { return a }
	}
	return &Responder{conn: conn, resolve: resolve, logger: logger, done: make(chan struct{})}, nil
}

// LocalAddr returns the address the responder is actually listening on
// (useful when addr was given with port 0 in tests).
func (r *Responder) LocalAddr() net.Addr { return r.conn.LocalAddr() }

// Serve runs the echo loop until Close is called. It always returns a
// non-nil error (net.ErrClosed after a clean Close).
func (r *Responder) Serve() error {
	buf := make([]byte, 1500)
	for {
		n, from, err := r.conn.ReadFrom(buf)
		if err != nil {
			select {
			case <-r.done:
				return err
			default:
			}
			if r.logger != nil {
				r.logger.Errorf("natprobe responder: read error: %v", err)
			}
			return err
		}
		nonce, ok := decodeRequest(buf[:n])
		if !ok {
			continue // not a probe packet (or corrupt) -- ignore, don't reflect arbitrary traffic
		}
		udpAddr, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		observed := udpAddr.AddrPort()
		observed = netip.AddrPortFrom(observed.Addr().Unmap(), observed.Port())
		observed = r.resolve(observed)
		resp := encodeResponse(nonce, observed)
		if _, err := r.conn.WriteTo(resp, from); err != nil && r.logger != nil {
			r.logger.Verbosef("natprobe responder: write error: %v", err)
		}
	}
}

// Close stops Serve and releases the socket.
func (r *Responder) Close() error {
	close(r.done)
	return r.conn.Close()
}
