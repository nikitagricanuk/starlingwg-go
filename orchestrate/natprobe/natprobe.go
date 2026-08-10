package natprobe

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// DefaultTimeout and DefaultRetries are the per-probe timeout and retry
// count: a probe that gets no response after DefaultRetries+1 attempts is
// treated as inconclusive, which callers fall back to cloaked from (never
// block indefinitely, per requirement #2/#4).
const (
	DefaultTimeout = 2 * time.Second
	DefaultRetries = 2
)

// packetRW is the minimal socket surface Characterize needs; satisfied by
// *net.UDPConn (production, the same socket Y will use for the AWG
// tunnel -- see the plan's native-mode establishment flow) and by fakes in
// tests.
type packetRW interface {
	WriteTo(b []byte, addr net.Addr) (int, error)
	ReadFrom(b []byte) (int, net.Addr, error)
	SetReadDeadline(t time.Time) error
}

func randomNonce() (uint64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b[:]), nil
}

// probeOnce sends one request to dst and waits up to timeout for a
// matching response, retrying up to retries additional times. It returns
// the observed external address, or an error if every attempt timed out.
func probeOnce(conn packetRW, dst netip.AddrPort, timeout time.Duration, retries int) (netip.AddrPort, error) {
	dstAddr := net.UDPAddrFromAddrPort(dst)
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		nonce, err := randomNonce()
		if err != nil {
			return netip.AddrPort{}, err
		}
		if _, err := conn.WriteTo(encodeRequest(nonce), dstAddr); err != nil {
			lastErr = err
			continue
		}
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return netip.AddrPort{}, err
		}
		buf := make([]byte, 64)
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			n, _, err := conn.ReadFrom(buf)
			if err != nil {
				lastErr = err
				break
			}
			gotNonce, observed, err := decodeResponse(buf[:n])
			if err != nil || gotNonce != nonce {
				continue // stray/mismatched packet, keep waiting within this attempt's deadline
			}
			return observed, nil
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("natprobe: no response from %s after %d attempts", dst, retries+1)
	}
	return netip.AddrPort{}, lastErr
}

// Characterize runs Y's NAT classification algorithm on conn -- the exact
// socket Y intends to use for the AWG tunnel, so the mapping characterized
// is the one that will actually matter for native mode. It probes X's two
// distinguishable reflector endpoints (portA, portB) and compares the
// externally-observed mappings: identical => cone-type (native viable),
// different => symmetric-type (native is hopeless), no response from
// either => Unknown (also treated as "don't attempt native").
func Characterize(conn packetRW, portA, portB netip.AddrPort, timeout time.Duration, retries int) (Result, error) {
	mappingA, errA := probeOnce(conn, portA, timeout, retries)
	if errA != nil {
		mappingB, errB := probeOnce(conn, portB, timeout, retries)
		if errB != nil {
			// Neither probe port was reachable at all -- can't
			// characterize; never block indefinitely, fall back to
			// cloaked via Unknown.
			return Result{Class: Unknown}, fmt.Errorf("natprobe: both probes failed: %v; %v", errA, errB)
		}
		// One endpoint reachable, one not -- inconclusive about
		// address-independence, but we do have *a* mapping. Treat as
		// unknown rather than guessing cone from a single data point.
		_ = mappingB
		return Result{Class: Unknown}, nil
	}

	mappingB, errB := probeOnce(conn, portB, timeout, retries)
	if errB != nil {
		return Result{Class: Unknown}, nil
	}

	if mappingA == mappingB {
		return Result{Class: Cone, ExternalAddr: mappingA}, nil
	}
	return Result{Class: Symmetric}, nil
}
