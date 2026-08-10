package natprobe

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// The probe wire protocol is a minimal, self-hosted STUN-equivalent: a
// nonce-tagged request, echoed back with the source (ip, port) X actually
// observed. The nonce lets the requester ignore stray/off-path packets;
// there is no stronger authentication here since NAT characterization
// itself carries no sensitive data -- the control channel (which is
// authenticated) is what carries the real coordination.

var reqMagic = [4]byte{'N', 'P', 'R', '1'}
var respMagic = [4]byte{'N', 'P', 'S', '1'}

const nonceSize = 8

func encodeRequest(nonce uint64) []byte {
	buf := make([]byte, 4+nonceSize)
	copy(buf[:4], reqMagic[:])
	binary.BigEndian.PutUint64(buf[4:], nonce)
	return buf
}

func decodeRequest(b []byte) (nonce uint64, ok bool) {
	if len(b) < 4+nonceSize || [4]byte(b[:4]) != reqMagic {
		return 0, false
	}
	return binary.BigEndian.Uint64(b[4 : 4+nonceSize]), true
}

func encodeResponse(nonce uint64, observed netip.AddrPort) []byte {
	buf := make([]byte, 0, 4+nonceSize+19)
	buf = append(buf, respMagic[:]...)
	var n [nonceSize]byte
	binary.BigEndian.PutUint64(n[:], nonce)
	buf = append(buf, n[:]...)
	addr := observed.Addr()
	if addr.Is4() {
		buf = append(buf, 4)
		a4 := addr.As4()
		buf = append(buf, a4[:]...)
	} else {
		buf = append(buf, 6)
		a16 := addr.As16()
		buf = append(buf, a16[:]...)
	}
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], observed.Port())
	buf = append(buf, portBuf[:]...)
	return buf
}

func decodeResponse(b []byte) (nonce uint64, observed netip.AddrPort, err error) {
	if len(b) < 4+nonceSize+1 || [4]byte(b[:4]) != respMagic {
		return 0, netip.AddrPort{}, fmt.Errorf("natprobe: not a valid response")
	}
	nonce = binary.BigEndian.Uint64(b[4 : 4+nonceSize])
	rest := b[4+nonceSize:]
	family := rest[0]
	rest = rest[1:]
	var addr netip.Addr
	switch family {
	case 4:
		if len(rest) < 4+2 {
			return 0, netip.AddrPort{}, fmt.Errorf("natprobe: truncated v4 response")
		}
		addr = netip.AddrFrom4([4]byte(rest[:4]))
		rest = rest[4:]
	case 6:
		if len(rest) < 16+2 {
			return 0, netip.AddrPort{}, fmt.Errorf("natprobe: truncated v6 response")
		}
		addr = netip.AddrFrom16([16]byte(rest[:16]))
		rest = rest[16:]
	default:
		return 0, netip.AddrPort{}, fmt.Errorf("natprobe: unknown address family %d", family)
	}
	port := binary.BigEndian.Uint16(rest[:2])
	return nonce, netip.AddrPortFrom(addr, port), nil
}
