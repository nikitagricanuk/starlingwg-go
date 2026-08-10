package control

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// Role mirrors orchestrate.Role without importing it (control stays
// role-agnostic and dependency-free of the orchestrate package; orchestrate
// imports control, never the reverse).
type Role uint8

const (
	RoleX Role = 0
	RoleY Role = 1
)

// Mode identifies which connectivity mode a decision/session refers to.
type Mode uint8

const (
	ModeUnknown Mode = 0
	ModeNative  Mode = 1
	ModeCloaked Mode = 2
)

// SessionID identifies one native/cloaked establishment attempt so replies
// can be correlated with the request that triggered them.
type SessionID [16]byte

type MessageType uint8

const (
	TypeHello MessageType = iota + 1
	TypeXInfo
	TypeNATProbeRequest
	TypeNATProbeResponse
	TypeNativeEndpointReport
	TypeNativeReady
	TypeNativeFailed
	TypeModeDecision
	TypeCloakedParams
	TypePing
	TypePong
	TypeBye
)

// Message is any control-channel message. Encode/Decode are the tagged
// binary codec described in the plan (deliberately not gob: keeps the wire
// format auditable, avoids reflection-based cross-version drift on a
// security-relevant surface).
type Message interface {
	Type() MessageType
	encodeBody() []byte
}

func (Hello) Type() MessageType                { return TypeHello }
func (XInfo) Type() MessageType                { return TypeXInfo }
func (NATProbeRequest) Type() MessageType      { return TypeNATProbeRequest }
func (NATProbeResponse) Type() MessageType     { return TypeNATProbeResponse }
func (NativeEndpointReport) Type() MessageType { return TypeNativeEndpointReport }
func (NativeReady) Type() MessageType          { return TypeNativeReady }
func (NativeFailed) Type() MessageType         { return TypeNativeFailed }
func (ModeDecision) Type() MessageType         { return TypeModeDecision }
func (CloakedParams) Type() MessageType        { return TypeCloakedParams }
func (Ping) Type() MessageType                 { return TypePing }
func (Pong) Type() MessageType                 { return TypePong }
func (Bye) Type() MessageType                  { return TypeBye }

// Hello is the first application message each side sends once the Noise_IK
// handshake completes, confirming role expectations match.
type Hello struct {
	Role            Role
	WGPublicKey     [KeySize]byte
	ProtocolVersion uint8
}

// XInfo is sent by X right after Hello, advertising the fixed ports every Y
// needs: the two NAT-probe echo ports and the two shared-Device ports
// (native and cloaked). X's shared native Device binds one fixed port used
// by every native-mode Y, so it must be known up front, not discovered
// per-attempt.
type XInfo struct {
	ProbePortA        uint16
	ProbePortB        uint16
	NativeListenPort  uint16
	CloakedListenPort uint16
}

// NATProbeRequest/Response drive NAT characterization: Y asks X's probe
// responder (on two distinguishable ports) what source address it observed.
type NATProbeRequest struct {
	ProbeID uint64
	Port    uint16 // which of X's probe ports this request targets (A or B)
}

type NATProbeResponse struct {
	ProbeID      uint64
	ObservedAddr netip.AddrPort
}

// NativeEndpointReport: Y reports its punched external address, requesting
// X attempt a native handshake toward it.
type NativeEndpointReport struct {
	SessionID    SessionID
	ExternalAddr netip.AddrPort
}

// NativeReady / NativeFailed: X's result of the native attempt.
type NativeReady struct {
	SessionID SessionID
}

type NativeFailed struct {
	SessionID SessionID
	Reason    string
}

// ModeDecision: either side announcing that native mode is not going to be
// attempted (e.g. Y detected symmetric NAT), so both sides' state machines
// converge on cloaked without waiting for a native timeout.
type ModeDecision struct {
	SessionID SessionID
	Mode      Mode
	Reason    string
}

// CloakedParams: X -> Y, the exact obfuscation parameters Y must use --
// only the fields that must match byte-for-byte between peers (S1-S4,
// H1-H4, HeaderProtectionKey); Jc/Jmin/Jmax/I1-I5/timings are local-only
// and never sent here.
type CloakedParams struct {
	S1, S2, S3, S4      uint32
	H1Lo, H1Hi          uint32
	H2Lo, H2Hi          uint32
	H3Lo, H3Hi          uint32
	H4Lo, H4Hi          uint32
	HeaderProtectionKey [32]byte
	HasHeaderProtection bool
	ListenEndpoint      netip.AddrPort
}

// Ping/Pong: control-channel liveness heartbeat, independent of the data
// tunnel's own keepalive.
type Ping struct{ Nonce uint64 }
type Pong struct{ Nonce uint64 }

// Bye: graceful teardown notice.
type Bye struct{ Reason string }

// --- encoding helpers ---

func putU16(buf []byte, v uint16) []byte {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return append(buf, b[:]...)
}

func putU32(buf []byte, v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return append(buf, b[:]...)
}

func putU64(buf []byte, v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return append(buf, b[:]...)
}

func putString(buf []byte, s string) []byte {
	buf = putU16(buf, uint16(len(s)))
	return append(buf, s...)
}

func putAddrPort(buf []byte, ap netip.AddrPort) []byte {
	addr := ap.Addr()
	if addr.Is4() {
		buf = append(buf, 4)
		a4 := addr.As4()
		buf = append(buf, a4[:]...)
	} else {
		buf = append(buf, 6)
		a16 := addr.As16()
		buf = append(buf, a16[:]...)
	}
	return putU16(buf, ap.Port())
}

func getAddrPort(b []byte) (netip.AddrPort, []byte, error) {
	if len(b) < 1 {
		return netip.AddrPort{}, nil, fmt.Errorf("control: truncated addrport")
	}
	family, rest := b[0], b[1:]
	var addr netip.Addr
	switch family {
	case 4:
		if len(rest) < 4 {
			return netip.AddrPort{}, nil, fmt.Errorf("control: truncated v4 addr")
		}
		addr = netip.AddrFrom4([4]byte(rest[:4]))
		rest = rest[4:]
	case 6:
		if len(rest) < 16 {
			return netip.AddrPort{}, nil, fmt.Errorf("control: truncated v6 addr")
		}
		addr = netip.AddrFrom16([16]byte(rest[:16]))
		rest = rest[16:]
	default:
		return netip.AddrPort{}, nil, fmt.Errorf("control: unknown address family %d", family)
	}
	if len(rest) < 2 {
		return netip.AddrPort{}, nil, fmt.Errorf("control: truncated port")
	}
	port := binary.BigEndian.Uint16(rest[:2])
	return netip.AddrPortFrom(addr, port), rest[2:], nil
}

func getU16(b []byte) (uint16, []byte, error) {
	if len(b) < 2 {
		return 0, nil, fmt.Errorf("control: truncated u16")
	}
	return binary.BigEndian.Uint16(b[:2]), b[2:], nil
}

func getU32(b []byte) (uint32, []byte, error) {
	if len(b) < 4 {
		return 0, nil, fmt.Errorf("control: truncated u32")
	}
	return binary.BigEndian.Uint32(b[:4]), b[4:], nil
}

func getU64(b []byte) (uint64, []byte, error) {
	if len(b) < 8 {
		return 0, nil, fmt.Errorf("control: truncated u64")
	}
	return binary.BigEndian.Uint64(b[:8]), b[8:], nil
}

func getString(b []byte) (string, []byte, error) {
	l, rest, err := getU16(b)
	if err != nil {
		return "", nil, err
	}
	if len(rest) < int(l) {
		return "", nil, fmt.Errorf("control: truncated string")
	}
	return string(rest[:l]), rest[l:], nil
}

// --- Message.encodeBody implementations ---

func (m Hello) encodeBody() []byte {
	buf := make([]byte, 0, 1+KeySize+1)
	buf = append(buf, byte(m.Role))
	buf = append(buf, m.WGPublicKey[:]...)
	buf = append(buf, m.ProtocolVersion)
	return buf
}

func (m XInfo) encodeBody() []byte {
	buf := make([]byte, 0, 8)
	buf = putU16(buf, m.ProbePortA)
	buf = putU16(buf, m.ProbePortB)
	buf = putU16(buf, m.NativeListenPort)
	buf = putU16(buf, m.CloakedListenPort)
	return buf
}

func (m NATProbeRequest) encodeBody() []byte {
	buf := make([]byte, 0, 10)
	buf = putU64(buf, m.ProbeID)
	buf = putU16(buf, m.Port)
	return buf
}

func (m NATProbeResponse) encodeBody() []byte {
	buf := make([]byte, 0, 8+19)
	buf = putU64(buf, m.ProbeID)
	buf = putAddrPort(buf, m.ObservedAddr)
	return buf
}

func (m NativeEndpointReport) encodeBody() []byte {
	buf := make([]byte, 0, 16+19)
	buf = append(buf, m.SessionID[:]...)
	buf = putAddrPort(buf, m.ExternalAddr)
	return buf
}

func (m NativeReady) encodeBody() []byte {
	buf := make([]byte, 0, 16)
	return append(buf, m.SessionID[:]...)
}

func (m NativeFailed) encodeBody() []byte {
	buf := make([]byte, 0, 16+2+len(m.Reason))
	buf = append(buf, m.SessionID[:]...)
	buf = putString(buf, m.Reason)
	return buf
}

func (m ModeDecision) encodeBody() []byte {
	buf := make([]byte, 0, 16+1+2+len(m.Reason))
	buf = append(buf, m.SessionID[:]...)
	buf = append(buf, byte(m.Mode))
	buf = putString(buf, m.Reason)
	return buf
}

func (m CloakedParams) encodeBody() []byte {
	buf := make([]byte, 0, 4*4+4*8+1+32+19)
	buf = putU32(buf, m.S1)
	buf = putU32(buf, m.S2)
	buf = putU32(buf, m.S3)
	buf = putU32(buf, m.S4)
	buf = putU32(buf, m.H1Lo)
	buf = putU32(buf, m.H1Hi)
	buf = putU32(buf, m.H2Lo)
	buf = putU32(buf, m.H2Hi)
	buf = putU32(buf, m.H3Lo)
	buf = putU32(buf, m.H3Hi)
	buf = putU32(buf, m.H4Lo)
	buf = putU32(buf, m.H4Hi)
	if m.HasHeaderProtection {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}
	buf = append(buf, m.HeaderProtectionKey[:]...)
	buf = putAddrPort(buf, m.ListenEndpoint)
	return buf
}

func (m Ping) encodeBody() []byte { return putU64(nil, m.Nonce) }
func (m Pong) encodeBody() []byte { return putU64(nil, m.Nonce) }

func (m Bye) encodeBody() []byte { return putString(nil, m.Reason) }

// decodeBody parses a message body given its type tag.
func decodeBody(t MessageType, body []byte) (Message, error) {
	switch t {
	case TypeHello:
		if len(body) < 1+KeySize+1 {
			return nil, fmt.Errorf("control: truncated Hello")
		}
		var m Hello
		m.Role = Role(body[0])
		copy(m.WGPublicKey[:], body[1:1+KeySize])
		m.ProtocolVersion = body[1+KeySize]
		return m, nil

	case TypeXInfo:
		var m XInfo
		b := body
		var err error
		if m.ProbePortA, b, err = getU16(b); err != nil {
			return nil, err
		}
		if m.ProbePortB, b, err = getU16(b); err != nil {
			return nil, err
		}
		if m.NativeListenPort, b, err = getU16(b); err != nil {
			return nil, err
		}
		if m.CloakedListenPort, b, err = getU16(b); err != nil {
			return nil, err
		}
		return m, nil

	case TypeNATProbeRequest:
		var m NATProbeRequest
		b := body
		var err error
		if m.ProbeID, b, err = getU64(b); err != nil {
			return nil, err
		}
		if m.Port, b, err = getU16(b); err != nil {
			return nil, err
		}
		return m, nil

	case TypeNATProbeResponse:
		var m NATProbeResponse
		b := body
		var err error
		if m.ProbeID, b, err = getU64(b); err != nil {
			return nil, err
		}
		if m.ObservedAddr, b, err = getAddrPort(b); err != nil {
			return nil, err
		}
		return m, nil

	case TypeNativeEndpointReport:
		if len(body) < 16 {
			return nil, fmt.Errorf("control: truncated NativeEndpointReport")
		}
		var m NativeEndpointReport
		copy(m.SessionID[:], body[:16])
		var err error
		if m.ExternalAddr, _, err = getAddrPort(body[16:]); err != nil {
			return nil, err
		}
		return m, nil

	case TypeNativeReady:
		if len(body) < 16 {
			return nil, fmt.Errorf("control: truncated NativeReady")
		}
		var m NativeReady
		copy(m.SessionID[:], body[:16])
		return m, nil

	case TypeNativeFailed:
		if len(body) < 16 {
			return nil, fmt.Errorf("control: truncated NativeFailed")
		}
		var m NativeFailed
		copy(m.SessionID[:], body[:16])
		var err error
		if m.Reason, _, err = getString(body[16:]); err != nil {
			return nil, err
		}
		return m, nil

	case TypeModeDecision:
		if len(body) < 17 {
			return nil, fmt.Errorf("control: truncated ModeDecision")
		}
		var m ModeDecision
		copy(m.SessionID[:], body[:16])
		m.Mode = Mode(body[16])
		var err error
		if m.Reason, _, err = getString(body[17:]); err != nil {
			return nil, err
		}
		return m, nil

	case TypeCloakedParams:
		var m CloakedParams
		b := body
		var err error
		for _, dst := range []*uint32{&m.S1, &m.S2, &m.S3, &m.S4, &m.H1Lo, &m.H1Hi, &m.H2Lo, &m.H2Hi, &m.H3Lo, &m.H3Hi, &m.H4Lo, &m.H4Hi} {
			if *dst, b, err = getU32(b); err != nil {
				return nil, err
			}
		}
		if len(b) < 1+32 {
			return nil, fmt.Errorf("control: truncated CloakedParams")
		}
		m.HasHeaderProtection = b[0] == 1
		copy(m.HeaderProtectionKey[:], b[1:33])
		b = b[33:]
		if m.ListenEndpoint, _, err = getAddrPort(b); err != nil {
			return nil, err
		}
		return m, nil

	case TypePing:
		v, _, err := getU64(body)
		if err != nil {
			return nil, err
		}
		return Ping{Nonce: v}, nil

	case TypePong:
		v, _, err := getU64(body)
		if err != nil {
			return nil, err
		}
		return Pong{Nonce: v}, nil

	case TypeBye:
		s, _, err := getString(body)
		if err != nil {
			return nil, err
		}
		return Bye{Reason: s}, nil

	default:
		return nil, fmt.Errorf("control: unknown message type %d", t)
	}
}
