package control

import (
	"net/netip"
	"reflect"
	"testing"
)

func roundTrip(t *testing.T, m Message) Message {
	t.Helper()
	body := m.encodeBody()
	decoded, err := decodeBody(m.Type(), body)
	if err != nil {
		t.Fatalf("decodeBody(%T): %v", m, err)
	}
	return decoded
}

func TestMessageRoundTrip(t *testing.T) {
	addr4 := netip.MustParseAddrPort("203.0.113.7:51820")
	addr6 := netip.MustParseAddrPort("[2001:db8::1]:51820")

	cases := []Message{
		Hello{Role: RoleY, WGPublicKey: [32]byte{1, 2, 3}, ProtocolVersion: 1},
		XInfo{ProbePortA: 40001, ProbePortB: 40002, NativeListenPort: 51821, CloakedListenPort: 51820},
		NATProbeRequest{ProbeID: 0xDEADBEEF, Port: 40001},
		NATProbeResponse{ProbeID: 0xDEADBEEF, ObservedAddr: addr4},
		NATProbeResponse{ProbeID: 1, ObservedAddr: addr6},
		NativeEndpointReport{SessionID: SessionID{1, 2, 3}, ExternalAddr: addr4},
		NativeReady{SessionID: SessionID{9, 9, 9}},
		NativeFailed{SessionID: SessionID{1}, Reason: "handshake-timeout"},
		ModeDecision{SessionID: SessionID{2}, Mode: ModeCloaked, Reason: "symmetric-nat"},
		CloakedParams{
			S1: 15, S2: 18, S3: 20, S4: 25,
			H1Lo: 100, H1Hi: 200,
			H2Lo: 300, H2Hi: 400,
			H3Lo: 500, H3Hi: 600,
			H4Lo: 700, H4Hi: 800,
			HeaderProtectionKey: [32]byte{0xAA, 0xBB},
			HasHeaderProtection: true,
			ListenEndpoint:      addr4,
		},
		Ping{Nonce: 42},
		Pong{Nonce: 42},
		Bye{Reason: "shutting down"},
		Bye{Reason: ""},
	}

	for _, m := range cases {
		got := roundTrip(t, m)
		if !reflect.DeepEqual(got, m) {
			t.Errorf("round-trip mismatch for %T:\n  sent: %#v\n  got:  %#v", m, m, got)
		}
	}
}

func TestDecodeBodyMalformedTruncated(t *testing.T) {
	// Every message type should fail closed (return an error, not panic)
	// on a truncated/empty body.
	types := []MessageType{
		TypeHello, TypeXInfo, TypeNATProbeRequest, TypeNATProbeResponse,
		TypeNativeEndpointReport, TypeNativeReady, TypeNativeFailed,
		TypeModeDecision, TypeCloakedParams, TypePing, TypePong, TypeBye,
	}
	for _, ty := range types {
		if _, err := decodeBody(ty, nil); err == nil {
			t.Errorf("decodeBody(%d, nil) unexpectedly succeeded", ty)
		}
	}
}

func TestDecodeBodyUnknownType(t *testing.T) {
	if _, err := decodeBody(MessageType(255), []byte{1, 2, 3}); err == nil {
		t.Fatalf("expected error for unknown message type")
	}
}

func TestAddrPortRoundTripV4AndV6(t *testing.T) {
	for _, s := range []string{"203.0.113.7:51820", "[2001:db8::1]:51820", "0.0.0.0:0"} {
		ap := netip.MustParseAddrPort(s)
		buf := putAddrPort(nil, ap)
		got, rest, err := getAddrPort(buf)
		if err != nil {
			t.Fatalf("getAddrPort(%s): %v", s, err)
		}
		if len(rest) != 0 {
			t.Fatalf("getAddrPort(%s): unexpected trailing bytes: %d", s, len(rest))
		}
		if got != ap {
			t.Fatalf("getAddrPort(%s): got %s", s, got)
		}
	}
}
