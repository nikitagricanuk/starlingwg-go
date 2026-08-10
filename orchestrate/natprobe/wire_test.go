package natprobe

import (
	"net/netip"
	"testing"
)

func TestRequestRoundTrip(t *testing.T) {
	buf := encodeRequest(0xDEADBEEFCAFEBABE)
	nonce, ok := decodeRequest(buf)
	if !ok {
		t.Fatalf("decodeRequest failed on a validly-encoded request")
	}
	if nonce != 0xDEADBEEFCAFEBABE {
		t.Fatalf("nonce = %x, want %x", nonce, uint64(0xDEADBEEFCAFEBABE))
	}
}

func TestDecodeRequestRejectsGarbage(t *testing.T) {
	if _, ok := decodeRequest([]byte("not a probe packet at all")); ok {
		t.Fatalf("expected decodeRequest to reject non-magic garbage")
	}
	if _, ok := decodeRequest(nil); ok {
		t.Fatalf("expected decodeRequest to reject empty input")
	}
	if _, ok := decodeRequest([]byte{'N', 'P', 'R', '1'}); ok {
		t.Fatalf("expected decodeRequest to reject a truncated request (magic only, no nonce)")
	}
}

func TestResponseRoundTripV4AndV6(t *testing.T) {
	for _, s := range []string{"203.0.113.9:12345", "[2001:db8::9]:12345"} {
		ap := netip.MustParseAddrPort(s)
		buf := encodeResponse(42, ap)
		nonce, observed, err := decodeResponse(buf)
		if err != nil {
			t.Fatalf("decodeResponse(%s): %v", s, err)
		}
		if nonce != 42 {
			t.Fatalf("nonce = %d, want 42", nonce)
		}
		if observed != ap {
			t.Fatalf("observed = %s, want %s", observed, ap)
		}
	}
}

func TestDecodeResponseRejectsGarbage(t *testing.T) {
	if _, _, err := decodeResponse([]byte("garbage")); err == nil {
		t.Fatalf("expected decodeResponse to reject non-magic garbage")
	}
	if _, _, err := decodeResponse(nil); err == nil {
		t.Fatalf("expected decodeResponse to reject empty input")
	}
}
