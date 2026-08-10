package orchestrate

import (
	"net/netip"
	"strings"
	"testing"
)

func TestRangeString(t *testing.T) {
	if got := rangeString(5, 5); got != "5" {
		t.Errorf("rangeString(5,5) = %q, want %q", got, "5")
	}
	if got := rangeString(100, 200); got != "100-200" {
		t.Errorf("rangeString(100,200) = %q, want %q", got, "100-200")
	}
}

func fullObfProfile() ObfuscationProfile {
	return ObfuscationProfile{
		Jc: 5, Jmin: 500, Jmax: 1000,
		S1: 15, S2: 18, S3: 20, S4: 25,
		H1Lo: 100, H1Hi: 200,
		H2Lo: 300, H2Hi: 400,
		H3Lo: 500, H3Hi: 600,
		H4Lo: 700, H4Hi: 800,
		HasHeaderProtectionKey:   true,
		HeaderProtectionKey:      [32]byte{1, 2, 3, 4},
		I1:                       "<b 0xAABB>",
		ContentPaddingAdditionLo: 10,
		ContentPaddingAdditionHi: 20,
	}
}

func TestObfuscationProfileUAPIContainsAllFields(t *testing.T) {
	p := fullObfProfile()
	out := p.uapi()
	for _, want := range []string{
		"jc=5", "jmin=500", "jmax=1000",
		"s1=15", "s2=18", "s3=20", "s4=25",
		"h1=100-200", "h2=300-400", "h3=500-600", "h4=700-800",
		"header_protection_key=0102030400000000000000000000000000000000000000000000000000000000",
		"i1=<b 0xAABB>",
		"content_padding_addition=10-20",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("uapi() missing %q; full output:\n%s", want, out)
		}
	}
}

func TestObfuscationProfileUAPIOmitsUnsetFields(t *testing.T) {
	out := ObfuscationProfile{}.uapi()
	if out != "" {
		t.Errorf("zero-value ObfuscationProfile.uapi() = %q, want empty", out)
	}
}

func TestObfuscationProfileUAPIOmitsHeaderProtectionWhenUnset(t *testing.T) {
	p := fullObfProfile()
	p.HasHeaderProtectionKey = false
	out := p.uapi()
	if strings.Contains(out, "header_protection_key") {
		t.Errorf("uapi() included header_protection_key despite HasHeaderProtectionKey=false:\n%s", out)
	}
}

func TestToWireParamsOnlyCarriesServerSideFields(t *testing.T) {
	p := fullObfProfile()
	ep := netip.MustParseAddrPort("203.0.113.1:51820")
	wire := p.toWireParams(ep)

	if wire.S1 != p.S1 || wire.S2 != p.S2 || wire.S3 != p.S3 || wire.S4 != p.S4 {
		t.Errorf("toWireParams did not carry S1-S4 correctly: %+v", wire)
	}
	if wire.H1Lo != p.H1Lo || wire.H1Hi != p.H1Hi {
		t.Errorf("toWireParams did not carry H1 correctly: %+v", wire)
	}
	if wire.HasHeaderProtection != p.HasHeaderProtectionKey || wire.HeaderProtectionKey != p.HeaderProtectionKey {
		t.Errorf("toWireParams did not carry HeaderProtectionKey correctly: %+v", wire)
	}
	if wire.ListenEndpoint != ep {
		t.Errorf("toWireParams.ListenEndpoint = %s, want %s", wire.ListenEndpoint, ep)
	}
	// Jc/Jmin/Jmax/I1-I5/timings/content-padding are local-only and must
	// never appear on the wire -- control.CloakedParams has no fields for
	// them at all, so this is enforced by the type itself; this test just
	// documents that invariant explicitly.
}

func TestCloakedParamsUAPIRoundTripsIntoObfuscationUAPI(t *testing.T) {
	p := fullObfProfile()
	ep := netip.MustParseAddrPort("203.0.113.1:51820")
	wire := p.toWireParams(ep)
	out := cloakedParamsUAPI(wire)

	for _, want := range []string{
		"s1=15", "s2=18", "s3=20", "s4=25",
		"h1=100-200", "h2=300-400", "h3=500-600", "h4=700-800",
		"header_protection_key=",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("cloakedParamsUAPI() missing %q; full output:\n%s", want, out)
		}
	}
	// Must never leak client-side-only fields, since CloakedParams never
	// carried them to begin with.
	for _, mustNotContain := range []string{"jc=", "jmin=", "jmax=", "i1=", "content_padding_addition="} {
		if strings.Contains(out, mustNotContain) {
			t.Errorf("cloakedParamsUAPI() unexpectedly contains %q; full output:\n%s", mustNotContain, out)
		}
	}
}

func TestCloakedParamsUAPIOmitsHeaderProtectionWhenUnset(t *testing.T) {
	p := fullObfProfile()
	p.HasHeaderProtectionKey = false
	wire := p.toWireParams(netip.MustParseAddrPort("203.0.113.1:51820"))
	out := cloakedParamsUAPI(wire)
	if strings.Contains(out, "header_protection_key") {
		t.Errorf("cloakedParamsUAPI() included header_protection_key despite HasHeaderProtection=false:\n%s", out)
	}
}
