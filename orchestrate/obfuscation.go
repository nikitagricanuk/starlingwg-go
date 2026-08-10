package orchestrate

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"

	"github.com/amnezia-vpn/amneziawg-go/v3/orchestrate/control"
)

func rangeString(lo, hi uint32) string {
	if lo == hi {
		return fmt.Sprintf("%d", lo)
	}
	return fmt.Sprintf("%d-%d", lo, hi)
}

// uapi renders X's full obfuscation profile -- including the client-side
// knobs (jc/jmin/jmax/i1-i5/timings/content-padding) that X applies to its
// own shared cloaked Device but never needs to send to Y -- as UAPI
// device-config lines.
func (p ObfuscationProfile) uapi() string {
	var b strings.Builder
	if p.Jc != 0 {
		fmt.Fprintf(&b, "jc=%d\n", p.Jc)
	}
	if p.Jmin != 0 {
		fmt.Fprintf(&b, "jmin=%d\n", p.Jmin)
	}
	if p.Jmax != 0 {
		fmt.Fprintf(&b, "jmax=%d\n", p.Jmax)
	}
	if p.S1 != 0 {
		fmt.Fprintf(&b, "s1=%d\n", p.S1)
	}
	if p.S2 != 0 {
		fmt.Fprintf(&b, "s2=%d\n", p.S2)
	}
	if p.S3 != 0 {
		fmt.Fprintf(&b, "s3=%d\n", p.S3)
	}
	if p.S4 != 0 {
		fmt.Fprintf(&b, "s4=%d\n", p.S4)
	}
	if p.H1Hi != 0 {
		fmt.Fprintf(&b, "h1=%s\n", rangeString(p.H1Lo, p.H1Hi))
	}
	if p.H2Hi != 0 {
		fmt.Fprintf(&b, "h2=%s\n", rangeString(p.H2Lo, p.H2Hi))
	}
	if p.H3Hi != 0 {
		fmt.Fprintf(&b, "h3=%s\n", rangeString(p.H3Lo, p.H3Hi))
	}
	if p.H4Hi != 0 {
		fmt.Fprintf(&b, "h4=%s\n", rangeString(p.H4Lo, p.H4Hi))
	}
	if p.HasHeaderProtectionKey {
		fmt.Fprintf(&b, "header_protection_key=%s\n", hex.EncodeToString(p.HeaderProtectionKey[:]))
	}
	for i, spec := range []string{p.I1, p.I2, p.I3, p.I4, p.I5} {
		if spec != "" {
			fmt.Fprintf(&b, "i%d=%s\n", i+1, spec)
		}
	}
	if p.ContentPaddingAdditionHi != 0 {
		fmt.Fprintf(&b, "content_padding_addition=%s\n", rangeString(p.ContentPaddingAdditionLo, p.ContentPaddingAdditionHi))
	}
	return b.String()
}

// toWireParams extracts only the fields that must match byte-for-byte
// between X and Y -- S1-S4, H1-H4, HeaderProtectionKey, the "server-side"
// params per device/receive.go's DeterminePacketTypeAndPadding, which fails
// closed on any mismatch -- plus where Y should connect. Jc/Jmin/Jmax/
// I1-I5/timings/content-padding are deliberately never sent: they're
// local-only, and Y is free to configure its own independently.
func (p ObfuscationProfile) toWireParams(listenEndpoint netip.AddrPort) control.CloakedParams {
	return control.CloakedParams{
		S1: p.S1, S2: p.S2, S3: p.S3, S4: p.S4,
		H1Lo: p.H1Lo, H1Hi: p.H1Hi,
		H2Lo: p.H2Lo, H2Hi: p.H2Hi,
		H3Lo: p.H3Lo, H3Hi: p.H3Hi,
		H4Lo: p.H4Lo, H4Hi: p.H4Hi,
		HasHeaderProtection: p.HasHeaderProtectionKey,
		HeaderProtectionKey: p.HeaderProtectionKey,
		ListenEndpoint:      listenEndpoint,
	}
}

// cloakedParamsUAPI renders a received CloakedParams message as the UAPI
// device-config lines Y's own Device needs, to match X exactly on every
// field that must match.
func cloakedParamsUAPI(m control.CloakedParams) string {
	var b strings.Builder
	if m.S1 != 0 {
		fmt.Fprintf(&b, "s1=%d\n", m.S1)
	}
	if m.S2 != 0 {
		fmt.Fprintf(&b, "s2=%d\n", m.S2)
	}
	if m.S3 != 0 {
		fmt.Fprintf(&b, "s3=%d\n", m.S3)
	}
	if m.S4 != 0 {
		fmt.Fprintf(&b, "s4=%d\n", m.S4)
	}
	if m.H1Hi != 0 {
		fmt.Fprintf(&b, "h1=%s\n", rangeString(m.H1Lo, m.H1Hi))
	}
	if m.H2Hi != 0 {
		fmt.Fprintf(&b, "h2=%s\n", rangeString(m.H2Lo, m.H2Hi))
	}
	if m.H3Hi != 0 {
		fmt.Fprintf(&b, "h3=%s\n", rangeString(m.H3Lo, m.H3Hi))
	}
	if m.H4Hi != 0 {
		fmt.Fprintf(&b, "h4=%s\n", rangeString(m.H4Lo, m.H4Hi))
	}
	if m.HasHeaderProtection {
		fmt.Fprintf(&b, "header_protection_key=%s\n", hex.EncodeToString(m.HeaderProtectionKey[:]))
	}
	return b.String()
}
