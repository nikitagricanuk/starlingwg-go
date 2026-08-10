// Package natprobe implements requirement #2's NAT characterization: before
// attempting native mode, Y determines whether it's behind a cone-type NAT
// (native mode viable) or a symmetric-type NAT (native mode is hopeless,
// skip straight to cloaked) -- without depending on any third-party STUN
// service. X self-hosts the two distinguishable reflector endpoints Y needs
// to probe against.
package natprobe

import "net/netip"

// Class is the result of NAT characterization.
type Class int

const (
	// Unknown means characterization did not complete (e.g. both probes
	// timed out) -- treated the same as Symmetric by callers: native mode
	// is not attempted when the outcome is uncertain.
	Unknown Class = iota
	// Cone means X observed the same external (ip, port) mapping for Y
	// regardless of which of X's two probe endpoints was contacted --
	// address/port-independent mapping, native mode is viable.
	Cone
	// Symmetric means X observed different external mappings per
	// destination -- native mode cannot work, since X can't predict what
	// mapping Y will get toward its real data endpoint.
	Symmetric
)

func (c Class) String() string {
	switch c {
	case Cone:
		return "cone"
	case Symmetric:
		return "symmetric"
	default:
		return "unknown"
	}
}

// Result is the outcome of running Characterize.
type Result struct {
	Class Class
	// ExternalAddr is Y's externally-visible (ip, port) mapping, valid
	// only when Class == Cone (it's the address native mode should punch
	// toward and report to X).
	ExternalAddr netip.AddrPort
}
