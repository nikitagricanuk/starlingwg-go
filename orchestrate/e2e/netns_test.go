//go:build linux

// This file drives the real-NAT e2e harness (testdata/netns_setup.sh):
// network namespaces + iptables MASQUERADE, reusing the same idioms as the
// existing tests/netns.sh rather than Docker -- dependency-free, matches
// existing project convention, gives precise real-kernel-NAT control that
// the in-process tests (inprocess_test.go) structurally cannot, since
// loopback has no real NAT in the way.
//
// Opt-in and root-gated: needs CAP_NET_ADMIN to create network namespaces
// and manipulate iptables, so it's skipped unless AWG_NETNS_E2E=1 is set,
// e.g.:
//
//	sudo AWG_NETNS_E2E=1 go test -tags netnstest ./orchestrate/e2e/... -run TestNetnsRealNAT -v
//
// Also requires a `-tags netnstest` build tag on top of the linux build
// constraint above, so it never runs as part of a plain `go test ./...`.
package e2e_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func buildNetnsHelper(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "netnshelper")
	cmd := exec.Command("go", "build", "-o", bin, "github.com/amnezia-vpn/amneziawg-go/v3/orchestrate/e2e/netnshelper")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build netnshelper: %v\n%s", err, out)
	}
	return bin
}

func runNetnsScenario(t *testing.T, natMode string) {
	if os.Getenv("AWG_NETNS_E2E") != "1" {
		t.Skip("set AWG_NETNS_E2E=1 (and run as root) to run the real-NAT netns e2e harness")
	}
	if os.Geteuid() != 0 {
		t.Skip("netns e2e harness requires root (CAP_NET_ADMIN)")
	}

	bin := buildNetnsHelper(t)
	script := filepath.Join("testdata", "netns_setup.sh")

	cmd := exec.Command("bash", script, bin, natMode)
	out, err := cmd.CombinedOutput()
	t.Logf("netns_setup.sh %s output:\n%s", natMode, out)
	if err != nil {
		t.Fatalf("netns_setup.sh %s failed: %v", natMode, err)
	}
}

// TestNetnsRealNATConeSucceeds validates native-mode establishment against
// genuine kernel NAT behavior that looks cone-type from Y's perspective
// (deterministic MASQUERADE, address/port-independent mapping): X should
// successfully dial Y once it reports its punched address, and real ping
// traffic should flow both directions.
func TestNetnsRealNATConeSucceeds(t *testing.T) {
	runNetnsScenario(t, "cone")
}

// TestNetnsRealNATSymmetricSkipsNative validates that Y's characterization
// correctly detects a symmetric-type NAT (randomized per-flow MASQUERADE
// port mapping) and does not attempt native mode at all, rather than
// wasting a punch attempt that's known to fail (requirement #2).
func TestNetnsRealNATSymmetricSkipsNative(t *testing.T) {
	runNetnsScenario(t, "symmetric")
}
