package xkernel

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
)

// fakeRunner records every command it's asked to run and returns
// pre-programmed output/errors, so these tests exercise SharedDevice's
// argument-building and output-parsing without a real kmod-amneziawg
// interface, root privileges, or the `awg` binary at all.
type fakeRunner struct {
	calls   [][]string
	outputs map[string]string // joined command -> stdout to return
	errors  map[string]error  // joined command -> error to return
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{outputs: map[string]string{}, errors: map[string]error{}}
}

func (f *fakeRunner) Run(name string, args ...string) (string, error) {
	call := append([]string{name}, args...)
	f.calls = append(f.calls, call)
	key := strings.Join(call, " ")
	if err, ok := f.errors[key]; ok {
		return "", err
	}
	return f.outputs[key], nil
}

func (f *fakeRunner) lastCall() []string {
	if len(f.calls) == 0 {
		return nil
	}
	return f.calls[len(f.calls)-1]
}

func (f *fakeRunner) callsContaining(substr string) [][]string {
	var out [][]string
	for _, c := range f.calls {
		if strings.Contains(strings.Join(c, " "), substr) {
			out = append(out, c)
		}
	}
	return out
}

func genKey(t *testing.T) device.NoisePublicKey {
	t.Helper()
	var pk device.NoisePublicKey
	if _, err := rand.Read(pk[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return pk
}

func TestNewCreatesAndConfiguresInterface(t *testing.T) {
	run := newFakeRunner()
	dev, err := New(Config{
		Interface:  "awg-test0",
		ListenPort: 41823,
		Runner:     run,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() {
		run.errors = map[string]error{} // let Close succeed cleanly
		dev.Close()
	}()

	addCalls := run.callsContaining("ip link add dev awg-test0 type amneziawg")
	if len(addCalls) != 1 {
		t.Fatalf("expected exactly one `ip link add`, got %d: %v", len(addCalls), run.calls)
	}

	setCalls := run.callsContaining("awg set awg-test0 private-key")
	if len(setCalls) != 1 {
		t.Fatalf("expected exactly one `awg set ... private-key`, got %d: %v", len(setCalls), run.calls)
	}
	if !strings.Contains(strings.Join(setCalls[0], " "), "listen-port 41823") {
		t.Fatalf("expected listen-port 41823 in %v", setCalls[0])
	}
	// Native mode: no obfuscation flags configured, none should appear.
	for _, flag := range []string{"jc", "jmin", "jmax", "s1", "h1"} {
		for _, arg := range setCalls[0] {
			if arg == flag {
				t.Fatalf("unexpected obfuscation flag %q in native-mode set call: %v", flag, setCalls[0])
			}
		}
	}

	upCalls := run.callsContaining("ip link set awg-test0 up")
	if len(upCalls) != 1 {
		t.Fatalf("expected exactly one `ip link set ... up`, got %d: %v", len(upCalls), run.calls)
	}
}

func TestNewAppliesObfuscationProfile(t *testing.T) {
	run := newFakeRunner()
	dev, err := New(Config{
		Interface:  "awg-cloaked0",
		ListenPort: 41824,
		Jc:         5, Jmin: 50, Jmax: 1000,
		S1: 10, S2: 20, S3: 30, S4: 40,
		H1: 111, H2: 222, H3: 333, H4: 444,
		Runner: run,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { run.errors = map[string]error{}; dev.Close() }()

	setCalls := run.callsContaining("private-key")
	if len(setCalls) != 1 {
		t.Fatalf("expected one configure call, got %d", len(setCalls))
	}
	got := strings.Join(setCalls[0], " ")
	for _, want := range []string{
		"jc 5", "jmin 50", "jmax 1000",
		"s1 10", "s2 20", "s3 30", "s4 40",
		"h1 111", "h2 222", "h3 333", "h4 444",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected %q in configure call, got: %s", want, got)
		}
	}
}

func TestNewFailureCleansUpInterface(t *testing.T) {
	run := newFakeRunner()
	run.errors["ip link set awg-test0 up"] = fmt.Errorf("boom")
	_, err := New(Config{Interface: "awg-test0", Runner: run})
	if err == nil {
		t.Fatalf("expected New to fail")
	}
	delCalls := run.callsContaining("ip link del dev awg-test0")
	if len(delCalls) == 0 {
		t.Fatalf("expected a cleanup `ip link del` after New failed, got calls: %v", run.calls)
	}
}

func TestAddPeerBuildsExpectedCommand(t *testing.T) {
	run := newFakeRunner()
	dev, err := New(Config{Interface: "awg-test0", PersistentKeepalive: 15 * time.Second, Runner: run})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pk := genKey(t)
	ep := netip.MustParseAddrPort("203.0.113.5:41823")
	prefixes := []netip.Prefix{netip.MustParsePrefix("10.10.0.7/32")}

	if err := dev.AddPeer(pk, &ep, prefixes); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	call := run.lastCall()
	got := strings.Join(call, " ")
	wantPeer := base64.StdEncoding.EncodeToString(pk[:])
	for _, want := range []string{
		"awg set awg-test0 peer " + wantPeer,
		"endpoint 203.0.113.5:41823",
		"persistent-keepalive 15",
		"allowed-ips 10.10.0.7/32",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected %q in AddPeer command, got: %s", want, got)
		}
	}
}

func TestAddPeerWithoutEndpointOmitsEndpointFlag(t *testing.T) {
	// Cloaked mode: X waits passively, never dials, so endpoint must be nil
	// -- confirm that translates to no "endpoint" flag at all, not an
	// empty/zero one (a real omitted-vs-empty distinction the CLI cares
	// about).
	run := newFakeRunner()
	dev, err := New(Config{Interface: "awg-test0", Runner: run})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pk := genKey(t)
	if err := dev.AddPeer(pk, nil, []netip.Prefix{netip.MustParsePrefix("10.10.0.7/32")}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	got := strings.Join(run.lastCall(), " ")
	if strings.Contains(got, "endpoint") {
		t.Fatalf("expected no endpoint flag for a nil endpoint, got: %s", got)
	}
}

func TestRemovePeerBuildsExpectedCommand(t *testing.T) {
	run := newFakeRunner()
	dev, err := New(Config{Interface: "awg-test0", Runner: run})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pk := genKey(t)
	if err := dev.RemovePeer(pk); err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}
	got := strings.Join(run.lastCall(), " ")
	wantPeer := base64.StdEncoding.EncodeToString(pk[:])
	if !strings.Contains(got, "awg set awg-test0 peer "+wantPeer+" remove") {
		t.Fatalf("unexpected RemovePeer command: %s", got)
	}
}

func TestHandshakeTimeParsesRealAwgShowFormat(t *testing.T) {
	run := newFakeRunner()
	dev, err := New(Config{Interface: "awg-test0", Runner: run})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pkFound := genKey(t)
	pkZero := genKey(t)
	pkAbsent := genKey(t)

	// Exact tab-separated format confirmed live against a real
	// kmod-amneziawg host's `awg show <iface> latest-handshakes` output.
	run.outputs["awg show awg-test0 latest-handshakes"] = fmt.Sprintf(
		"%s\t1786348505\n%s\t0\n",
		base64.StdEncoding.EncodeToString(pkFound[:]),
		base64.StdEncoding.EncodeToString(pkZero[:]),
	)

	if tm, found := dev.HandshakeTime(pkFound); !found || tm.Unix() != 1786348505 {
		t.Fatalf("HandshakeTime(pkFound) = %v, %v; want 1786348505, true", tm, found)
	}
	if tm, found := dev.HandshakeTime(pkZero); !found || !tm.IsZero() {
		t.Fatalf("HandshakeTime(pkZero) = %v, %v; want zero time, true", tm, found)
	}
	if _, found := dev.HandshakeTime(pkAbsent); found {
		t.Fatalf("HandshakeTime(pkAbsent) reported found=true, want false")
	}
}

func TestDeviceReturnsNil(t *testing.T) {
	run := newFakeRunner()
	dev, err := New(Config{Interface: "awg-test0", Runner: run})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if dev.Device() != nil {
		t.Fatalf("expected Device() to return nil for a kernel-backed SharedDevice")
	}
}

func TestCloseDeletesInterface(t *testing.T) {
	run := newFakeRunner()
	dev, err := New(Config{Interface: "awg-test0", Runner: run})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := dev.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	delCalls := run.callsContaining("ip link del dev awg-test0")
	// New() also does a preemptive delete before add; Close() must add one
	// more on top of that.
	if len(delCalls) != 2 {
		t.Fatalf("expected 2 total `ip link del` calls (New's preemptive one + Close's), got %d: %v", len(delCalls), run.calls)
	}
}
