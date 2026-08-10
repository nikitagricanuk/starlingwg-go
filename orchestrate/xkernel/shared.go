// Package xkernel implements X's per-mode shared device (see
// orchestrate/xshared's doc for what that means and why there are exactly
// two, not one per Y) backed by a real kernel AmneziaWG network interface
// instead of this repo's in-process, userspace device.Device. It satisfies
// nativeflow.SharedDevice, so it drops straight into
// orchestrate.Config.NativeDataPlane/CloakedDataPlane -- every other piece
// of dual-mode orchestration (control-channel negotiation, NAT probing, the
// session state machine, persistence, events) is unchanged and unaware
// which backend is in use.
//
// Every operation shells out to the amneziawg-tools `awg` CLI rather than
// talking netlink directly: `awg` already exists on any host with
// kmod-amneziawg installed (it's kmod-amneziawg's own configuration tool),
// so this adds no new binary dependency, and its command-line surface is a
// straightforward 1:1 match for what SharedDevice needs -- confirmed
// directly against a real `awg set`/`awg show` on kernel-module hosts
// rather than assumed:
//
//	awg set <iface> private-key <file> listen-port <port> [jc <n>] [jmin <n>] [jmax <n>]
//	         [s1 <n>] [s2 <n>] [s3 <n>] [s4 <n>] [h1 <n>] [h2 <n>] [h3 <n>] [h4 <n>]
//	awg set <iface> peer <base64-pubkey> [endpoint <ip:port>] [persistent-keepalive <secs>]
//	         [allowed-ips <cidr1>,<cidr2>,...]
//	awg set <iface> peer <base64-pubkey> remove
//	awg show <iface> latest-handshakes   -- "<base64-pubkey>\t<unix-seconds>" per line
package xkernel

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
)

// Config configures one kernel-backed SharedDevice.
type Config struct {
	// Interface is the OS network interface name to create/use, e.g.
	// "awg-native0". Must be unique across both New calls on one host (one
	// SharedDevice per mode, per xshared's design).
	Interface string
	// PrivateKey/ListenPort mirror xshared.Config's fields exactly.
	PrivateKey device.NoisePrivateKey
	ListenPort uint16
	// Obfuscation profile, device-scoped exactly like the kernel module's
	// own netlink attributes (WGDEVICE_A_JC/JMIN/JMAX/S1-S4/H1-H4) -- must
	// be left entirely zero for a native-mode (unobfuscated) SharedDevice,
	// same invariant xshared.Config documents.
	Jc, Jmin, Jmax      int
	S1, S2, S3, S4      int
	H1, H2, H3, H4      int
	PersistentKeepalive time.Duration
	// AWGBinary overrides the `awg` executable path/name. Defaults to
	// "awg" (resolved via PATH) if empty.
	AWGBinary string
	// Runner overrides how commands are executed -- nil uses a real
	// os/exec.Cmd. Tests substitute a fake to exercise SharedDevice's
	// argument-building and output-parsing without a real kmod-amneziawg
	// interface or root privileges.
	Runner CommandRunner
}

// CommandRunner executes one command and returns its combined stdout,
// discarding stderr into the error on failure. Matches the one method
// SharedDevice actually needs from os/exec, kept minimal and mockable.
type CommandRunner interface {
	Run(name string, args ...string) (stdout string, err error)
}

type execRunner struct{}

func (execRunner) Run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(errBuf.String()))
	}
	return out.String(), nil
}

// SharedDevice is a nativeflow.SharedDevice backed by a real kernel
// AmneziaWG interface, configured via the `awg` CLI. Safe for concurrent
// use (serializes AddPeer/RemovePeer against each other, matching
// xshared.SharedDevice's own concurrency contract -- the kernel interface
// itself handles concurrent data-plane traffic independently).
type SharedDevice struct {
	iface     string
	awgBin    string
	run       CommandRunner
	keepalive time.Duration
	mu        sync.Mutex
}

// New creates (or recreates, if one already exists under this name -- see
// amneziawg.sh's identical `ip link del; ip link add` pattern, which this
// mirrors deliberately for consistency with the existing OpenWrt package)
// a kernel AmneziaWG interface, configures its private key/listen
// port/obfuscation profile via `awg setconf`, and brings it up. No peers
// are configured yet -- use AddPeer.
func New(cfg Config) (*SharedDevice, error) {
	if cfg.Interface == "" {
		return nil, fmt.Errorf("xkernel: Interface must not be empty")
	}
	awgBin := cfg.AWGBinary
	if awgBin == "" {
		awgBin = "awg"
	}
	run := cfg.Runner
	if run == nil {
		run = execRunner{}
	}

	s := &SharedDevice{iface: cfg.Interface, awgBin: awgBin, run: run}

	// Deliberately ignore the del error: the common case is "didn't exist
	// yet," and any other failure surfaces naturally when `ip link add`
	// below fails instead.
	_, _ = run.Run("ip", "link", "del", "dev", cfg.Interface)
	if _, err := run.Run("ip", "link", "add", "dev", cfg.Interface, "type", "amneziawg"); err != nil {
		return nil, fmt.Errorf("xkernel: create interface %s: %w", cfg.Interface, err)
	}

	keyFile, err := writeTempKey(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("xkernel: write private key: %w", err)
	}
	defer os.Remove(keyFile)

	setArgs := []string{"set", cfg.Interface, "private-key", keyFile, "listen-port", strconv.Itoa(int(cfg.ListenPort))}
	setArgs = appendIfNonZero(setArgs, "jc", cfg.Jc)
	setArgs = appendIfNonZero(setArgs, "jmin", cfg.Jmin)
	setArgs = appendIfNonZero(setArgs, "jmax", cfg.Jmax)
	setArgs = appendIfNonZero(setArgs, "s1", cfg.S1)
	setArgs = appendIfNonZero(setArgs, "s2", cfg.S2)
	setArgs = appendIfNonZero(setArgs, "s3", cfg.S3)
	setArgs = appendIfNonZero(setArgs, "s4", cfg.S4)
	setArgs = appendIfNonZero(setArgs, "h1", cfg.H1)
	setArgs = appendIfNonZero(setArgs, "h2", cfg.H2)
	setArgs = appendIfNonZero(setArgs, "h3", cfg.H3)
	setArgs = appendIfNonZero(setArgs, "h4", cfg.H4)
	if _, err := run.Run(awgBin, setArgs...); err != nil {
		run.Run("ip", "link", "del", "dev", cfg.Interface)
		return nil, fmt.Errorf("xkernel: configure interface %s: %w", cfg.Interface, err)
	}

	if _, err := run.Run("ip", "link", "set", cfg.Interface, "up"); err != nil {
		run.Run("ip", "link", "del", "dev", cfg.Interface)
		return nil, fmt.Errorf("xkernel: bring up interface %s: %w", cfg.Interface, err)
	}

	s.keepalive = cfg.PersistentKeepalive
	return s, nil
}

func appendIfNonZero(args []string, flag string, v int) []string {
	if v == 0 {
		return args
	}
	return append(args, flag, strconv.Itoa(v))
}

func writeTempKey(pk device.NoisePrivateKey) (string, error) {
	f, err := os.CreateTemp("", "xkernel-privkey-*")
	if err != nil {
		return "", err
	}
	defer f.Close()
	if err := f.Chmod(0o600); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	if _, err := f.WriteString(base64.StdEncoding.EncodeToString(pk[:])); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// AddPeer adds or reconfigures a peer, exactly matching
// xshared.SharedDevice.AddPeer's semantics and doc.
func (s *SharedDevice) AddPeer(pk device.NoisePublicKey, endpoint *netip.AddrPort, allowedIPs []netip.Prefix) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	args := []string{"set", s.iface, "peer", base64.StdEncoding.EncodeToString(pk[:])}
	if endpoint != nil {
		args = append(args, "endpoint", endpoint.String())
	}
	if s.keepalive > 0 {
		args = append(args, "persistent-keepalive", strconv.Itoa(int(s.keepalive.Seconds())))
	}
	if len(allowedIPs) > 0 {
		cidrs := make([]string, len(allowedIPs))
		for i, p := range allowedIPs {
			cidrs[i] = p.String()
		}
		args = append(args, "allowed-ips", strings.Join(cidrs, ","))
	}
	if _, err := s.run.Run(s.awgBin, args...); err != nil {
		return fmt.Errorf("xkernel: add peer %x: %w", pk[:4], err)
	}
	return nil
}

// RemovePeer removes exactly one peer. Per the isolation guarantee this
// mirrors from xshared.SharedDevice, this can never affect any other peer
// on the same interface.
func (s *SharedDevice) RemovePeer(pk device.NoisePublicKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.run.Run(s.awgBin, "set", s.iface, "peer", base64.StdEncoding.EncodeToString(pk[:]), "remove"); err != nil {
		return fmt.Errorf("xkernel: remove peer %x: %w", pk[:4], err)
	}
	return nil
}

// HandshakeTime reports the last completed handshake time for pk, and
// whether that peer is currently configured on this interface at all --
// exactly matching xshared.SharedDevice.HandshakeTime's contract (found
// but zero time means "known peer, no handshake yet").
func (s *SharedDevice) HandshakeTime(pk device.NoisePublicKey) (time.Time, bool) {
	out, err := s.run.Run(s.awgBin, "show", s.iface, "latest-handshakes")
	if err != nil {
		return time.Time{}, false
	}
	want := base64.StdEncoding.EncodeToString(pk[:])
	for _, line := range strings.Split(out, "\n") {
		key, secStr, ok := strings.Cut(line, "\t")
		if !ok || key != want {
			continue
		}
		sec, err := strconv.ParseInt(strings.TrimSpace(secStr), 10, 64)
		if err != nil || sec == 0 {
			return time.Time{}, true
		}
		return time.Unix(sec, 0), true
	}
	return time.Time{}, false
}

// Device always returns nil: there is no in-process device.Device backing
// a kernel interface. See nativeflow.SharedDevice's doc -- every call site
// that reads this is status/diagnostic only, never load-bearing.
func (s *SharedDevice) Device() *device.Device { return nil }

// Close tears down the kernel interface entirely. Matches
// xshared.SharedDevice.Close's "whole shared device going away," not a
// single peer -- do not call this for anything short of process shutdown.
func (s *SharedDevice) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.run.Run("ip", "link", "del", "dev", s.iface); err != nil {
		return fmt.Errorf("xkernel: delete interface %s: %w", s.iface, err)
	}
	return nil
}
