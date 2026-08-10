// Command netnshelper is a tiny driver around orchestrate.Orchestrator,
// built for the netns-based real-NAT e2e test (orchestrate/e2e/netns_test.go
// + testdata/netns_setup.sh). It is not part of the public library surface
// -- it exists purely so the shell harness can launch "X" or "Y" as a real
// process inside a real network namespace, with a real OS TUN interface,
// so genuine kernel NAT rules (iptables) actually apply to its traffic.
// This is the same relationship main.go/main_windows.go have to the
// device package: a thin process wrapper around library calls.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/orchestrate"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func mustHexKey(s string) [32]byte {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		fmt.Fprintf(os.Stderr, "netnshelper: bad hex key %q: %v\n", s, err)
		os.Exit(2)
	}
	var k [32]byte
	copy(k[:], b)
	return k
}

func main() {
	if len(os.Args) == 3 && os.Args[1] == "-derive-pubkey" {
		// A tiny side-mode so the shell harness can derive both sides'
		// public keys using this same already-built binary, instead of
		// depending on `wg genkey`/`wg pubkey` being installed or on a
		// separate `go run` invocation resolving module dependencies on
		// its own (fragile in a sandboxed/offline CI environment).
		priv := mustHexKey(os.Args[2])
		var pub [32]byte
		curve25519.ScalarBaseMult(&pub, &priv)
		fmt.Print(hex.EncodeToString(pub[:]))
		return
	}

	role := flag.String("role", "", "x or y")
	ifname := flag.String("tun", "", "TUN interface name to create")
	cloakedIfname := flag.String("cloaked-tun", "", "X only: second TUN interface name, for the shared cloaked Device")
	mtu := flag.Int("mtu", 1420, "TUN MTU")
	privHex := flag.String("privkey", "", "local WireGuard private key, hex")
	peerHex := flag.String("peerkey", "", "remote peer's WireGuard public key, hex")
	controlListen := flag.String("control-listen", "", "X only: control channel listen address")
	publicHost := flag.String("public-host", "", "X only: externally-reachable host/IP Y is told to dial for cloaked mode")
	controlAddr := flag.String("control-addr", "", "Y only: X's control channel address")
	probeA := flag.Int("probe-a", 0, "X only: NAT probe port A")
	probeB := flag.Int("probe-b", 0, "X only: NAT probe port B")
	nativePort := flag.Int("native-port", 0, "X only: shared native Device listen port")
	cloakedPort := flag.Int("cloaked-port", 0, "X only: shared cloaked Device listen port")
	var allowedIPs stringList
	flag.Var(&allowedIPs, "allowed-ip", "AllowedIPs CIDR (repeatable)")
	var extraXPeers stringList
	flag.Var(&extraXPeers, "x-extra-peer", "X only: additional authorized peer, \"pubkeyhex=cidr1,cidr2\" (repeatable), on top of -peerkey/-allowed-ip")
	timeout := flag.Duration("native-timeout", 10*time.Second, "native handshake timeout")
	cloakedTimeout := flag.Duration("cloaked-timeout", 10*time.Second, "cloaked handshake timeout")
	flag.Parse()

	if *ifname == "" || *privHex == "" || *peerHex == "" {
		fmt.Fprintln(os.Stderr, "netnshelper: -tun, -privkey, -peerkey are required")
		os.Exit(2)
	}

	tunDev, err := tun.CreateTUN(*ifname, *mtu)
	if err != nil {
		fmt.Fprintf(os.Stderr, "netnshelper: CreateTUN(%s): %v\n", *ifname, err)
		os.Exit(1)
	}

	logger := device.NewLogger(device.LogLevelVerbose, fmt.Sprintf("[%s] ", *ifname))
	priv := mustHexKey(*privHex)
	peer := mustHexKey(*peerHex)

	cfg := orchestrate.Config{
		LocalPrivateKey:         device.NoisePrivateKey(priv),
		NativeHandshakeTimeout:  *timeout,
		CloakedHandshakeTimeout: *cloakedTimeout,
		Logger:                  logger,
	}

	switch *role {
	case "x":
		if *controlListen == "" || *publicHost == "" || *probeA == 0 || *probeB == 0 || *nativePort == 0 || *cloakedPort == 0 || *cloakedIfname == "" {
			fmt.Fprintln(os.Stderr, "netnshelper: role=x requires -control-listen, -public-host, -probe-a, -probe-b, -native-port, -cloaked-port, -cloaked-tun")
			os.Exit(2)
		}
		cloakedTUN, err := tun.CreateTUN(*cloakedIfname, *mtu)
		if err != nil {
			fmt.Fprintf(os.Stderr, "netnshelper: CreateTUN(%s): %v\n", *cloakedIfname, err)
			os.Exit(1)
		}
		cfg.Role = orchestrate.RoleX
		cfg.ControlListenAddr = *controlListen
		cfg.PublicHost = *publicHost
		cfg.ProbePortA = uint16(*probeA)
		cfg.ProbePortB = uint16(*probeB)
		cfg.NativeListenPort = uint16(*nativePort)
		cfg.CloakedListenPort = uint16(*cloakedPort)
		cfg.NativeTUN = tunDev
		cfg.CloakedTUN = cloakedTUN
		cfg.AuthorizedPeers = []orchestrate.PeerAuthorization{
			{PublicKey: device.NoisePublicKey(peer), AllowedIPs: allowedIPs},
		}
		for _, spec := range extraXPeers {
			pk, cidrs, ok := strings.Cut(spec, "=")
			if !ok || pk == "" || cidrs == "" {
				fmt.Fprintf(os.Stderr, "netnshelper: bad -x-extra-peer %q, want pubkeyhex=cidr1,cidr2\n", spec)
				os.Exit(2)
			}
			cfg.AuthorizedPeers = append(cfg.AuthorizedPeers, orchestrate.PeerAuthorization{
				PublicKey:  device.NoisePublicKey(mustHexKey(pk)),
				AllowedIPs: strings.Split(cidrs, ","),
			})
		}
	case "y":
		if *controlAddr == "" {
			fmt.Fprintln(os.Stderr, "netnshelper: role=y requires -control-addr")
			os.Exit(2)
		}
		cfg.Role = orchestrate.RoleY
		cfg.YTUN = tunDev
		cfg.Peers = []orchestrate.PeerConfig{
			{RemotePublicKey: device.NoisePublicKey(peer), ControlAddr: *controlAddr, AllowedIPs: allowedIPs},
		}
	default:
		fmt.Fprintln(os.Stderr, "netnshelper: -role must be x or y")
		os.Exit(2)
	}

	o, err := orchestrate.NewOrchestrator(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "netnshelper: NewOrchestrator: %v\n", err)
		os.Exit(1)
	}

	if err := o.Start(); err != nil {
		// On Y, Start() only returns once every configured peer's
		// session has finished (succeeded or failed) -- so a non-nil
		// error here means native mode genuinely did not work out for
		// this run, which the calling test case needs to know about via
		// the process exit code.
		fmt.Fprintf(os.Stderr, "netnshelper: Start: %v\n", err)
		os.Exit(1)
	}

	var diagSession *orchestrate.Session
	if *role == "y" {
		for _, pc := range cfg.Peers {
			st, reason := o.Session(pc.ControlAddr).State()
			fmt.Printf("STATE=%s REASON=%q\n", st, reason)
			diagSession = o.Session(pc.ControlAddr)
		}
	}
	fmt.Println("READY")

	if diagSession != nil {
		go func() {
			for range time.Tick(3 * time.Second) {
				if dev := diagSession.Device(); dev != nil {
					out, _ := dev.IpcGet()
					fmt.Fprintf(os.Stderr, "DIAG IpcGet:\n%s\n", out)
				}
			}
		}()
	}
	if *role == "x" {
		go func() {
			for range time.Tick(3 * time.Second) {
				for _, p := range cfg.AuthorizedPeers {
					key := fmt.Sprintf("%x", p.PublicKey[:])
					sess := o.Session(key)
					if sess == nil {
						continue
					}
					st, reason := sess.State()
					fmt.Fprintf(os.Stderr, "DIAG X session %s: state=%s reason=%q\n", key[:8], st, reason)
					if dev := sess.Device(); dev != nil {
						out, _ := dev.IpcGet()
						fmt.Fprintf(os.Stderr, "DIAG X IpcGet:\n%s\n", out)
					}
				}
			}
		}()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	o.Stop()
}
