// Command amneziawg-dualmoded is X's process for dual-mode connectivity
// backed by a real kernel AmneziaWG interface (via orchestrate/xkernel)
// rather than this repo's in-process, userspace device.Device -- intended
// for a host that already runs kmod-amneziawg (e.g. an OpenWrt router)
// where the data plane should be the fast in-kernel one, with only the
// control-plane negotiation (Noise_IK handshake, NAT probing, mode
// decision) running here in userspace. See orchestrate/xkernel's package
// doc for why the split is drawn there and not elsewhere.
//
// This is X-only: Y's role (a NATed client dialing out) has no equivalent
// need for a resident listening process the way X's control-channel
// listener does, and is expected to be handled by a lighter-weight,
// proto-script/cron-driven mechanism instead on a platform like OpenWrt --
// see the dual-mode OpenWrt integration notes for that side.
//
// Flags mirror orchestrate/e2e/netnshelper's -role=x flag set where they
// overlap, so a UCI-to-flags translation layer (e.g. a netifd proto
// script) has one consistent shape to target across both.
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
	"github.com/amnezia-vpn/amneziawg-go/v3/orchestrate/xkernel"
)

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func mustHexKey32(s, flagName string) [32]byte {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		fmt.Fprintf(os.Stderr, "amneziawg-dualmoded: bad hex value for -%s: %q\n", flagName, s)
		os.Exit(2)
	}
	var k [32]byte
	copy(k[:], b)
	return k
}

func main() {
	privHex := flag.String("privkey", "", "local WireGuard private key, hex (required)")
	nativeIface := flag.String("native-iface", "awg-native0", "OS interface name for the shared native (unobfuscated) device")
	cloakedIface := flag.String("cloaked-iface", "awg-cloaked0", "OS interface name for the shared cloaked (obfuscated) device")
	controlListen := flag.String("control-listen", "", "control channel listen address, e.g. 0.0.0.0:41820 (required)")
	publicHost := flag.String("public-host", "", "externally-reachable host/IP Y is told to dial for cloaked mode (required)")
	probeA := flag.Int("probe-a", 0, "NAT probe port A (required)")
	probeB := flag.Int("probe-b", 0, "NAT probe port B (required)")
	nativePort := flag.Int("native-port", 0, "shared native device listen port (required)")
	cloakedPort := flag.Int("cloaked-port", 0, "shared cloaked device listen port (required)")
	awgBin := flag.String("awg-bin", "awg", "path to the awg CLI (amneziawg-tools)")
	verbose := flag.Bool("verbose", false, "verbose logging (default: errors only, appropriate for long-running production use)")

	jc := flag.Int("jc", 0, "cloaked device: Jc")
	jmin := flag.Int("jmin", 0, "cloaked device: Jmin")
	jmax := flag.Int("jmax", 0, "cloaked device: Jmax")
	s1 := flag.Int("s1", 0, "cloaked device: S1")
	s2 := flag.Int("s2", 0, "cloaked device: S2")
	s3 := flag.Int("s3", 0, "cloaked device: S3")
	s4 := flag.Int("s4", 0, "cloaked device: S4")
	h1 := flag.Int("h1", 0, "cloaked device: H1")
	h2 := flag.Int("h2", 0, "cloaked device: H2")
	h3 := flag.Int("h3", 0, "cloaked device: H3")
	h4 := flag.Int("h4", 0, "cloaked device: H4")

	nativeTimeout := flag.Duration("native-timeout", 10*time.Second, "native handshake timeout")
	cloakedTimeout := flag.Duration("cloaked-timeout", 10*time.Second, "cloaked handshake timeout")

	var peers stringList
	flag.Var(&peers, "peer", "authorized Y: \"pubkeyhex=cidr1,cidr2\" (repeatable, at least one required)")

	flag.Parse()

	if *privHex == "" || *controlListen == "" || *publicHost == "" || *probeA == 0 || *probeB == 0 ||
		*nativePort == 0 || *cloakedPort == 0 || len(peers) == 0 {
		fmt.Fprintln(os.Stderr, "amneziawg-dualmoded: -privkey, -control-listen, -public-host, -probe-a, -probe-b, -native-port, -cloaked-port, and at least one -peer are required")
		os.Exit(2)
	}

	logLevel := device.LogLevelError
	if *verbose {
		logLevel = device.LogLevelVerbose
	}
	logger := device.NewLogger(logLevel, "")

	priv := device.NoisePrivateKey(mustHexKey32(*privHex, "privkey"))

	var authorized []orchestrate.PeerAuthorization
	for _, spec := range peers {
		pkHex, cidrs, ok := strings.Cut(spec, "=")
		if !ok || pkHex == "" || cidrs == "" {
			fmt.Fprintf(os.Stderr, "amneziawg-dualmoded: bad -peer %q, want pubkeyhex=cidr1,cidr2\n", spec)
			os.Exit(2)
		}
		authorized = append(authorized, orchestrate.PeerAuthorization{
			PublicKey:  device.NoisePublicKey(mustHexKey32(pkHex, "peer")),
			AllowedIPs: strings.Split(cidrs, ","),
		})
	}

	nativeDev, err := xkernel.New(xkernel.Config{
		Interface:  *nativeIface,
		PrivateKey: priv,
		ListenPort: uint16(*nativePort),
		// PersistentKeepalive required here for the same reason
		// xshared's does it: without it, a freshly added peer with
		// endpoint= set never actually dials out until some other
		// trigger fires.
		PersistentKeepalive: time.Second,
		AWGBinary:           *awgBin,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "amneziawg-dualmoded: bring up native interface %s: %v\n", *nativeIface, err)
		os.Exit(1)
	}

	cloakedDev, err := xkernel.New(xkernel.Config{
		Interface:  *cloakedIface,
		PrivateKey: priv,
		ListenPort: uint16(*cloakedPort),
		Jc:         *jc, Jmin: *jmin, Jmax: *jmax,
		S1: *s1, S2: *s2, S3: *s3, S4: *s4,
		H1: *h1, H2: *h2, H3: *h3, H4: *h4,
		AWGBinary: *awgBin,
	})
	if err != nil {
		nativeDev.Close()
		fmt.Fprintf(os.Stderr, "amneziawg-dualmoded: bring up cloaked interface %s: %v\n", *cloakedIface, err)
		os.Exit(1)
	}

	// LocalPublicKey is derived, not separately supplied -- avoids a
	// second copy of the same key material a caller could get out of sync
	// with -privkey.
	var pub device.NoisePublicKey
	curve25519.ScalarBaseMult((*[32]byte)(&pub), (*[32]byte)(&priv))

	cfg := orchestrate.Config{
		Role:                    orchestrate.RoleX,
		LocalPrivateKey:         priv,
		LocalPublicKey:          pub,
		ControlListenAddr:       *controlListen,
		PublicHost:              *publicHost,
		ProbePortA:              uint16(*probeA),
		ProbePortB:              uint16(*probeB),
		NativeListenPort:        uint16(*nativePort),
		CloakedListenPort:       uint16(*cloakedPort),
		AuthorizedPeers:         authorized,
		NativeDataPlane:         nativeDev,
		CloakedDataPlane:        cloakedDev,
		NativeInterfaceName:     *nativeIface,
		CloakedInterfaceName:    *cloakedIface,
		NativeHandshakeTimeout:  *nativeTimeout,
		CloakedHandshakeTimeout: *cloakedTimeout,
		Logger:                  logger,
	}

	o, err := orchestrate.NewOrchestrator(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "amneziawg-dualmoded: NewOrchestrator: %v\n", err)
		os.Exit(1)
	}
	if err := o.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "amneziawg-dualmoded: Start: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("amneziawg-dualmoded: listening on %s (native=%s cloaked=%s), %d authorized peer(s)\n",
		*controlListen, *nativeIface, *cloakedIface, len(authorized))

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	o.Stop()
}
