#!/bin/bash
#
# Real-NAT e2e harness for orchestrate's native-mode establishment,
# modeled directly on the existing tests/netns.sh idioms in this repo
# (same ip-netns/veth/iptables/pretty-logging/cleanup-trap conventions),
# just driving the netnshelper binary (which wraps orchestrate.Orchestrator)
# instead of the raw wg/amneziawg-go CLI.
#
# Topology:
#
#   ┌────────────┐   ┌──────────────────────────┐   ┌────────────┐
#   │  $nsX      │   │        $nsRouter          │   │  $nsY      │
#   │ (public)   │   │   (does NAT, cone or      │   │ (private,  │
#   │            │───│    symmetric per NAT_MODE)│───│  behind    │
#   │ 10.0.0.1   │   │ 10.0.0.2  |  192.168.1.1  │   │  NAT)      │
#   └────────────┘   └──────────────────────────┘   │192.168.1.2 │
#                                                     └────────────┘
#
# Usage: netns_setup.sh <path-to-netnshelper-binary> <cone|symmetric>
#
# Requires root and Linux (ip netns, iptables). Exits non-zero on any
# failure; on success, X reaches ConnectedNative for the "cone" case and
# fails over to inconclusive/no-native for the "symmetric" case (cloaked
# fallback itself isn't exercised here yet -- this harness only validates
# NAT characterization + native establishment against real kernel NAT,
# matching the plan's phase-3 scope).

set -e

exec 3>&1
program="$1"
nat_mode="${2:-cone}"
[[ -n $program && -x $program ]] || { echo "usage: $0 <netnshelper-binary> <cone|symmetric>" >&2; exit 2; }

nsX="awg-e2e-$$-x"
nsRouter="awg-e2e-$$-r"
nsY="awg-e2e-$$-y"

pretty() { echo -e "\x1b[32m\x1b[1m[+] ${1:+NS$1: }${2}\x1b[0m" >&3; }
pp() { pretty "" "$*"; "$@"; }
nX() { pretty X "$*"; ip netns exec "$nsX" "$@"; }
nR() { pretty R "$*"; ip netns exec "$nsRouter" "$@"; }
nY() { pretty Y "$*"; ip netns exec "$nsY" "$@"; }
ipX() { pretty X "ip $*"; ip -n "$nsX" "$@"; }
ipR() { pretty R "ip $*"; ip -n "$nsRouter" "$@"; }
ipY() { pretty Y "ip $*"; ip -n "$nsY" "$@"; }
waitiface() { pretty "" "wait for $2 to come up in $1"; ip netns exec "$1" bash -c "while [[ \$(< \"/sys/class/net/$2/operstate\") != up ]]; do read -t .1 -N 0 || true; done;"; }

pids=()
cleanup() {
    set +e
    exec 2>/dev/null
    for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null; done
    sleep 0.3
    local to_kill="$(ip netns pids "$nsX" 2>/dev/null) $(ip netns pids "$nsRouter" 2>/dev/null) $(ip netns pids "$nsY" 2>/dev/null)"
    [[ -n $to_kill ]] && kill $to_kill 2>/dev/null
    ip netns del "$nsX" 2>/dev/null
    ip netns del "$nsRouter" 2>/dev/null
    ip netns del "$nsY" 2>/dev/null
    exit
}
trap cleanup EXIT

ip netns del "$nsX" 2>/dev/null || true
ip netns del "$nsRouter" 2>/dev/null || true
ip netns del "$nsY" 2>/dev/null || true
pp ip netns add "$nsX"
pp ip netns add "$nsRouter"
pp ip netns add "$nsY"
ipX link set up dev lo
ipR link set up dev lo
ipY link set up dev lo

# X <-> Router (the "public" link)
ipR link add vethXpub type veth peer name vethXside
ipR link set vethXside netns "$nsX"
ipR addr add 10.0.0.1/24 dev vethXpub
ipX addr add 10.0.0.2/24 dev vethXside
ipR link set vethXpub up
ipX link set vethXside up
waitiface "$nsRouter" vethXpub
waitiface "$nsX" vethXside

# Router <-> Y (the "private" link, behind NAT)
ipR link add vethYpub type veth peer name vethYside
ipR link set vethYside netns "$nsY"
ipR addr add 192.168.1.1/24 dev vethYpub
ipY addr add 192.168.1.2/24 dev vethYside
ipR link set vethYpub up
ipY link set vethYside up
waitiface "$nsRouter" vethYpub
waitiface "$nsY" vethYside

ipY route add default via 192.168.1.1

nR bash -c 'printf 1 > /proc/sys/net/ipv4/ip_forward'

case "$nat_mode" in
cone)
    # Address/port-independent mapping for the life of the flow -- the
    # deterministic MASQUERADE default -- approximates a cone-type NAT:
    # native mode should succeed.
    nR iptables -t nat -A POSTROUTING -s 192.168.1.0/24 -o vethXpub -j MASQUERADE
    ;;
symmetric)
    # --random forces a fresh external port per new connection (i.e. per
    # destination port here, since Y's two probes and its real native
    # traffic each open distinct conntrack entries), approximating a
    # symmetric NAT: characterization should detect this and native mode
    # must not be attempted.
    nR iptables -t nat -A POSTROUTING -s 192.168.1.0/24 -o vethXpub -j MASQUERADE --random
    ;;
*)
    echo "unknown NAT mode: $nat_mode" >&2
    exit 2
    ;;
esac

# --- Generate keys: raw 32-byte hex via /dev/urandom, no dependency on
# wg(8) being installed. Public keys are derived using the same
# already-built netnshelper binary's -derive-pubkey side-mode, avoiding a
# separate `go run`/module-dependency-resolution step that could fail
# offline.
genkey() { head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
xkey="$(genkey)"
ykey="$(genkey)"
xpub="$("$program" -derive-pubkey "$xkey")"
ypub="$("$program" -derive-pubkey "$ykey")"
[[ -n $xpub && -n $ypub ]]

# --- Launch X in nsX ---
nX env LOG_LEVEL=verbose "$program" \
    -role=x -tun=awg-x -cloaked-tun=awg-xc -mtu=1420 \
    -privkey="$xkey" -peerkey="$ypub" \
    -control-listen=0.0.0.0:41820 -public-host=10.0.0.2 \
    -probe-a=41821 -probe-b=41822 \
    -native-port=41823 -cloaked-port=41824 \
    -allowed-ip=10.10.0.2/32 \
    >/tmp/awg-e2e-x.log 2>&1 &
pids+=($!)
waitiface "$nsX" awg-x
ipX addr add 10.10.0.1/24 dev awg-x
ipX link set up dev awg-x

# --- Launch Y in nsY, pointed at X's address as seen from the router's
# public side (this is what a real Y, dialing X's real public IP, would
# resolve to) ---
nY env LOG_LEVEL=verbose "$program" \
    -role=y -tun=awg-y -mtu=1420 \
    -privkey="$ykey" -peerkey="$xpub" \
    -control-addr=10.0.0.2:41820 \
    -allowed-ip=10.10.0.1/32 \
    -native-timeout=10s \
    >/tmp/awg-e2e-y.log 2>&1 &
ypid=$!
pids+=($ypid)

# Y's process prints STATE=... and READY once its (single, synchronous)
# Start() call resolves, then blocks. Wait for that line.
for _ in $(seq 1 150); do
    grep -q '^STATE=' /tmp/awg-e2e-y.log 2>/dev/null && break
    kill -0 "$ypid" 2>/dev/null || break
    sleep 0.1
done

state_line="$(grep '^STATE=' /tmp/awg-e2e-y.log || true)"
pretty "" "Y reported: ${state_line:-<none>}"

case "$nat_mode" in
cone)
    [[ $state_line == STATE=connected-native* ]] || { echo "FAIL: expected connected-native for cone-type NAT, got: $state_line" >&2; cat /tmp/awg-e2e-y.log >&2; exit 1; }
    ipY addr add 10.10.0.2/24 dev awg-y
    ipY link set up dev awg-y
    waitiface "$nsY" awg-y
    nY ping -c 3 -W 2 10.10.0.1
    nX ping -c 3 -W 2 10.10.0.2
    pretty "" "cone-type NAT: native mode established and ping succeeded, as expected."
    ;;
symmetric)
    [[ $state_line == STATE=connected-native* ]] && { echo "FAIL: expected native mode to NOT succeed for symmetric NAT, but it did: $state_line" >&2; exit 1; }
    pretty "" "symmetric-type NAT: native mode correctly not established ($state_line)."
    ;;
esac

echo "PASS ($nat_mode)"
