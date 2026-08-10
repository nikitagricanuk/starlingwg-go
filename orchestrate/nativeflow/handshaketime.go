package nativeflow

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
)

// DeviceHandshakeTime scans dev.IpcGet()'s output for pk's peer block and
// reads its last_handshake_time_sec/nsec fields. device/uapi.go's
// IpcGetOperation always emits both fields, in that order, for every peer
// (device/uapi.go:190-195).
//
// This duplicates xshared's internal handshake-time parsing rather than
// importing it: xshared.SharedDevice.HandshakeTime is X's per-mode
// shared-Device abstraction, but every Device this helper is used against
// (Y's own cloaked/native Devices, and the background-re-attempt probe
// Device) is a plain, directly-constructed *device.Device, not a
// xshared.SharedDevice.
func DeviceHandshakeTime(dev *device.Device, pk device.NoisePublicKey) (t time.Time, found bool) {
	out, err := dev.IpcGet()
	if err != nil {
		return time.Time{}, false
	}
	want := hex.EncodeToString(pk[:])
	inBlock := false
	var sec, nsec int64
	asTime := func() time.Time {
		if sec == 0 && nsec == 0 {
			return time.Time{}
		}
		return time.Unix(sec, nsec)
	}
	for _, line := range bytes.Split([]byte(out), []byte("\n")) {
		key, value, ok := strings.Cut(string(line), "=")
		if !ok {
			continue
		}
		switch key {
		case "public_key":
			if inBlock {
				return asTime(), true
			}
			inBlock = value == want
		case "last_handshake_time_sec":
			if inBlock {
				fmt.Sscanf(value, "%d", &sec)
			}
		case "last_handshake_time_nsec":
			if inBlock {
				fmt.Sscanf(value, "%d", &nsec)
			}
		}
	}
	if inBlock {
		return asTime(), true
	}
	return time.Time{}, false
}

// DeviceRxBytes scans dev.IpcGet()'s output for pk's peer block and
// returns its rx_bytes counter -- bytes received from this peer,
// cumulative for the Device's lifetime.
//
// This, not DeviceHandshakeTime, is the right signal for ongoing
// connectivity liveness: WireGuard's persistent-keepalive traffic keeps
// rx_bytes climbing every keepalive interval even with no application
// traffic, whereas last_handshake_time only updates on a full Noise
// handshake -- which, in normal operation, only happens roughly every
// couple of minutes (rekey), not continuously. A short liveness check
// window compared against handshake recency would misfire on a perfectly
// healthy tunnel that simply hasn't needed to rekey yet.
func DeviceRxBytes(dev *device.Device, pk device.NoisePublicKey) (rx uint64, found bool) {
	out, err := dev.IpcGet()
	if err != nil {
		return 0, false
	}
	want := hex.EncodeToString(pk[:])
	inBlock := false
	for _, line := range bytes.Split([]byte(out), []byte("\n")) {
		key, value, ok := strings.Cut(string(line), "=")
		if !ok {
			continue
		}
		switch key {
		case "public_key":
			if inBlock {
				return rx, true
			}
			inBlock = value == want
		case "rx_bytes":
			if inBlock {
				fmt.Sscanf(value, "%d", &rx)
			}
		}
	}
	if inBlock {
		return rx, true
	}
	return 0, false
}
