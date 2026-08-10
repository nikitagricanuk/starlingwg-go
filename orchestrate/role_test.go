package orchestrate

import (
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
)

func validXConfig() Config {
	return Config{
		Role:                    RoleX,
		ControlListenAddr:       ":41820",
		PublicHost:              "203.0.113.1",
		ProbePortA:              40001,
		ProbePortB:              40002,
		NativeListenPort:        51821,
		CloakedListenPort:       51820,
		NativeHandshakeTimeout:  8 * time.Second,
		CloakedHandshakeTimeout: 8 * time.Second,
		NativeTUN:               tuntest.NewChannelTUN().TUN(),
		CloakedTUN:              tuntest.NewChannelTUN().TUN(),
		Logger:                  device.NewLogger(device.LogLevelSilent, ""),
	}
}

func validYConfig() Config {
	return Config{
		Role: RoleY,
		Peers: []PeerConfig{
			{ControlAddr: "203.0.113.1:41820"},
		},
		NativeHandshakeTimeout:  8 * time.Second,
		CloakedHandshakeTimeout: 8 * time.Second,
		YTUN:                    tuntest.NewChannelTUN().TUN(),
		Logger:                  device.NewLogger(device.LogLevelSilent, ""),
	}
}

func TestConfigValidateAcceptsValidX(t *testing.T) {
	if err := validXConfig().validate(); err != nil {
		t.Fatalf("expected valid X config to pass validation, got: %v", err)
	}
}

func TestConfigValidateAcceptsValidY(t *testing.T) {
	if err := validYConfig().validate(); err != nil {
		t.Fatalf("expected valid Y config to pass validation, got: %v", err)
	}
}

func TestConfigValidateRejectsMissingLogger(t *testing.T) {
	c := validXConfig()
	c.Logger = nil
	if err := c.validate(); err == nil {
		t.Fatalf("expected validation error for missing Logger")
	}
}

func TestConfigValidateRejectsXMissingControlAddr(t *testing.T) {
	c := validXConfig()
	c.ControlListenAddr = ""
	if err := c.validate(); err == nil {
		t.Fatalf("expected validation error for missing ControlListenAddr")
	}
}

func TestConfigValidateRejectsXMissingPublicHost(t *testing.T) {
	c := validXConfig()
	c.PublicHost = ""
	if err := c.validate(); err == nil {
		t.Fatalf("expected validation error for missing PublicHost")
	}
}

func TestConfigValidateRejectsXMissingCloakedTUN(t *testing.T) {
	c := validXConfig()
	c.CloakedTUN = nil
	if err := c.validate(); err == nil {
		t.Fatalf("expected validation error for missing CloakedTUN")
	}
}

func TestConfigValidateRejectsXSameProbePorts(t *testing.T) {
	c := validXConfig()
	c.ProbePortB = c.ProbePortA
	if err := c.validate(); err == nil {
		t.Fatalf("expected validation error for identical probe ports")
	}
}

func TestConfigValidateRejectsXSameNativeAndCloakedPort(t *testing.T) {
	c := validXConfig()
	c.CloakedListenPort = c.NativeListenPort
	if err := c.validate(); err == nil {
		t.Fatalf("expected validation error for identical native/cloaked ports")
	}
}

func TestConfigValidateRejectsYWithNoPeers(t *testing.T) {
	c := validYConfig()
	c.Peers = nil
	if err := c.validate(); err == nil {
		t.Fatalf("expected validation error for Y with no peers")
	}
}

func TestConfigValidateRejectsXMissingNativeTUN(t *testing.T) {
	c := validXConfig()
	c.NativeTUN = nil
	if err := c.validate(); err == nil {
		t.Fatalf("expected validation error for missing NativeTUN")
	}
}

func TestConfigValidateRejectsYMissingTUN(t *testing.T) {
	c := validYConfig()
	c.YTUN = nil
	if err := c.validate(); err == nil {
		t.Fatalf("expected validation error for missing YTUN")
	}
}

func TestConfigValidateRejectsYPeerMissingControlAddr(t *testing.T) {
	c := validYConfig()
	c.Peers[0].ControlAddr = ""
	if err := c.validate(); err == nil {
		t.Fatalf("expected validation error for peer missing ControlAddr")
	}
}

func TestConfigValidateRejectsZeroTimeout(t *testing.T) {
	c := validXConfig()
	c.NativeHandshakeTimeout = 0
	if err := c.validate(); err == nil {
		t.Fatalf("expected validation error for zero NativeHandshakeTimeout")
	}
}

func TestConfigValidateRejectsZeroCloakedTimeout(t *testing.T) {
	c := validXConfig()
	c.CloakedHandshakeTimeout = 0
	if err := c.validate(); err == nil {
		t.Fatalf("expected validation error for zero CloakedHandshakeTimeout")
	}
}

func TestRoleString(t *testing.T) {
	if RoleX.String() != "X" {
		t.Errorf("RoleX.String() = %q, want %q", RoleX.String(), "X")
	}
	if RoleY.String() != "Y" {
		t.Errorf("RoleY.String() = %q, want %q", RoleY.String(), "Y")
	}
}

func TestKeyConversionRoundTrip(t *testing.T) {
	var priv device.NoisePrivateKey
	priv[0] = 0xAB
	cp := toControlPrivateKey(priv)
	if cp[0] != 0xAB {
		t.Fatalf("toControlPrivateKey lost data: %x", cp)
	}

	var pub device.NoisePublicKey
	pub[1] = 0xCD
	cpub := toControlPublicKey(pub)
	if cpub[1] != 0xCD {
		t.Fatalf("toControlPublicKey lost data: %x", cpub)
	}
}
