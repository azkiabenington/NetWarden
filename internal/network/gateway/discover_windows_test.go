//go:build windows

package gateway

import (
	"net"
	"net/netip"
	"testing"
	"unsafe"
)

func TestMIBIPForwardRowSize(t *testing.T) {
	if got := unsafe.Sizeof(mibIPForwardRow{}); got != 56 {
		t.Fatalf("sizeof(mibIPForwardRow) = %d, want 56", got)
	}
}

func TestIPv4FromWin32Uint32(t *testing.T) {
	// 192.168.100.1 in network byte order read as little-endian uint32: 0x0164a8c0
	got := ipv4FromWin32Uint32(0x0164a8c0)
	want := netip.MustParseAddr("192.168.100.1")
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestSelectInterfaceIPv4PrefersGatewaySubnet(t *testing.T) {
	addrs := []net.Addr{
		&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
		&net.IPNet{IP: net.ParseIP("10.0.0.5"), Mask: net.CIDRMask(24, 32)},
		&net.IPNet{IP: net.ParseIP("192.168.100.182"), Mask: net.CIDRMask(24, 32)},
	}
	got, ok := selectInterfaceIPv4(addrs, netip.MustParseAddr("192.168.100.1"))
	if !ok || got != netip.MustParseAddr("192.168.100.182") {
		t.Fatalf("got %s (%t), want 192.168.100.182", got, ok)
	}
}

func TestSelectInterfaceIPv4FallsBackWhenGatewayOutsideMask(t *testing.T) {
	addrs := []net.Addr{
		&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
		&net.IPNet{IP: net.ParseIP("100.72.240.9"), Mask: net.CIDRMask(32, 32)},
	}
	got, ok := selectInterfaceIPv4(addrs, netip.MustParseAddr("100.72.240.1"))
	if !ok || got != netip.MustParseAddr("100.72.240.9") {
		t.Fatalf("got %s (%t), want 100.72.240.9", got, ok)
	}
}
