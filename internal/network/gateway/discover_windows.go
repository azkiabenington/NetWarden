//go:build windows

package gateway

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modIphlpapi      = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetBestRoute = modIphlpapi.NewProc("GetBestRoute")
)

// mibIPForwardRow mirrors the Win32 MIB_IPFORWARDROW structure.
type mibIPForwardRow struct {
	ForwardDest      uint32
	ForwardMask      uint32
	ForwardPolicy    uint32
	ForwardNextHop   uint32
	ForwardIfIndex   uint32
	ForwardType      uint32
	ForwardProto     uint32
	ForwardAge       uint32
	ForwardNextHopAS uint32
	ForwardMetric1   uint32
	ForwardMetric2   uint32
	ForwardMetric3   uint32
	ForwardMetric4   uint32
	ForwardMetric5   uint32
}

// discoverSystemRoute queries the Windows IP Helper API directly in-process so
// periodic default-route checks never spawn route.exe / conhost.exe.
func discoverSystemRoute(ctx context.Context) (Route, error) {
	if err := ctx.Err(); err != nil {
		return Route{}, err
	}
	var row mibIPForwardRow
	ret, _, _ := procGetBestRoute.Call(0, 0, uintptr(unsafe.Pointer(&row)))
	if ret != 0 {
		errno := syscall.Errno(ret)
		if errno == windows.ERROR_NETWORK_UNREACHABLE || errno == windows.ERROR_HOST_UNREACHABLE || errno == windows.ERROR_NOT_FOUND {
			return Route{}, fmt.Errorf("%w: %v", ErrNoDefaultRoute, errno)
		}
		return Route{}, fmt.Errorf("%w: GetBestRoute: %v", ErrRouteQuery, errno)
	}
	if row.ForwardDest != 0 || row.ForwardMask != 0 {
		return Route{}, fmt.Errorf("%w: best route is not a default IPv4 route", ErrNoDefaultRoute)
	}
	gatewayIP := ipv4FromWin32Uint32(row.ForwardNextHop)
	if !gatewayIP.IsValid() || gatewayIP.IsUnspecified() {
		return Route{}, fmt.Errorf("%w: default route has no IPv4 gateway address", ErrNoDefaultRoute)
	}

	iface, err := net.InterfaceByIndex(int(row.ForwardIfIndex))
	if err != nil {
		return Route{}, fmt.Errorf("%w: lookup interface %d: %v", ErrRouteQuery, row.ForwardIfIndex, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return Route{}, fmt.Errorf("%w: list addresses for interface %q: %v", ErrRouteQuery, iface.Name, err)
	}
	if err := ctx.Err(); err != nil {
		return Route{}, err
	}
	interfaceIP, ok := selectInterfaceIPv4(addrs, gatewayIP)
	if !ok {
		return Route{}, fmt.Errorf("%w: interface %q has no usable IPv4 address", ErrRouteQuery, iface.Name)
	}
	return Route{GatewayIP: gatewayIP, InterfaceIP: interfaceIP}, nil
}

func ipv4FromWin32Uint32(raw uint32) netip.Addr {
	var octets [4]byte
	binary.LittleEndian.PutUint32(octets[:], raw)
	return netip.AddrFrom4(octets)
}

func selectInterfaceIPv4(addrs []net.Addr, gatewayIP netip.Addr) (netip.Addr, bool) {
	var fallback netip.Addr
	for _, addr := range addrs {
		prefix, err := netip.ParsePrefix(addr.String())
		if err != nil {
			continue
		}
		ip := prefix.Addr().Unmap()
		if !ip.Is4() || ip.IsLoopback() || ip.IsUnspecified() {
			continue
		}
		if prefix.Masked().Contains(gatewayIP) {
			return ip, true
		}
		if !fallback.IsValid() {
			fallback = ip
		}
	}
	return fallback, fallback.IsValid()
}
