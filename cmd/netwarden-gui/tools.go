package main

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/amdzy/NetWarden/internal/device"
	"github.com/amdzy/NetWarden/internal/metadata"
	"github.com/amdzy/NetWarden/internal/nettools"
	networkgateway "github.com/amdzy/NetWarden/internal/network/gateway"
)

func (a *GUIApp) PingHost(target string, count int) (nettools.PingResult, error) {
	baseCtx := a.ctx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	ctx, cancel := context.WithTimeout(baseCtx, 25*time.Second)
	defer cancel()
	return nettools.PingHost(ctx, target, count)
}

func (a *GUIApp) TraceRoute(target string, maxHops int) (nettools.TraceRouteResult, error) {
	baseCtx := a.ctx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	ctx, cancel := context.WithTimeout(baseCtx, 35*time.Second)
	defer cancel()
	return nettools.TraceRoute(ctx, target, maxHops)
}

func (a *GUIApp) ScanWiFi() (nettools.WiFiScanResult, error) {
	baseCtx := a.ctx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	ctx, cancel := context.WithTimeout(baseCtx, 15*time.Second)
	defer cancel()
	return nettools.ScanWiFi(ctx, func(mac net.HardwareAddr) string {
		v := shortVendorName(metadata.LookupVendor(mac))
		if v == "" {
			return metadata.LookupVendor(mac)
		}
		return v
	})
}

func (a *GUIApp) WakeOnLAN(macAddress, targetIP string) error {
	return nettools.SendWakeOnLAN(macAddress, targetIP)
}

func (a *GUIApp) ScanPorts(target, preset string) (nettools.PortScanResult, error) {
	baseCtx := a.ctx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	ctx, cancel := context.WithTimeout(baseCtx, 25*time.Second)
	defer cancel()
	return nettools.ScanPorts(ctx, target, preset)
}

func (a *GUIApp) CheckRouterVulnerabilities() (nettools.RouterVulnerabilityResult, error) {
	baseCtx := a.ctx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	ctx, cancel := context.WithTimeout(baseCtx, 20*time.Second)
	defer cancel()
	gatewayIP := a.resolveActiveGatewayIP(ctx)
	return nettools.CheckRouterVulnerabilities(ctx, gatewayIP)
}

func (a *GUIApp) DetectHiddenCameras() (nettools.HiddenCameraResult, error) {
	baseCtx := a.ctx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	ctx, cancel := context.WithTimeout(baseCtx, 35*time.Second)
	defer cancel()

	devices, err := a.Devices()
	if err != nil {
		return nettools.HiddenCameraResult{}, err
	}
	inputs := make([]nettools.DeviceInput, 0, len(devices))
	for _, dev := range devices {
		if strings.EqualFold(dev.Role, "This device") || strings.EqualFold(dev.Role, "Gateway") {
			continue
		}
		inputs = append(inputs, nettools.DeviceInput{
			IP:     dev.IP,
			MAC:    dev.MAC,
			Name:   dev.Name,
			Vendor: dev.Vendor,
			Type:   dev.Type,
			Online: dev.Online,
		})
	}
	return nettools.DetectHiddenCameras(ctx, inputs)
}

func (a *GUIApp) CheckInternetHealth() (nettools.InternetHealthResult, error) {
	baseCtx := a.ctx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	ctx, cancel := context.WithTimeout(baseCtx, 20*time.Second)
	defer cancel()
	gatewayIP := a.resolveActiveGatewayIP(ctx)
	return nettools.CheckInternetHealth(ctx, gatewayIP)
}

func (a *GUIApp) resolveActiveGatewayIP(ctx context.Context) string {
	a.mu.RLock()
	supervisor := a.supervisor
	a.mu.RUnlock()
	if supervisor != nil && supervisor.Current() != nil {
		for _, dev := range supervisor.Devices() {
			if dev.Role == device.RoleGateway && dev.IP.IsValid() {
				return dev.IP.String()
			}
		}
	}
	if route, err := (networkgateway.SystemDiscoverer{}).Discover(ctx); err == nil && route.GatewayIP.IsValid() {
		return route.GatewayIP.String()
	}
	if snapshot, err := loadHistorySnapshot(); err == nil {
		for _, dev := range snapshot.Devices {
			if dev.Role == device.RoleGateway && dev.IP.IsValid() {
				return dev.IP.String()
			}
		}
	}
	return ""
}
