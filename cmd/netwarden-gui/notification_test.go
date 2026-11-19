package main

import (
	"net/netip"
	"testing"

	coreapp "github.com/amdzy/NetWarden/internal/app"
	appconfig "github.com/amdzy/NetWarden/internal/config"
	"github.com/amdzy/NetWarden/internal/device"
)

func TestNotificationContentDoesNotRepeatIPAddressAsDeviceName(t *testing.T) {
	event := coreapp.Event{Device: &device.Device{
		IP: netip.MustParseAddr("192.168.30.48"), MAC: "12:98:38:6b:f3:5c",
		Name: "192.168.30.48", Vendor: "Private / randomized",
	}}
	title, body := notificationContent(event, ActivityDTO{Title: "New device joined"})
	if title != "New device joined" || body != "Private / randomized\n192.168.30.48 · 12:98:38:6b:f3:5c" {
		t.Fatalf("got %q / %q", title, body)
	}
}

func TestBaselineNotificationBatchesEnabledDeviceCategories(t *testing.T) {
	settings := appconfig.NotificationSettings{Enabled: true, NewDevices: true, KnownDevices: true}
	title, body, ok := baselineNotificationContent(settings, 2, 9)
	if !ok || title != "Initial network scan complete" || body != "2 new devices · 9 known devices" {
		t.Fatalf("got %q / %q / %v", title, body, ok)
	}
}

func TestBaselineNotificationHonorsNotificationSettings(t *testing.T) {
	settings := appconfig.NotificationSettings{Enabled: true, KnownDevices: true}
	_, body, ok := baselineNotificationContent(settings, 4, 1)
	if !ok || body != "1 known device" {
		t.Fatalf("got %q / %v", body, ok)
	}
	settings.Enabled = false
	if _, _, ok := baselineNotificationContent(settings, 4, 1); ok {
		t.Fatal("disabled master setting produced a notification")
	}
}

func TestNotificationContentUsesResolvedDeviceName(t *testing.T) {
	event := coreapp.Event{Device: &device.Device{
		IP: netip.MustParseAddr("192.168.1.104"), MAC: "00:11:22:33:44:55",
		Name: "Samsung Galaxy S25", Vendor: "Samsung",
	}}
	_, body := notificationContent(event, ActivityDTO{Title: "New device joined"})
	if body != "Samsung Galaxy S25\n192.168.1.104 · 00:11:22:33:44:55" {
		t.Fatalf("got %q", body)
	}
}

func TestDeviceDTOUsesFallbackVendorNameWhenHostnameUnresolved(t *testing.T) {
	gateway := deviceDTO(device.Device{
		IP: netip.MustParseAddr("192.168.100.1"), MAC: "3c:93:f4:e6:76:8b",
		Name: "192.168.100.1", Vendor: "HUAWEI TECHNOLOGIES CO.,LTD", Role: device.RoleGateway,
	})
	if gateway.Name != "Huawei Gateway" {
		t.Fatalf("gateway.Name = %q, want Huawei Gateway", gateway.Name)
	}
	peer := deviceDTO(device.Device{
		IP: netip.MustParseAddr("192.168.100.79"), MAC: "d8:d6:68:e1:9e:07",
		Name: "192.168.100.79", Vendor: "Tuya Smart Inc.", Type: device.TypeSmartHome, Role: device.RolePeer,
	})
	if peer.Name != "Tuya · Smart home" {
		t.Fatalf("peer.Name = %q, want Tuya · Smart home", peer.Name)
	}
}
