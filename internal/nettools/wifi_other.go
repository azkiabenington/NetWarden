//go:build !windows

package nettools

import (
	"context"
	"errors"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// ScanWiFi scans nearby Wireless Access Points on Linux (Ubuntu NetworkManager
// nmcli) and returns signal strength, channel, band, and collision likelihood.
func ScanWiFi(ctx context.Context, vendorLookup func(net.HardwareAddr) string) (WiFiScanResult, error) {
	if err := ctx.Err(); err != nil {
		return WiFiScanResult{}, err
	}
	if runtime.GOOS != "linux" {
		return WiFiScanResult{}, errors.New("Wi-Fi BSS scanning is supported on Windows and Linux (Ubuntu NetworkManager)")
	}
	nmcliPath, err := exec.LookPath("nmcli")
	if err != nil {
		return WiFiScanResult{}, errors.New("nmcli (NetworkManager) is required for Wi-Fi scanning on Ubuntu/Linux")
	}

	ifaceName := detectLinuxWirelessInterface(ctx, nmcliPath)
	cmdCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(
		cmdCtx,
		nmcliPath,
		"-t",
		"-e", "no",
		"-f", "SSID,BSSID,CHAN,FREQ,SIGNAL",
		"dev", "wifi", "list",
		"--rescan", "auto",
	).Output()
	if err != nil {
		return WiFiScanResult{}, errors.New("could not read Wi-Fi scan list from NetworkManager")
	}

	networks := parseNMCLIWiFiOutput(string(output), vendorLookup)
	return WiFiScanResult{
		InterfaceName: ifaceName,
		ScannedAt:     time.Now().UTC(),
		Networks:      networks,
	}, nil
}

func detectLinuxWirelessInterface(ctx context.Context, nmcliPath string) string {
	cmdCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cmdCtx, nmcliPath, "-t", "-e", "no", "-f", "DEVICE,TYPE", "dev", "status").Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			parts := strings.Split(strings.TrimSpace(line), ":")
			if len(parts) >= 2 && parts[1] == "wifi" && parts[0] != "" {
				return parts[0]
			}
		}
	}
	return "wlan0"
}
