//go:build !windows

package nettools

import (
	"context"
	"errors"
	"net"
)

func ScanWiFi(_ context.Context, _ func(net.HardwareAddr) string) (WiFiScanResult, error) {
	return WiFiScanResult{}, errors.New("native Wi-Fi BSS scanning is currently supported on Windows")
}
