//go:build windows

package nettools

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var (
	wlanapi                  = syscall.NewLazyDLL("wlanapi.dll")
	procWlanOpenHandle       = wlanapi.NewProc("WlanOpenHandle")
	procWlanCloseHandle      = wlanapi.NewProc("WlanCloseHandle")
	procWlanEnumInterfaces   = wlanapi.NewProc("WlanEnumInterfaces")
	procWlanScan             = wlanapi.NewProc("WlanScan")
	procWlanGetNetworkBssList = wlanapi.NewProc("WlanGetNetworkBssList")
	procWlanFreeMemory       = wlanapi.NewProc("WlanFreeMemory")
)

type wlanInterfaceInfo struct {
	InterfaceGuid           syscall.GUID
	StrInterfaceDescription [256]uint16
	IsState                 uint32
}

type wlanInterfaceInfoList struct {
	NumberOfItems uint32
	Index         uint32
	FirstInfo     wlanInterfaceInfo
}

type dot11SSID struct {
	SSIDLength uint32
	SSID       [32]byte
}

type wlanRateSet struct {
	RateSetLength uint32
	RateSet       [126]uint16
}

type wlanBSSEntry struct {
	Dot11Ssid             dot11SSID
	PhyId                 uint32
	Dot11Bssid            [6]byte
	_                     [2]byte
	Dot11BssType          uint32
	Dot11BssPhyType       uint32
	Rssi                  int32
	LinkQuality           uint32
	InRegDomain           uint8
	_                     uint8
	BeaconPeriod          uint16
	_                     uint32
	Timestamp             uint64
	HostTimestamp         uint64
	CapabilityInformation uint16
	_                     uint16
	ChCenterFrequency     uint32
	WlanRateSet           wlanRateSet
	IeOffset              uint32
	IeSize                uint32
}

type wlanBSSList struct {
	TotalSize     uint32
	NumberOfItems uint32
	FirstEntry    wlanBSSEntry
}

func ScanWiFi(ctx context.Context, vendorLookup func(net.HardwareAddr) string) (WiFiScanResult, error) {
	if err := ctx.Err(); err != nil {
		return WiFiScanResult{}, err
	}
	var negotiatedVersion uint32
	var clientHandle uintptr
	ret, _, _ := procWlanOpenHandle.Call(2, 0, uintptr(unsafe.Pointer(&negotiatedVersion)), uintptr(unsafe.Pointer(&clientHandle)))
	if ret != 0 {
		return WiFiScanResult{}, fmt.Errorf("open Windows WLAN service: error %d", ret)
	}
	defer procWlanCloseHandle.Call(clientHandle, 0)

	var ifaceList *wlanInterfaceInfoList
	ret, _, _ = procWlanEnumInterfaces.Call(clientHandle, 0, uintptr(unsafe.Pointer(&ifaceList)))
	if ret != 0 || ifaceList == nil {
		return WiFiScanResult{}, fmt.Errorf("enumerate Wi-Fi interfaces: error %d", ret)
	}
	defer procWlanFreeMemory.Call(uintptr(unsafe.Pointer(ifaceList)))

	if ifaceList.NumberOfItems == 0 {
		return WiFiScanResult{}, errors.New("no wireless interfaces detected on this computer")
	}

	firstIface := &ifaceList.FirstInfo
	ifaceDesc := syscall.UTF16ToString(firstIface.StrInterfaceDescription[:])
	guid := firstIface.InterfaceGuid

	// Request a fresh scan and give the driver a moment to collect beacons.
	_, _, _ = procWlanScan.Call(clientHandle, uintptr(unsafe.Pointer(&guid)), 0, 0, 0)
	select {
	case <-ctx.Done():
		return WiFiScanResult{}, ctx.Err()
	case <-time.After(750 * time.Millisecond):
	}

	var bssList *wlanBSSList
	ret, _, _ = procWlanGetNetworkBssList.Call(
		clientHandle,
		uintptr(unsafe.Pointer(&guid)),
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&bssList)),
	)
	if ret != 0 || bssList == nil {
		return WiFiScanResult{}, fmt.Errorf("read Wi-Fi BSS list: error %d", ret)
	}
	defer procWlanFreeMemory.Call(uintptr(unsafe.Pointer(bssList)))

	entries := unsafe.Slice(&bssList.FirstEntry, int(bssList.NumberOfItems))
	networks := make([]WiFiNetwork, 0, len(entries))
	channelCounts := make(map[int]int)

	for i := range entries {
		entry := &entries[i]
		ssidLen := entry.Dot11Ssid.SSIDLength
		if ssidLen > 32 {
			ssidLen = 32
		}
		ssid := strings.TrimSpace(string(entry.Dot11Ssid.SSID[:ssidLen]))
		if ssid == "" {
			ssid = "(Hidden Network)"
		}
		bssidMAC := net.HardwareAddr(entry.Dot11Bssid[:])
		bssid := strings.ToLower(bssidMAC.String())
		vendor := ""
		if vendorLookup != nil {
			vendor = vendorLookup(bssidMAC)
		}
		freqMHz := int(entry.ChCenterFrequency / 1000)
		channel, band := FrequencyToChannel(freqMHz)
		channelCounts[channel]++

		rssi := int(entry.Rssi)
		quality := int(entry.LinkQuality)
		if quality <= 0 && rssi < 0 {
			quality = max(0, min(100, 2*(rssi+100)))
		}

		networks = append(networks, WiFiNetwork{
			SSID:          ssid,
			BSSID:         bssid,
			Vendor:        vendor,
			RSSIDBm:       rssi,
			SignalQuality: quality,
			Channel:       channel,
			FrequencyMHz:  freqMHz,
			Band:          band,
		})
	}

	for i := range networks {
		same := channelCounts[networks[i].Channel]
		networks[i].SameChannelAP = same
		networks[i].CollisionRisk = EvaluateCollisionRisk(networks[i].Band, same, networks[i].RSSIDBm)
	}

	sort.Slice(networks, func(i, j int) bool {
		if networks[i].RSSIDBm != networks[j].RSSIDBm {
			return networks[i].RSSIDBm > networks[j].RSSIDBm
		}
		return networks[i].SSID < networks[j].SSID
	})

	return WiFiScanResult{
		InterfaceName: ifaceDesc,
		ScannedAt:     time.Now().UTC(),
		Networks:      networks,
	}, nil
}
