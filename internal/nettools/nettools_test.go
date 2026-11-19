package nettools

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

func TestBuildWakeOnLANPacketFormat(t *testing.T) {
	mac, err := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	if err != nil {
		t.Fatal(err)
	}
	packet, err := BuildWakeOnLANPacket(mac)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet) != 102 {
		t.Fatalf("len(packet) = %d, want 102", len(packet))
	}
	for i := 0; i < 6; i++ {
		if packet[i] != 0xFF {
			t.Fatalf("header byte %d = %02x, want ff", i, packet[i])
		}
	}
	for copyIdx := 0; copyIdx < 16; copyIdx++ {
		offset := 6 + copyIdx*6
		if string(packet[offset:offset+6]) != string(mac) {
			t.Fatalf("copy %d mismatch", copyIdx)
		}
	}
}

func TestFrequencyToChannelAndCollisionRisk(t *testing.T) {
	ch, band := FrequencyToChannel(2412)
	if ch != 1 || band != "2.4 GHz" {
		t.Fatalf("2412 MHz = ch %d (%s), want ch 1 (2.4 GHz)", ch, band)
	}
	ch5, band5 := FrequencyToChannel(5180)
	if ch5 != 36 || band5 != "5 GHz" {
		t.Fatalf("5180 MHz = ch %d (%s), want ch 36 (5 GHz)", ch5, band5)
	}
	if risk := EvaluateCollisionRisk("2.4 GHz", 4, -55); risk != "High" {
		t.Fatalf("collision risk = %s, want High", risk)
	}
	if risk := EvaluateCollisionRisk("5 GHz", 1, -50); risk != "Low" {
		t.Fatalf("collision risk = %s, want Low", risk)
	}
}

func TestScanPortsDetectsLocalListener(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, portStr, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	open, ok := probeTCPPort(context.Background(), netip.MustParseAddr("127.0.0.1"), port, 500*time.Millisecond)
	if !ok || open.Port != port {
		t.Fatalf("probeTCPPort did not detect local listener on port %d: %#v, %v", port, open, ok)
	}
}

func TestDetectHiddenCamerasScoresVendorAndPorts(t *testing.T) {
	result, err := DetectHiddenCameras(context.Background(), []DeviceInput{
		{IP: "192.168.1.50", MAC: "00:11:22:33:44:55", Name: "Hikvision IPC-200", Vendor: "Hikvision Digital Technology", Online: false},
		{IP: "192.168.1.51", MAC: "00:11:22:33:44:66", Name: "Office Printer", Vendor: "HP Inc.", Online: false},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Suspects) != 1 || result.Suspects[0].IP != "192.168.1.50" || result.Suspects[0].Confidence != "High" {
		t.Fatalf("unexpected camera suspects: %#v", result.Suspects)
	}
}

func TestPingLocalhost(t *testing.T) {
	res, err := PingHost(context.Background(), "127.0.0.1", 2)
	if err != nil {
		t.Fatal(err)
	}
	if res.Received == 0 || len(res.Samples) != 2 {
		t.Fatalf("PingHost(127.0.0.1) = %#v", res)
	}
}
