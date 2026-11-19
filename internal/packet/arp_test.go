package packet

import (
	"net"
	"net/netip"
	"testing"
)

func TestARPRoundTrip(t *testing.T) {
	source := mustMAC(t, "02:00:00:00:00:01")
	destination := mustMAC(t, "ff:ff:ff:ff:ff:ff")
	want := ARP{
		Operation: ARPOpRequest,
		SenderMAC: source,
		SenderIP:  netip.MustParseAddr("192.168.1.10"),
		TargetMAC: mustMAC(t, "00:00:00:00:00:00"),
		TargetIP:  netip.MustParseAddr("192.168.1.1"),
	}

	frame, err := MarshalARP(destination, source, want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseARP(frame)
	if err != nil {
		t.Fatal(err)
	}
	if got.Operation != want.Operation || got.SenderIP != want.SenderIP ||
		got.TargetIP != want.TargetIP || got.SenderMAC.String() != want.SenderMAC.String() ||
		got.TargetMAC.String() != want.TargetMAC.String() {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestParseARPRejectsShortFrame(t *testing.T) {
	if _, err := ParseARP(make([]byte, 10)); err == nil {
		t.Fatal("expected an error")
	}
}

func TestParseARPAcceptsPriorityTaggedFrameAndRejectsNonZeroVLAN(t *testing.T) {
	source := mustMAC(t, "3c:93:f4:e6:76:8b")
	destination := mustMAC(t, "04:56:e5:fa:92:b3")
	want := ARP{
		Operation: ARPOpReply,
		SenderMAC: source,
		SenderIP:  netip.MustParseAddr("192.168.100.1"),
		TargetMAC: destination,
		TargetIP:  netip.MustParseAddr("192.168.100.182"),
	}
	untagged, err := MarshalARP(destination, source, want)
	if err != nil {
		t.Fatal(err)
	}
	for _, tci := range []uint16{0x0000, 0x6000} {
		tagged := insertVLAN8021Q(untagged, tci)
		got, err := ParseARP(tagged)
		if err != nil {
			t.Fatalf("tci=0x%04x: ParseARP failed: %v", tci, err)
		}
		if got.Operation != want.Operation || got.SenderIP != want.SenderIP ||
			got.TargetIP != want.TargetIP || got.SenderMAC.String() != want.SenderMAC.String() ||
			got.TargetMAC.String() != want.TargetMAC.String() {
			t.Fatalf("tci=0x%04x: got %#v, want %#v", tci, got, want)
		}
	}
	if _, err := ParseARP(insertVLAN8021Q(untagged, 0x000a)); err == nil {
		t.Fatal("accepted ARP frame with non-zero VLAN ID")
	}
	if _, err := ParseARP(insertVLAN8021Q(insertVLAN8021Q(untagged, 0x0000), 0x0000)); err == nil {
		t.Fatal("accepted double-tagged ARP frame")
	}
	truncated := insertVLAN8021Q(untagged, 0x0000)[:EthernetHeaderLen+VLANHeaderLen+ARPHeaderLen-1]
	if _, err := ParseARP(truncated); err == nil {
		t.Fatal("accepted truncated priority-tagged ARP frame")
	}
}

func mustMAC(t *testing.T, value string) net.HardwareAddr {
	t.Helper()
	mac, err := net.ParseMAC(value)
	if err != nil {
		t.Fatal(err)
	}
	return mac
}
