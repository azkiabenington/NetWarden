package metadata

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestCleanResolvedHostname(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"AbuNaum.local.", "AbuNaum"},
		{"LAPTOP-M0M59QM9.lan", "LAPTOP-M0M59QM9"},
		{"Android_4c7711986dc44e439dc1881f58c8edc4.local", "Android (4c77)"},
		{"printer.example.com.", "printer.example.com"},
	}
	for _, tc := range tests {
		if got := cleanResolvedHostname(tc.input); got != tc.want {
			t.Errorf("cleanResolvedHostname(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestParseDNSPTRResponse(t *testing.T) {
	ip := netip.MustParseAddr("192.168.100.19")
	query, err := buildIPv4PTRQuery(ip, 0x1234, 0x0001)
	if err != nil {
		t.Fatal(err)
	}
	// Turn query into a 1-answer PTR response pointing to "AbuNaum.local".
	resp := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(resp[2:4], 0x8400)
	binary.BigEndian.PutUint16(resp[6:8], 1) // ANCOUNT = 1
	// Answer name pointer to offset 12 (0xc00c), TYPE=PTR (12), CLASS=IN (1), TTL=120
	rdata := []byte{7, 'A', 'b', 'u', 'N', 'a', 'u', 'm', 5, 'l', 'o', 'c', 'a', 'l', 0}
	var ansHeader [12]byte
	binary.BigEndian.PutUint16(ansHeader[0:2], 0xc00c)
	binary.BigEndian.PutUint16(ansHeader[2:4], 12)
	binary.BigEndian.PutUint16(ansHeader[4:6], 1)
	binary.BigEndian.PutUint32(ansHeader[6:10], 120)
	binary.BigEndian.PutUint16(ansHeader[10:12], uint16(len(rdata)))
	resp = append(resp, ansHeader[:]...)
	resp = append(resp, rdata...)

	qname, target, ok := parseDNSPTRResponse(resp)
	if !ok || qname != "19.100.168.192.in-addr.arpa" || target != "AbuNaum.local" {
		t.Fatalf("got qname=%q target=%q ok=%t", qname, target, ok)
	}
}

func TestParseNetBIOSResponse(t *testing.T) {
	packet := make([]byte, 57+18)
	packet[56] = 1
	copy(packet[57:72], []byte("LAPTOP-M0M59QM9"))
	packet[72] = 0x00 // Workstation service
	binary.BigEndian.PutUint16(packet[73:75], 0x0400) // Unique name
	if got := parseNetBIOSResponse(packet); got != "LAPTOP-M0M59QM9" {
		t.Fatalf("got %q, want LAPTOP-M0M59QM9", got)
	}
}

func TestParseUPnPDeviceXML(t *testing.T) {
	xmlData := []byte(`<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <friendlyName>Archer C54 AC1200 Dual Band Wi-Fi Router</friendlyName>
    <modelName>Archer C54</modelName>
  </device>
</root>`)
	if got := parseUPnPDeviceXML(xmlData); got != "Archer C54 AC1200 Dual Band Wi-Fi Router" {
		t.Fatalf("got %q", got)
	}
}
