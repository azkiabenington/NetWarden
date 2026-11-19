package packet

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func insertVLAN8021Q(frame []byte, tci uint16) []byte {
	tagged := make([]byte, len(frame)+VLANHeaderLen)
	copy(tagged[:12], frame[:12])
	binary.BigEndian.PutUint16(tagged[12:14], EtherTypeVLAN)
	binary.BigEndian.PutUint16(tagged[14:16], tci)
	copy(tagged[16:], frame[12:])
	return tagged
}

func TestStripPriorityTag(t *testing.T) {
	untagged := []byte{
		0x04, 0x56, 0xe5, 0xfa, 0x92, 0xb3,
		0x3c, 0x93, 0xf4, 0xe6, 0x76, 0x8b,
		0x08, 0x06, 0xde, 0xad, 0xbe, 0xef,
	}
	for _, tci := range []uint16{0x0000, 0x6000, 0xf000} {
		tagged := insertVLAN8021Q(untagged, tci)
		original := append([]byte(nil), tagged...)
		if !IsPriorityTagged(tagged) {
			t.Fatalf("tci=0x%04x: expected IsPriorityTagged=true", tci)
		}
		got := StripPriorityTag(nil, tagged)
		if !bytes.Equal(got, untagged) {
			t.Fatalf("tci=0x%04x: got %x, want %x", tci, got, untagged)
		}
		if !bytes.Equal(tagged, original) {
			t.Fatalf("tci=0x%04x: StripPriorityTag mutated source buffer", tci)
		}
	}

	// Non-zero VLAN ID must remain untouched.
	realVLAN := insertVLAN8021Q(untagged, 0x000a)
	if IsPriorityTagged(realVLAN) {
		t.Fatal("non-zero VLAN ID reported as priority-only tag")
	}
	if got := StripPriorityTag(nil, realVLAN); !bytes.Equal(got, realVLAN) {
		t.Fatalf("non-zero VLAN frame was modified: got %x", got)
	}

	// Truncated VLAN header must be rejected safely.
	truncated := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x81, 0x00, 0x00, 0x00}
	if IsPriorityTagged(truncated) {
		t.Fatal("truncated VLAN frame reported as priority-tagged")
	}
}
