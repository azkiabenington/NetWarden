package packet

import "encoding/binary"

const (
	// EtherTypeVLAN is the IEEE 802.1Q tag protocol identifier (TPID).
	EtherTypeVLAN = 0x8100
	// VLANHeaderLen is the 4-byte size of an IEEE 802.1Q tag (TPID + TCI).
	VLANHeaderLen = 4
)

// IsPriorityTagged reports whether frame begins with an IEEE 802.1Q
// priority-only tag (EtherType 0x8100 with VLAN ID 0). Npcap 1.81+ on Windows
// Wi-Fi interfaces reconstructs such zero-VID tags from NDIS metadata on
// incoming unicast frames even on untagged networks.
func IsPriorityTagged(frame []byte) bool {
	if len(frame) < EthernetHeaderLen+VLANHeaderLen {
		return false
	}
	if binary.BigEndian.Uint16(frame[12:14]) != EtherTypeVLAN {
		return false
	}
	tci := binary.BigEndian.Uint16(frame[14:16])
	return tci&0x0fff == 0
}

// StripPriorityTag removes a single IEEE 802.1Q VLAN-0 priority tag from frame
// without mutating frame. It writes the untagged Ethernet frame into dst
// (reusing dst's backing array when capacity permits) and returns the resulting
// slice. Non-priority-tagged frames are returned unchanged.
func StripPriorityTag(dst, frame []byte) []byte {
	if !IsPriorityTagged(frame) {
		return frame
	}
	needed := len(frame) - VLANHeaderLen
	if cap(dst) < needed {
		dst = make([]byte, needed)
	} else {
		dst = dst[:needed]
	}
	copy(dst[:12], frame[:12])
	copy(dst[12:], frame[16:])
	return dst
}

// ParseEthernetHeader returns the frame's EtherType and payload slice. A single
// IEEE 802.1Q priority-only tag (VLAN ID 0) is unwrapped; frames carrying a
// non-zero VLAN ID or truncated tag remain unstripped.
func ParseEthernetHeader(frame []byte) (etherType uint16, payload []byte, ok bool) {
	if len(frame) < EthernetHeaderLen {
		return 0, nil, false
	}
	if IsPriorityTagged(frame) {
		return binary.BigEndian.Uint16(frame[16:18]), frame[EthernetHeaderLen+VLANHeaderLen:], true
	}
	return binary.BigEndian.Uint16(frame[12:14]), frame[EthernetHeaderLen:], true
}
