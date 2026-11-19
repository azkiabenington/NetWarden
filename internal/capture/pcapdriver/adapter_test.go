package pcapdriver

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/amdzy/NetWarden/internal/capture"
	"github.com/amdzy/NetWarden/internal/packet"
)

func TestClassifyOpenError(t *testing.T) {
	tests := []struct {
		message string
		want    error
	}{
		{"permission denied", capture.ErrPermissionDenied},
		{"No such device exists", capture.ErrInterfaceMissing},
		{"libpcap unavailable", capture.ErrRuntimeUnavailable},
	}
	for _, test := range tests {
		err := classifyOpenError("en0", errors.New(test.message))
		if !errors.Is(err, test.want) {
			t.Errorf("classify %q: got %v, want %v", test.message, err, test.want)
		}
		var operation *capture.OperationError
		if !errors.As(err, &operation) || operation.Operation == "" {
			t.Errorf("classify %q did not preserve operation context: %v", test.message, err)
		}
	}
}

func TestNormalizeCapturedFrameStripsPriorityTagWithoutMutatingSource(t *testing.T) {
	untagged := []byte{
		0x04, 0x56, 0xe5, 0xfa, 0x92, 0xb3,
		0x3c, 0x93, 0xf4, 0xe6, 0x76, 0x8b,
		0x08, 0x06, 0x00, 0x01, 0x08, 0x00,
	}
	tagged := make([]byte, len(untagged)+packet.VLANHeaderLen)
	copy(tagged[:12], untagged[:12])
	binary.BigEndian.PutUint16(tagged[12:14], packet.EtherTypeVLAN)
	binary.BigEndian.PutUint16(tagged[14:16], 0x0000)
	copy(tagged[16:], untagged[12:])
	snapshot := append([]byte(nil), tagged...)

	copied, _ := normalizeCapturedFrame(nil, tagged, true)
	if !bytes.Equal(copied, untagged) {
		t.Fatalf("copy mode got %x, want %x", copied, untagged)
	}
	if !bytes.Equal(tagged, snapshot) {
		t.Fatal("copy mode mutated source capture buffer")
	}

	borrowed, scratch := normalizeCapturedFrame(nil, tagged, false)
	if !bytes.Equal(borrowed, untagged) || len(scratch) != len(untagged) {
		t.Fatalf("borrowed mode got %x (scratch=%d), want %x", borrowed, len(scratch), untagged)
	}
	if !bytes.Equal(tagged, snapshot) {
		t.Fatal("borrowed mode mutated source capture buffer")
	}

	// Non-zero VLAN ID stays untouched.
	realVLAN := append([]byte(nil), tagged...)
	binary.BigEndian.PutUint16(realVLAN[14:16], 0x0005)
	preserved, _ := normalizeCapturedFrame(scratch, realVLAN, true)
	if !bytes.Equal(preserved, realVLAN) {
		t.Fatalf("non-zero VLAN was altered: got %x, want %x", preserved, realVLAN)
	}
}
