package helper

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/amdzy/NetWarden/internal/capture"
	"github.com/amdzy/NetWarden/internal/packet"
)

type borrowedProtocolDriver struct {
	borrowed atomic.Bool
	regular  atomic.Bool
}

func (d *borrowedProtocolDriver) Run(ctx context.Context, _ func(capture.Frame) error) error {
	d.regular.Store(true)
	<-ctx.Done()
	return ctx.Err()
}

func (d *borrowedProtocolDriver) RunBorrowed(ctx context.Context, _ func(capture.Frame) error) error {
	d.borrowed.Store(true)
	<-ctx.Done()
	return ctx.Err()
}

func (*borrowedProtocolDriver) Send(context.Context, []byte) error { return nil }
func (*borrowedProtocolDriver) Close() error                       { return nil }

func TestServeUsesBorrowedFrameDriverWhenAvailable(t *testing.T) {
	driver := &borrowedProtocolDriver{}
	localMAC, _ := net.ParseMAC("02:00:00:00:00:10")
	err := Serve(context.Background(), driver, localMAC,
		netip.MustParseAddr("192.168.1.10"), netip.MustParseAddr("192.168.1.1"),
		netip.MustParsePrefix("192.168.1.10/24"), nil, bytes.NewReader(nil), &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if !driver.borrowed.Load() || driver.regular.Load() {
		t.Fatalf("borrowed=%t regular=%t", driver.borrowed.Load(), driver.regular.Load())
	}
}

func TestValidateDiscoveryFrameRestrictsSenderAndOperation(t *testing.T) {
	localMAC, _ := net.ParseMAC("02:00:00:00:00:10")
	targetMAC, _ := net.ParseMAC("00:00:00:00:00:00")
	localIP := netip.MustParseAddr("192.168.1.10")
	prefix := netip.MustParsePrefix("192.168.1.10/24")
	frame, err := packet.MarshalARP(net.HardwareAddr{255, 255, 255, 255, 255, 255}, localMAC, packet.ARP{
		Operation: packet.ARPOpRequest, SenderMAC: localMAC, SenderIP: localIP,
		TargetMAC: targetMAC, TargetIP: netip.MustParseAddr("192.168.1.20"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateDiscoveryFrame(frame, localMAC, localIP, prefix); err != nil {
		t.Fatal(err)
	}
	frame[packet.EthernetHeaderLen+7] = byte(packet.ARPOpReply)
	if err := ValidateDiscoveryFrame(frame, localMAC, localIP, prefix); err == nil {
		t.Fatal("helper accepted an ARP reply")
	}
}

func TestValidateControlFrameAllowsOnlyScopedIsolationAndVerifiedRestoration(t *testing.T) {
	localMAC, _ := net.ParseMAC("02:00:00:00:00:10")
	gatewayMAC, _ := net.ParseMAC("02:00:00:00:00:01")
	targetMAC, _ := net.ParseMAC("02:00:00:00:00:20")
	localIP := netip.MustParseAddr("192.168.1.10")
	gatewayIP := netip.MustParseAddr("192.168.1.1")
	targetIP := netip.MustParseAddr("192.168.1.20")
	prefix := netip.MustParsePrefix("192.168.1.10/24")
	makeFrame := func(sender net.HardwareAddr) []byte {
		frame, err := packet.MarshalARP(targetMAC, sender, packet.ARP{
			Operation: packet.ARPOpReply, SenderMAC: sender, SenderIP: gatewayIP,
			TargetMAC: targetMAC, TargetIP: targetIP,
		})
		if err != nil {
			t.Fatal(err)
		}
		return frame
	}
	if err := ValidateControlFrame(makeFrame(localMAC), localMAC, gatewayMAC, localIP, gatewayIP, prefix); err != nil {
		t.Fatalf("isolation rejected: %v", err)
	}
	if err := ValidateControlFrame(makeFrame(gatewayMAC), localMAC, gatewayMAC, localIP, gatewayIP, prefix); err != nil {
		t.Fatalf("restoration rejected: %v", err)
	}
	unknownMAC, _ := net.ParseMAC("02:00:00:00:00:99")
	if err := ValidateControlFrame(makeFrame(unknownMAC), localMAC, gatewayMAC, localIP, gatewayIP, prefix); err == nil {
		t.Fatal("accepted an unverified control sender")
	}
}

func TestValidateIPv6DiscoveryFrameAllowsOnlyScopedSolicitations(t *testing.T) {
	localMAC, _ := net.ParseMAC("02:00:00:00:00:10")
	localIP := netip.MustParseAddr("fe80::10")
	prefixes := []netip.Prefix{netip.MustParsePrefix("fe80::10/64"), netip.MustParsePrefix("2001:db8:1::10/64")}
	makeFrame := func(target netip.Addr) []byte {
		frame, err := packet.MarshalNeighborSolicitation(packet.NeighborSolicitation{SourceIP: localIP, SourceMAC: localMAC, TargetIP: target})
		if err != nil {
			t.Fatal(err)
		}
		return frame
	}
	valid := makeFrame(netip.MustParseAddr("2001:db8:1::20"))
	if err := ValidateIPv6DiscoveryFrame(valid, localMAC, prefixes); err != nil {
		t.Fatal(err)
	}
	if err := ValidateIPv6DiscoveryFrame(makeFrame(netip.MustParseAddr("2001:db8:2::20")), localMAC, prefixes); err == nil {
		t.Fatal("accepted an off-link target")
	}
	valid[0] ^= 1
	if err := ValidateIPv6DiscoveryFrame(valid, localMAC, prefixes); err == nil {
		t.Fatal("accepted the wrong multicast MAC")
	}
	nonCanonical := append(makeFrame(netip.MustParseAddr("2001:db8:1::20")), 0)
	if err := ValidateIPv6DiscoveryFrame(nonCanonical, localMAC, prefixes); err == nil {
		t.Fatal("accepted a non-canonical solicitation")
	}
}

func tagPriorityVLAN0(frame []byte) []byte {
	tagged := make([]byte, len(frame)+packet.VLANHeaderLen)
	copy(tagged[:12], frame[:12])
	binary.BigEndian.PutUint16(tagged[12:14], packet.EtherTypeVLAN)
	binary.BigEndian.PutUint16(tagged[14:16], 0x0000)
	copy(tagged[16:], frame[12:])
	return tagged
}

func TestValidateOutboundFramesRejectPriorityTaggedARP(t *testing.T) {
	localMAC, _ := net.ParseMAC("02:00:00:00:00:10")
	gatewayMAC, _ := net.ParseMAC("02:00:00:00:00:01")
	targetMAC, _ := net.ParseMAC("02:00:00:00:00:20")
	localIP := netip.MustParseAddr("192.168.1.10")
	gatewayIP := netip.MustParseAddr("192.168.1.1")
	targetIP := netip.MustParseAddr("192.168.1.20")
	prefix := netip.MustParsePrefix("192.168.1.10/24")

	discoveryFrame, err := packet.MarshalARP(net.HardwareAddr{255, 255, 255, 255, 255, 255}, localMAC, packet.ARP{
		Operation: packet.ARPOpRequest, SenderMAC: localMAC, SenderIP: localIP,
		TargetMAC: net.HardwareAddr{0, 0, 0, 0, 0, 0}, TargetIP: targetIP,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateDiscoveryFrame(tagPriorityVLAN0(discoveryFrame), localMAC, localIP, prefix); err == nil {
		t.Fatal("helper accepted VLAN-tagged outbound discovery frame")
	}

	controlFrame, err := packet.MarshalARP(targetMAC, localMAC, packet.ARP{
		Operation: packet.ARPOpReply, SenderMAC: localMAC, SenderIP: gatewayIP,
		TargetMAC: targetMAC, TargetIP: targetIP,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateControlFrame(tagPriorityVLAN0(controlFrame), localMAC, gatewayMAC, localIP, gatewayIP, prefix); err == nil {
		t.Fatal("helper accepted VLAN-tagged outbound control frame")
	}
}

type singleFrameDriver struct {
	frame []byte
}

func (d *singleFrameDriver) Run(ctx context.Context, consume func(capture.Frame) error) error {
	if err := consume(capture.Frame{Data: d.frame}); err != nil {
		return err
	}
	<-ctx.Done()
	return ctx.Err()
}
func (*singleFrameDriver) Send(context.Context, []byte) error { return nil }
func (*singleFrameDriver) Close() error                       { return nil }

func TestServeStripsInboundPriorityTagBeforeForwardingToParent(t *testing.T) {
	localMAC, _ := net.ParseMAC("04:56:e5:fa:92:b3")
	gatewayMAC, _ := net.ParseMAC("3c:93:f4:e6:76:8b")
	localIP := netip.MustParseAddr("192.168.100.182")
	gatewayIP := netip.MustParseAddr("192.168.100.1")
	prefix := netip.MustParsePrefix("192.168.100.182/24")

	reply, err := packet.MarshalARP(localMAC, gatewayMAC, packet.ARP{
		Operation: packet.ARPOpReply, SenderMAC: gatewayMAC, SenderIP: gatewayIP,
		TargetMAC: localMAC, TargetIP: localIP,
	})
	if err != nil {
		t.Fatal(err)
	}
	inReader, inWriter := io.Pipe()
	outReader, outWriter := io.Pipe()
	driver := &singleFrameDriver{frame: tagPriorityVLAN0(reply)}
	serveErr := make(chan error, 1)
	go func() {
		defer outWriter.Close()
		serveErr <- Serve(context.Background(), driver, localMAC, localIP, gatewayIP, prefix, nil, inReader, outWriter)
	}()

	decoder := json.NewDecoder(outReader)
	var ready Message
	if err := decoder.Decode(&ready); err != nil || ready.Type != "ready" {
		t.Fatalf("unexpected first message: %#v, err=%v", ready, err)
	}
	var forwarded Message
	if err := decoder.Decode(&forwarded); err != nil || forwarded.Type != "frame" {
		t.Fatalf("expected forwarded frame message, got %#v, err=%v", forwarded, err)
	}
	if !bytes.Equal(forwarded.Data, reply) {
		t.Fatalf("forwarded frame was not stripped: got %x, want %x", forwarded.Data, reply)
	}
	_, _ = inWriter.Write([]byte("{\"type\":\"close\"}\n"))
	_ = inWriter.Close()
	if err := <-serveErr; err != nil {
		t.Fatalf("Serve returned error: %v", err)
	}
}
