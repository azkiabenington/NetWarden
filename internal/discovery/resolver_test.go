package discovery

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/amdzy/NetWarden/internal/capture"
	"github.com/amdzy/NetWarden/internal/packet"
)

type resolvingDriver struct {
	reply []byte
	sent  []byte
}

func (d *resolvingDriver) Send(_ context.Context, frame []byte) error {
	d.sent = append([]byte(nil), frame...)
	return nil
}
func (d *resolvingDriver) Run(_ context.Context, consume func(capture.Frame) error) error {
	return consume(capture.Frame{Data: d.reply})
}
func (d *resolvingDriver) Close() error { return nil }

func TestResolveARPReturnsMatchingReply(t *testing.T) {
	localMAC, _ := net.ParseMAC("02:00:00:00:00:10")
	gatewayMAC, _ := net.ParseMAC("02:00:00:00:00:01")
	localIP := netip.MustParseAddr("192.168.1.10")
	gatewayIP := netip.MustParseAddr("192.168.1.1")
	reply, err := packet.MarshalARP(localMAC, gatewayMAC, packet.ARP{
		Operation: packet.ARPOpReply,
		SenderMAC: gatewayMAC,
		SenderIP:  gatewayIP,
		TargetMAC: localMAC,
		TargetIP:  localIP,
	})
	if err != nil {
		t.Fatal(err)
	}
	driver := &resolvingDriver{reply: reply}
	got, err := ResolveARP(context.Background(), driver, localMAC, localIP, gatewayIP)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != gatewayMAC.String() {
		t.Fatalf("got %s, want %s", got, gatewayMAC)
	}
	request, err := packet.ParseARP(driver.sent)
	if err != nil || request.Operation != packet.ARPOpRequest || request.TargetIP != gatewayIP {
		t.Fatalf("unexpected request: %#v, %v", request, err)
	}
}

func TestResolveARPAcceptsPriorityTaggedReply(t *testing.T) {
	localMAC, _ := net.ParseMAC("04:56:e5:fa:92:b3")
	gatewayMAC, _ := net.ParseMAC("3c:93:f4:e6:76:8b")
	localIP := netip.MustParseAddr("192.168.100.182")
	gatewayIP := netip.MustParseAddr("192.168.100.1")
	reply, err := packet.MarshalARP(localMAC, gatewayMAC, packet.ARP{
		Operation: packet.ARPOpReply,
		SenderMAC: gatewayMAC,
		SenderIP:  gatewayIP,
		TargetMAC: localMAC,
		TargetIP:  localIP,
	})
	if err != nil {
		t.Fatal(err)
	}
	tagged := make([]byte, len(reply)+packet.VLANHeaderLen)
	copy(tagged[:12], reply[:12])
	binary.BigEndian.PutUint16(tagged[12:14], packet.EtherTypeVLAN)
	binary.BigEndian.PutUint16(tagged[14:16], 0x0000)
	copy(tagged[16:], reply[12:])

	driver := &resolvingDriver{reply: tagged}
	got, err := ResolveARP(context.Background(), driver, localMAC, localIP, gatewayIP)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != gatewayMAC.String() {
		t.Fatalf("got %s, want %s", got, gatewayMAC)
	}
}

type retryingResolveDriver struct {
	mu       sync.Mutex
	sends    int
	replyAt  int
	reply    []byte
	replyCh  chan []byte
}

func (d *retryingResolveDriver) Send(_ context.Context, _ []byte) error {
	d.mu.Lock()
	d.sends++
	count := d.sends
	d.mu.Unlock()
	if count >= d.replyAt {
		select {
		case d.replyCh <- d.reply:
		default:
		}
	}
	return nil
}

func (d *retryingResolveDriver) Run(ctx context.Context, consume func(capture.Frame) error) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case frame := <-d.replyCh:
			if err := consume(capture.Frame{Data: frame}); err != nil {
				return err
			}
		}
	}
}

func (*retryingResolveDriver) Close() error { return nil }

func TestResolveARPRetriesUntilReply(t *testing.T) {
	previous := arpResolveRetryInterval
	arpResolveRetryInterval = 10 * time.Millisecond
	defer func() { arpResolveRetryInterval = previous }()

	localMAC, _ := net.ParseMAC("02:00:00:00:00:10")
	gatewayMAC, _ := net.ParseMAC("02:00:00:00:00:01")
	localIP := netip.MustParseAddr("192.168.1.10")
	gatewayIP := netip.MustParseAddr("192.168.1.1")
	reply, err := packet.MarshalARP(localMAC, gatewayMAC, packet.ARP{
		Operation: packet.ARPOpReply, SenderMAC: gatewayMAC, SenderIP: gatewayIP,
		TargetMAC: localMAC, TargetIP: localIP,
	})
	if err != nil {
		t.Fatal(err)
	}
	driver := &retryingResolveDriver{replyAt: 2, reply: reply, replyCh: make(chan []byte, 1)}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := ResolveARP(ctx, driver, localMAC, localIP, gatewayIP)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != gatewayMAC.String() {
		t.Fatalf("got %s, want %s", got, gatewayMAC)
	}
	driver.mu.Lock()
	sends := driver.sends
	driver.mu.Unlock()
	if sends < 2 {
		t.Fatalf("expected retry probes, got %d sends", sends)
	}
}
