//go:build windows

package nettools

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var (
	iphlpapi             = syscall.NewLazyDLL("iphlpapi.dll")
	procIcmpCreateFile   = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpCloseHandle  = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho     = iphlpapi.NewProc("IcmpSendEcho")
)

const (
	ipSuccess           = 0
	ipReqTimedOut       = 11010
	ipTTLExpiredTransit = 11013
	ipTTLExpiredReassem = 11014
)

type ipOptionInformation struct {
	Ttl         uint8
	Tos         uint8
	Flags       uint8
	OptionsSize uint8
	_           [4]byte
	OptionsData uintptr
}

type icmpEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          uintptr
	Options       ipOptionInformation
}

func PingHost(ctx context.Context, target string, count int) (PingResult, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return PingResult{}, errors.New("target host or IP address is required")
	}
	if count <= 0 {
		count = 5
	}
	if count > 20 {
		count = 20
	}
	addr, err := resolveTargetIPv4(ctx, target)
	if err != nil {
		return PingResult{}, err
	}
	result := PingResult{
		Target:     target,
		ResolvedIP: addr.String(),
		Sent:       count,
		Samples:    make([]PingSample, 0, count),
	}

	var rtts []float64
	for seq := 1; seq <= count; seq++ {
		if err := ctx.Err(); err != nil {
			break
		}
		rtt, ttl, probeErr := icmpEchoOnce(ctx, addr, 64, 1200*time.Millisecond)
		if probeErr != nil {
			// Fallback to TCP connect probe if ICMP echo is blocked by host firewall.
			if tcpRTT, tcpErr := tcpLatencyProbe(ctx, addr, 800*time.Millisecond); tcpErr == nil {
				rtt = tcpRTT
				ttl = 64
				probeErr = nil
			}
		}
		sample := PingSample{Seq: seq}
		if probeErr == nil {
			sample.Success = true
			sample.RTTMS = math.Round(rtt*100) / 100
			sample.TTL = ttl
			result.Received++
			rtts = append(rtts, sample.RTTMS)
		} else {
			sample.Error = probeErr.Error()
		}
		result.Samples = append(result.Samples, sample)
		if seq < count {
			select {
			case <-ctx.Done():
			case <-time.After(220 * time.Millisecond):
			}
		}
	}
	finalizePingStats(&result, rtts)
	return result, nil
}

func TraceRoute(ctx context.Context, target string, maxHops int) (TraceRouteResult, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return TraceRouteResult{}, errors.New("target host or IP address is required")
	}
	if maxHops <= 0 {
		maxHops = 20
	}
	if maxHops > 30 {
		maxHops = 30
	}
	addr, err := resolveTargetIPv4(ctx, target)
	if err != nil {
		return TraceRouteResult{}, err
	}
	result := TraceRouteResult{
		Target:     target,
		ResolvedIP: addr.String(),
		Hops:       make([]TraceHop, 0, maxHops),
	}

	handle, _, callErr := procIcmpCreateFile.Call()
	if handle == 0 || handle == ^uintptr(0) {
		return TraceRouteResult{}, fmt.Errorf("open ICMP handle: %v", callErr)
	}
	defer procIcmpCloseHandle.Call(handle)

	rawAddr := addr.As4()
	destIP := binary.LittleEndian.Uint32(rawAddr[:])
	payload := []byte("NetWardenTrace")

	for ttl := 1; ttl <= maxHops; ttl++ {
		if err := ctx.Err(); err != nil {
			break
		}
		opts := ipOptionInformation{Ttl: uint8(ttl)}
		replyBuf := make([]byte, 256)
		start := time.Now()
		ret, _, _ := procIcmpSendEcho.Call(
			handle,
			uintptr(destIP),
			uintptr(unsafe.Pointer(&payload[0])),
			uintptr(len(payload)),
			uintptr(unsafe.Pointer(&opts)),
			uintptr(unsafe.Pointer(&replyBuf[0])),
			uintptr(len(replyBuf)),
			uintptr(800),
		)
		elapsedMS := math.Round(float64(time.Since(start).Microseconds())/10.0) / 100.0
		reply := (*icmpEchoReply)(unsafe.Pointer(&replyBuf[0]))

		hop := TraceHop{Hop: ttl}
		if ret > 0 || reply.Status == ipTTLExpiredTransit || reply.Status == ipTTLExpiredReassem || reply.Status == ipSuccess {
			var hopBytes [4]byte
			binary.LittleEndian.PutUint32(hopBytes[:], reply.Address)
			hopAddr := netip.AddrFrom4(hopBytes)
			if hopAddr.IsValid() && !hopAddr.IsUnspecified() {
				hop.IP = hopAddr.String()
				hop.RTTMS = elapsedMS
				if hop.RTTMS <= 0 && reply.RoundTripTime > 0 {
					hop.RTTMS = float64(reply.RoundTripTime)
				}
				hop.Hostname = quickReverseLookup(ctx, hop.IP, 220*time.Millisecond)
				if hopAddr == addr || reply.Status == ipSuccess {
					hop.Reached = true
				}
			} else {
				hop.Timeout = true
			}
		} else {
			hop.Timeout = true
		}
		result.Hops = append(result.Hops, hop)
		if hop.Reached {
			result.Reached = true
			break
		}
	}
	return result, nil
}

func icmpEchoOnce(ctx context.Context, addr netip.Addr, ttl uint8, timeout time.Duration) (float64, int, error) {
	if err := ctx.Err(); err != nil {
		return 0, 0, err
	}
	handle, _, callErr := procIcmpCreateFile.Call()
	if handle == 0 || handle == ^uintptr(0) {
		return 0, 0, fmt.Errorf("IcmpCreateFile: %v", callErr)
	}
	defer procIcmpCloseHandle.Call(handle)

	raw := addr.As4()
	destIP := binary.LittleEndian.Uint32(raw[:])
	payload := []byte("NetWardenPingProbe")
	opts := ipOptionInformation{Ttl: ttl}
	replyBuf := make([]byte, 256)
	timeoutMS := uint32(timeout.Milliseconds())
	if timeoutMS < 100 {
		timeoutMS = 100
	}

	start := time.Now()
	ret, _, _ := procIcmpSendEcho.Call(
		handle,
		uintptr(destIP),
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(len(payload)),
		uintptr(unsafe.Pointer(&opts)),
		uintptr(unsafe.Pointer(&replyBuf[0])),
		uintptr(len(replyBuf)),
		uintptr(timeoutMS),
	)
	elapsedMS := float64(time.Since(start).Microseconds()) / 1000.0
	if ret == 0 {
		return 0, 0, errors.New("request timed out")
	}
	reply := (*icmpEchoReply)(unsafe.Pointer(&replyBuf[0]))
	if reply.Status != ipSuccess {
		return 0, 0, fmt.Errorf("ICMP status %d", reply.Status)
	}
	if elapsedMS <= 0 && reply.RoundTripTime > 0 {
		elapsedMS = float64(reply.RoundTripTime)
	}
	replyTTL := int(reply.Options.Ttl)
	if replyTTL <= 0 {
		replyTTL = int(ttl)
	}
	return elapsedMS, replyTTL, nil
}

func resolveTargetIPv4(ctx context.Context, target string) (netip.Addr, error) {
	if addr, err := netip.ParseAddr(target); err == nil {
		if addr.Is4In6() {
			addr = addr.Unmap()
		}
		if !addr.Is4() {
			return netip.Addr{}, errors.New("please provide an IPv4 address or hostname")
		}
		return addr, nil
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(lookupCtx, "ip4", target)
	if err != nil || len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("could not resolve %q: %v", target, err)
	}
	if addr, ok := netip.AddrFromSlice(ips[0].To4()); ok {
		return addr, nil
	}
	return netip.Addr{}, fmt.Errorf("could not resolve IPv4 address for %q", target)
}
