//go:build !windows

package nettools

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strings"
	"time"
)

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
		rtt, probeErr := tcpLatencyProbe(ctx, addr, 1000*time.Millisecond)
		sample := PingSample{Seq: seq}
		if probeErr == nil {
			sample.Success = true
			sample.RTTMS = math.Round(rtt*100) / 100
			sample.TTL = 64
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

func TraceRoute(ctx context.Context, target string, _ int) (TraceRouteResult, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return TraceRouteResult{}, errors.New("target host or IP address is required")
	}
	addr, err := resolveTargetIPv4(ctx, target)
	if err != nil {
		return TraceRouteResult{}, err
	}
	rtt, probeErr := tcpLatencyProbe(ctx, addr, 1200*time.Millisecond)
	hop := TraceHop{
		Hop:      1,
		IP:       addr.String(),
		Hostname: quickReverseLookup(ctx, addr.String(), 300*time.Millisecond),
		RTTMS:    math.Round(rtt*100) / 100,
		Reached:  probeErr == nil,
		Timeout:  probeErr != nil,
	}
	return TraceRouteResult{
		Target:     target,
		ResolvedIP: addr.String(),
		Reached:    hop.Reached,
		Hops:       []TraceHop{hop},
	}, nil
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
