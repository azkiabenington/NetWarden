//go:build !windows

package nettools

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var (
	pingTimePattern = regexp.MustCompile(`(?i)time[=<]([\d.]+)\s*ms`)
	pingTTLPattern  = regexp.MustCompile(`(?i)ttl=(\d+)`)
	hopFromPattern  = regexp.MustCompile(`(?i)from\s+(\d{1,3}(?:\.\d{1,3}){3})`)
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
		rtt, ttl, probeErr := unixPingOnce(ctx, addr, 64, 1200*time.Millisecond)
		if probeErr != nil {
			if tcpRTT, tcpErr := tcpLatencyProbe(ctx, addr, 900*time.Millisecond); tcpErr == nil {
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

	pingPath, lookErr := exec.LookPath("ping")
	if lookErr != nil {
		rtt, probeErr := tcpLatencyProbe(ctx, addr, 1200*time.Millisecond)
		hop := TraceHop{
			Hop:      1,
			IP:       addr.String(),
			Hostname: quickReverseLookup(ctx, addr.String(), 300*time.Millisecond),
			RTTMS:    math.Round(rtt*100) / 100,
			Reached:  probeErr == nil,
			Timeout:  probeErr != nil,
		}
		result.Reached = hop.Reached
		result.Hops = append(result.Hops, hop)
		return result, nil
	}

	ttlFlag := "-t"
	if runtime.GOOS == "darwin" {
		ttlFlag = "-m"
	}

	for ttl := 1; ttl <= maxHops; ttl++ {
		if ctx.Err() != nil {
			break
		}
		hopCtx, cancel := context.WithTimeout(ctx, 1200*time.Millisecond)
		start := time.Now()
		out, cmdErr := exec.CommandContext(hopCtx, pingPath, "-n", "-c", "1", "-W", "1", ttlFlag, strconv.Itoa(ttl), addr.String()).CombinedOutput()
		elapsedMS := math.Round(float64(time.Since(start).Microseconds())/10.0) / 100.0
		cancel()

		text := string(out)
		hop := TraceHop{Hop: ttl}
		if match := hopFromPattern.FindStringSubmatch(text); len(match) > 1 {
			hop.IP = match[1]
			hop.RTTMS = elapsedMS
			if tm := pingTimePattern.FindStringSubmatch(text); len(tm) > 1 {
				if parsed, parseErr := strconv.ParseFloat(tm[1], 64); parseErr == nil {
					hop.RTTMS = math.Round(parsed*100) / 100
				}
			}
			hop.Hostname = quickReverseLookup(ctx, hop.IP, 220*time.Millisecond)
			if hop.IP == addr.String() && cmdErr == nil {
				hop.Reached = true
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

func unixPingOnce(ctx context.Context, addr netip.Addr, ttl int, timeout time.Duration) (float64, int, error) {
	pingPath, err := exec.LookPath("ping")
	if err != nil {
		return 0, 0, err
	}
	cmdCtx, cancel := context.WithTimeout(ctx, timeout+300*time.Millisecond)
	defer cancel()
	start := time.Now()
	out, err := exec.CommandContext(cmdCtx, pingPath, "-n", "-c", "1", "-W", "1", addr.String()).CombinedOutput()
	elapsedMS := float64(time.Since(start).Microseconds()) / 1000.0
	if err != nil {
		return 0, 0, errors.New("request timed out")
	}
	text := string(out)
	if tm := pingTimePattern.FindStringSubmatch(text); len(tm) > 1 {
		if parsed, parseErr := strconv.ParseFloat(tm[1], 64); parseErr == nil {
			elapsedMS = parsed
		}
	}
	replyTTL := ttl
	if ttlm := pingTTLPattern.FindStringSubmatch(text); len(ttlm) > 1 {
		if parsedTTL, parseErr := strconv.Atoi(ttlm[1]); parseErr == nil {
			replyTTL = parsedTTL
		}
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
