package metadata

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

var (
	ssdpCacheMu          sync.Mutex
	ssdpLastScan         time.Time
	ssdpInflight         chan struct{}
	ssdpNamesByIP        = make(map[netip.Addr]string)
	ssdpScanCooldown     = 15 * time.Second
	hostnameLookupTokens = make(chan struct{}, 8)
)

// lookupDeviceNames queries local-network name protocols concurrently (mDNS,
// NetBIOS Node Status, LLMNR, SSDP/UPnP description, and reverse DNS) and
// returns the highest-confidence human-readable device name found.
func lookupDeviceNames(ctx context.Context, address string) ([]string, error) {
	select {
	case hostnameLookupTokens <- struct{}{}:
		defer func() { <-hostnameLookupTokens }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	probeCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	ctx = probeCtx
	ip, err := netip.ParseAddr(strings.TrimSpace(address))
	if err != nil {
		return net.DefaultResolver.LookupAddr(ctx, address)
	}
	ip = ip.Unmap()

	type candidate struct {
		priority int
		name     string
	}
	results := make(chan candidate, 5)
	var wg sync.WaitGroup

	run := func(priority int, fn func(context.Context, netip.Addr) string) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if name := strings.TrimSpace(fn(ctx, ip)); name != "" {
				results <- candidate{priority: priority, name: name}
			}
		}()
	}

	run(1, lookupUPnPFriendlyName)
	run(2, lookupMDNSName)
	run(3, lookupNetBIOSName)
	run(4, lookupLLMNRName)
	run(5, func( lookupCtx context.Context, target netip.Addr) string {
		names, err := net.DefaultResolver.LookupAddr(lookupCtx, target.String())
		if err != nil || len(names) == 0 {
			return ""
		}
		return cleanResolvedHostname(names[0])
	})

	go func() {
		wg.Wait()
		close(results)
	}()

	bestPriority := 999
	bestName := ""
	for item := range results {
		if item.priority < bestPriority && item.name != "" && item.name != ip.String() {
			bestPriority = item.priority
			bestName = item.name
		}
	}
	if bestName == "" {
		return nil, nil
	}
	return []string{bestName}, nil
}

func cleanResolvedHostname(raw string) string {
	name := strings.TrimSpace(raw)
	name = strings.TrimSuffix(name, ".")
	for _, suffix := range []string{".local", ".lan", ".home", ".internal", ".localdomain"} {
		if len(name) > len(suffix) && strings.EqualFold(name[len(name)-len(suffix):], suffix) {
			name = name[:len(name)-len(suffix)]
			break
		}
	}
	// Clean Android_<32-hex> mDNS hostnames into a compact readable form.
	if strings.HasPrefix(strings.ToLower(name), "android_") && len(name) > 16 {
		suffix := name[8:]
		if isHexIdentifier(suffix) {
			return "Android (" + strings.ToLower(suffix[:4]) + ")"
		}
	}
	return strings.TrimSpace(name)
}

func isHexIdentifier(value string) bool {
	if len(value) < 8 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func lookupMDNSName(ctx context.Context, ip netip.Addr) string {
	if !ip.Is4() {
		return ""
	}
	query, err := buildIPv4PTRQuery(ip, 0x0000, 0x8001)
	if err != nil {
		return ""
	}
	return queryUDPPTR(ctx, query, []*net.UDPAddr{
		{IP: net.IP(ip.AsSlice()), Port: 5353},
		{IP: net.IPv4(224, 0, 0, 251), Port: 5353},
	}, ip)
}

func lookupLLMNRName(ctx context.Context, ip netip.Addr) string {
	if !ip.Is4() {
		return ""
	}
	query, err := buildIPv4PTRQuery(ip, 0x4e57, 0x0001)
	if err != nil {
		return ""
	}
	return queryUDPPTR(ctx, query, []*net.UDPAddr{
		{IP: net.IP(ip.AsSlice()), Port: 5355},
		{IP: net.IPv4(224, 0, 0, 252), Port: 5355},
	}, ip)
}

func buildIPv4PTRQuery(ip netip.Addr, txID, qclass uint16) ([]byte, error) {
	if !ip.Is4() {
		return nil, net.InvalidAddrError("IPv4 address required")
	}
	octets := ip.As4()
	reverseName := netip.AddrFrom4([4]byte{octets[3], octets[2], octets[1], octets[0]}).String() + ".in-addr.arpa"
	packet := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(packet[0:2], txID)
	binary.BigEndian.PutUint16(packet[2:4], 0x0000)
	binary.BigEndian.PutUint16(packet[4:6], 1) // QDCOUNT = 1
	for _, label := range strings.Split(reverseName, ".") {
		packet = append(packet, byte(len(label)))
		packet = append(packet, label...)
	}
	packet = append(packet, 0x00)
	var tail [4]byte
	binary.BigEndian.PutUint16(tail[0:2], 12) // QTYPE = PTR
	binary.BigEndian.PutUint16(tail[2:4], qclass)
	packet = append(packet, tail[:]...)
	return packet, nil
}

func localSourceIPv4For(target netip.Addr) net.IP {
	if !target.Is4() {
		return net.IPv4zero
	}
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IP(target.AsSlice()), Port: 5353})
	if err != nil {
		return net.IPv4zero
	}
	defer conn.Close()
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok && addr.IP != nil {
		return addr.IP
	}
	return net.IPv4zero
}

func queryUDPPTR(ctx context.Context, query []byte, targets []*net.UDPAddr, expectedIP netip.Addr) string {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: localSourceIPv4For(expectedIP), Port: 0})
	if err != nil {
		return ""
	}
	defer conn.Close()

	deadline := time.Now().Add(800 * time.Millisecond)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}

	octets := expectedIP.As4()
	expectedQName := strings.ToLower(netip.AddrFrom4([4]byte{octets[3], octets[2], octets[1], octets[0]}).String() + ".in-addr.arpa")
	buf := make([]byte, 1500)
	for attempt := 0; attempt < 2; attempt++ {
		if time.Now().After(deadline) {
			break
		}
		for _, target := range targets {
			_, _ = conn.WriteToUDP(query, target)
		}
		attemptDeadline := time.Now().Add(350 * time.Millisecond)
		if deadline.Before(attemptDeadline) {
			attemptDeadline = deadline
		}
		_ = conn.SetReadDeadline(attemptDeadline)
		for {
			n, sender, err := conn.ReadFromUDP(buf)
			if err != nil {
				break
			}
			qname, target, ok := parseDNSPTRResponse(buf[:n])
			if !ok {
				continue
			}
			senderIP, _ := netip.AddrFromSlice(sender.IP)
			if senderIP.Unmap() == expectedIP || strings.EqualFold(qname, expectedQName) {
				if cleaned := cleanResolvedHostname(target); cleaned != "" {
					return cleaned
				}
			}
		}
	}
	return ""
}

func parseDNSPTRResponse(packet []byte) (questionName, ptrTarget string, ok bool) {
	if len(packet) < 12 {
		return "", "", false
	}
	qdCount := int(binary.BigEndian.Uint16(packet[4:6]))
	anCount := int(binary.BigEndian.Uint16(packet[6:8]))
	if anCount == 0 {
		return "", "", false
	}
	offset := 12
	for i := 0; i < qdCount; i++ {
		_, next, valid := readDNSName(packet, offset)
		if !valid || next+4 > len(packet) {
			return "", "", false
		}
		offset = next + 4
	}
	for i := 0; i < anCount; i++ {
		name, next, valid := readDNSName(packet, offset)
		if !valid || next+10 > len(packet) {
			return "", "", false
		}
		rtype := binary.BigEndian.Uint16(packet[next : next+2])
		rdLength := int(binary.BigEndian.Uint16(packet[next+8 : next+10]))
		rdataOffset := next + 10
		if rdataOffset+rdLength > len(packet) {
			return "", "", false
		}
		if rtype == 12 { // PTR
			target, _, targetOK := readDNSName(packet, rdataOffset)
			if targetOK && target != "" {
				return name, target, true
			}
		}
		offset = rdataOffset + rdLength
	}
	return "", "", false
}

func readDNSName(packet []byte, start int) (string, int, bool) {
	var labels []string
	offset := start
	nextOffset := -1
	jumps := 0
	for {
		if offset >= len(packet) || jumps > 16 {
			return "", 0, false
		}
		length := int(packet[offset])
		if length == 0 {
			if nextOffset == -1 {
				nextOffset = offset + 1
			}
			break
		}
		if length&0xc0 == 0xc0 {
			if offset+1 >= len(packet) {
				return "", 0, false
			}
			if nextOffset == -1 {
				nextOffset = offset + 2
			}
			offset = ((length & 0x3f) << 8) | int(packet[offset+1])
			jumps++
			continue
		}
		if length&0xc0 != 0 {
			return "", 0, false
		}
		offset++
		if offset+length > len(packet) {
			return "", 0, false
		}
		labels = append(labels, string(packet[offset:offset+length]))
		offset += length
	}
	return strings.Join(labels, "."), nextOffset, true
}

func lookupNetBIOSName(ctx context.Context, ip netip.Addr) string {
	if !ip.Is4() {
		return ""
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return ""
	}
	defer conn.Close()

	deadline := time.Now().Add(650 * time.Millisecond)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)

	query := []byte(
		"\x13\x37\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" +
			"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00" +
			"\x00\x21\x00\x01",
	)
	_, err = conn.WriteToUDP(query, &net.UDPAddr{IP: net.IP(ip.AsSlice()), Port: 137})
	if err != nil {
		return ""
	}
	buf := make([]byte, 1024)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return ""
	}
	return parseNetBIOSResponse(buf[:n])
}

func parseNetBIOSResponse(packet []byte) string {
	if len(packet) < 57 {
		return ""
	}
	count := int(packet[56])
	offset := 57
	fallback := ""
	for i := 0; i < count && offset+18 <= len(packet); i++ {
		rawName := strings.TrimSpace(string(packet[offset : offset+15]))
		suffix := packet[offset+15]
		flags := binary.BigEndian.Uint16(packet[offset+16 : offset+18])
		offset += 18
		isGroup := flags&0x8000 != 0
		if isGroup || rawName == "" || strings.HasPrefix(rawName, "__") {
			continue
		}
		// 0x00 = Workstation Service, 0x20 = File Server Service.
		if suffix == 0x00 {
			return cleanPrintableASCII(rawName)
		}
		if suffix == 0x20 && fallback == "" {
			fallback = cleanPrintableASCII(rawName)
		}
	}
	return fallback
}

func cleanPrintableASCII(value string) string {
	var b strings.Builder
	for _, r := range value {
		if r >= 0x20 && r <= 0x7e {
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

func lookupUPnPFriendlyName(ctx context.Context, ip netip.Addr) string {
	if !ip.Is4() {
		return ""
	}
	ssdpCacheMu.Lock()
	if name := ssdpNamesByIP[ip]; name != "" {
		ssdpCacheMu.Unlock()
		return name
	}
	wait := ssdpInflight
	shouldScan := wait == nil && time.Since(ssdpLastScan) >= ssdpScanCooldown
	if shouldScan {
		ssdpLastScan = time.Now()
		wait = make(chan struct{})
		ssdpInflight = wait
	}
	ssdpCacheMu.Unlock()

	if shouldScan {
		discoverSSDPDescriptions(ctx, ip)
		ssdpCacheMu.Lock()
		ssdpInflight = nil
		close(wait)
		name := ssdpNamesByIP[ip]
		ssdpCacheMu.Unlock()
		return name
	}
	if wait != nil {
		select {
		case <-wait:
		case <-ctx.Done():
			return ""
		}
	}
	ssdpCacheMu.Lock()
	defer ssdpCacheMu.Unlock()
	return ssdpNamesByIP[ip]
}

func discoverSSDPDescriptions(ctx context.Context, targetIP netip.Addr) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: localSourceIPv4For(targetIP), Port: 0})
	if err != nil {
		return
	}
	defer conn.Close()

	deadline := time.Now().Add(700 * time.Millisecond)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)

	request := []byte(
		"M-SEARCH * HTTP/1.1\r\n" +
			"HOST: 239.255.255.250:1900\r\n" +
			"MAN: \"ssdp:discover\"\r\n" +
			"MX: 1\r\n" +
			"ST: ssdp:all\r\n\r\n",
	)
	_, _ = conn.WriteToUDP(request, &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 1900})

	locations := make(map[netip.Addr]string)
	buf := make([]byte, 2048)
	for {
		n, sender, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		senderIP, ok := netip.AddrFromSlice(sender.IP)
		if !ok {
			continue
		}
		senderIP = senderIP.Unmap()
		if _, exists := locations[senderIP]; exists {
			continue
		}
		if loc := extractSSDPLocation(string(buf[:n])); loc != "" {
			locations[senderIP] = loc
		}
	}

	for hostIP, location := range locations {
		if name := fetchUPnPFriendlyName(ctx, hostIP, location); name != "" {
			ssdpCacheMu.Lock()
			ssdpNamesByIP[hostIP] = name
			ssdpCacheMu.Unlock()
		}
	}
}

func extractSSDPLocation(response string) string {
	for _, line := range strings.Split(response, "\n") {
		line = strings.TrimSpace(line)
		if len(line) > 9 && strings.EqualFold(line[:9], "LOCATION:") {
			return strings.TrimSpace(line[9:])
		}
	}
	return ""
}

func fetchUPnPFriendlyName(ctx context.Context, expectedIP netip.Addr, location string) string {
	parsed, err := url.Parse(location)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return ""
	}
	host := parsed.Hostname()
	if locIP, err := netip.ParseAddr(host); err != nil || locIP.Unmap() != expectedIP {
		return ""
	}
	fetchCtx, cancel := context.WithTimeout(ctx, 900*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, location, nil)
	if err != nil {
		return ""
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return ""
	}
	return parseUPnPDeviceXML(body)
}

func parseUPnPDeviceXML(data []byte) string {
	type upnpDevice struct {
		FriendlyName string `xml:"device>friendlyName"`
		ModelName    string `xml:"device>modelName"`
	}
	var root upnpDevice
	if err := xml.Unmarshal(data, &root); err == nil {
		if name := strings.TrimSpace(root.FriendlyName); name != "" {
			return name
		}
		if model := strings.TrimSpace(root.ModelName); model != "" {
			return model
		}
	}
	return ""
}
