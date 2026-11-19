package nettools

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type portServiceInfo struct {
	Service string
	Risk    string
	Note    string
}

var knownPortCatalog = map[int]portServiceInfo{
	21:    {Service: "FTP", Risk: "high", Note: "Unencrypted file transfer protocol"},
	22:    {Service: "SSH", Risk: "info", Note: "Secure Shell remote administration"},
	23:    {Service: "Telnet", Risk: "high", Note: "Insecure cleartext remote shell"},
	25:    {Service: "SMTP", Risk: "warning", Note: "Mail transfer service"},
	53:    {Service: "DNS", Risk: "info", Note: "Domain Name System resolver"},
	80:    {Service: "HTTP", Risk: "info", Note: "Unencrypted web interface"},
	81:    {Service: "HTTP-Alt / Camera Web", Risk: "warning", Note: "Alternative web / IP camera interface"},
	88:    {Service: "Kerberos / Camera Web", Risk: "info", Note: "Authentication or embedded web UI"},
	110:   {Service: "POP3", Risk: "warning", Note: "Cleartext mail retrieval"},
	135:   {Service: "MS-RPC", Risk: "warning", Note: "Windows RPC endpoint mapper"},
	139:   {Service: "NetBIOS-SSN", Risk: "warning", Note: "Legacy Windows file & printer sharing"},
	143:   {Service: "IMAP", Risk: "info", Note: "Mail access service"},
	443:   {Service: "HTTPS", Risk: "info", Note: "Encrypted web interface"},
	445:   {Service: "SMB", Risk: "warning", Note: "Server Message Block file sharing"},
	548:   {Service: "AFP", Risk: "info", Note: "Apple Filing Protocol"},
	554:   {Service: "RTSP", Risk: "warning", Note: "Real-Time Streaming Protocol (IP Camera / Media)"},
	631:   {Service: "IPP / CUPS", Risk: "info", Note: "Network printer service"},
	1883:  {Service: "MQTT", Risk: "warning", Note: "Unencrypted IoT message broker"},
	1900:  {Service: "UPnP", Risk: "warning", Note: "Universal Plug and Play discovery"},
	1935:  {Service: "RTMP", Risk: "warning", Note: "Live video streaming service"},
	3306:  {Service: "MySQL", Risk: "high", Note: "Database port exposed to network"},
	3389:  {Service: "RDP", Risk: "warning", Note: "Windows Remote Desktop"},
	5000:  {Service: "UPnP / Synology / Flask", Risk: "info", Note: "Management or UPnP HTTP endpoint"},
	5353:  {Service: "mDNS", Risk: "info", Note: "Multicast DNS service"},
	5432:  {Service: "PostgreSQL", Risk: "high", Note: "Database port exposed to network"},
	5555:  {Service: "Android ADB", Risk: "high", Note: "Unauthenticated remote Android debug bridge"},
	5900:  {Service: "VNC", Risk: "high", Note: "Remote desktop frame buffer"},
	6379:  {Service: "Redis", Risk: "high", Note: "In-memory data store exposed to network"},
	6668:  {Service: "Tuya IoT", Risk: "info", Note: "Tuya local smart-home control channel"},
	7547:  {Service: "TR-069 CWMP", Risk: "high", Note: "ISP remote router management port"},
	8000:  {Service: "HTTP-Alt / Hikvision", Risk: "warning", Note: "IP camera SDK or alternative web server"},
	8008:  {Service: "Google Cast", Risk: "info", Note: "Chromecast / Smart TV control"},
	8009:  {Service: "Google Cast TLS", Risk: "info", Note: "Chromecast media control"},
	8080:  {Service: "HTTP-Proxy / Admin", Risk: "warning", Note: "Alternative web administration interface"},
	8081:  {Service: "HTTP-Camera / Stream", Risk: "warning", Note: "MJPEG stream or alternative web service"},
	8291:  {Service: "MikroTik Winbox", Risk: "warning", Note: "Router management interface"},
	8443:  {Service: "HTTPS-Alt", Risk: "info", Note: "Encrypted alternative administration UI"},
	8554:  {Service: "RTSP-Alt", Risk: "warning", Note: "Alternative RTSP video stream"},
	8883:  {Service: "MQTT-TLS", Risk: "info", Note: "Encrypted IoT message broker"},
	8899:  {Service: "ONVIF", Risk: "warning", Note: "ONVIF IP camera control service"},
	9000:  {Service: "Web / Dev / Media", Risk: "info", Note: "Application or camera service port"},
	9100:  {Service: "JetDirect Printer", Risk: "warning", Note: "Raw network printing port"},
	34567: {Service: "Xiongmai IP Camera", Risk: "warning", Note: "DVR / IP camera proprietary control port"},
	37777: {Service: "Dahua DVR/IPC", Risk: "warning", Note: "Dahua surveillance control port"},
	49152: {Service: "UPnP IGD", Risk: "warning", Note: "UPnP SOAP control endpoint"},
	62078: {Service: "Apple iDevice Sync", Risk: "info", Note: "iOS lockdownd pairing service"},
}

var defaultScanPorts = []int{
	21, 22, 23, 25, 53, 80, 81, 88, 110, 135, 139, 143, 443, 445, 548, 554, 631,
	1883, 1935, 3306, 3389, 5000, 5432, 5555, 5900, 6379, 6668, 7547, 8000, 8008,
	8009, 8080, 8081, 8291, 8443, 8554, 8883, 8899, 9000, 9100, 34567, 37777, 49152, 62078,
}

func BuildWakeOnLANPacket(mac net.HardwareAddr) ([]byte, error) {
	if len(mac) != 6 {
		return nil, fmt.Errorf("expected a 6-byte MAC address, got %d bytes", len(mac))
	}
	packet := make([]byte, 102)
	for i := 0; i < 6; i++ {
		packet[i] = 0xFF
	}
	for copyIdx := 0; copyIdx < 16; copyIdx++ {
		copy(packet[6+copyIdx*6:], mac)
	}
	return packet, nil
}

func SendWakeOnLAN(macText, targetIP string) error {
	mac, err := net.ParseMAC(strings.TrimSpace(macText))
	if err != nil {
		return fmt.Errorf("invalid MAC address %q: %w", macText, err)
	}
	payload, err := BuildWakeOnLANPacket(mac)
	if err != nil {
		return err
	}

	destinations := []string{"255.255.255.255:9", "255.255.255.255:7"}
	if addr, parseErr := netip.ParseAddr(strings.TrimSpace(targetIP)); parseErr == nil && addr.Is4() {
		raw := addr.As4()
		directed := netip.AddrFrom4([4]byte{raw[0], raw[1], raw[2], 255})
		destinations = append(destinations, directed.String()+":9", directed.String()+":7")
	}

	var sent int
	var lastErr error
	for _, dest := range destinations {
		conn, dialErr := net.DialTimeout("udp4", dest, 1500*time.Millisecond)
		if dialErr != nil {
			lastErr = dialErr
			continue
		}
		_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
		if _, writeErr := conn.Write(payload); writeErr == nil {
			sent++
		} else {
			lastErr = writeErr
		}
		_ = conn.Close()
	}
	if sent == 0 {
		if lastErr != nil {
			return fmt.Errorf("send Wake-on-LAN magic packet: %w", lastErr)
		}
		return errors.New("could not send Wake-on-LAN magic packet")
	}
	return nil
}

func ScanPorts(ctx context.Context, target, preset string) (PortScanResult, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return PortScanResult{}, errors.New("target host or IP address is required")
	}
	addr, err := resolveTargetIPv4(ctx, target)
	if err != nil {
		return PortScanResult{}, err
	}
	ports := selectPortPreset(preset)
	started := time.Now()

	type jobResult struct {
		open OpenPort
		ok   bool
	}

	sem := make(chan struct{}, 24)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var openPorts []OpenPort

	for _, port := range ports {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			if open, ok := probeTCPPort(ctx, addr, p, 450*time.Millisecond); ok {
				mu.Lock()
				openPorts = append(openPorts, open)
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()

	sort.Slice(openPorts, func(i, j int) bool { return openPorts[i].Port < openPorts[j].Port })
	return PortScanResult{
		Target:      target,
		ResolvedIP:  addr.String(),
		ProbedCount: len(ports),
		DurationMS:  time.Since(started).Milliseconds(),
		OpenPorts:   openPorts,
	}, nil
}

func selectPortPreset(preset string) []int {
	switch strings.ToLower(strings.TrimSpace(preset)) {
	case "web":
		return []int{80, 81, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9000}
	case "camera":
		return []int{80, 81, 88, 443, 554, 1935, 5000, 8000, 8080, 8081, 8554, 8899, 9000, 34567, 37777}
	case "admin":
		return []int{21, 22, 23, 53, 80, 135, 139, 443, 445, 3306, 3389, 5432, 5555, 5900, 6379, 7547, 8080, 8291, 8443}
	default:
		return defaultScanPorts
	}
}

func probeTCPPort(ctx context.Context, addr netip.Addr, port int, timeout time.Duration) (OpenPort, bool) {
	dialer := net.Dialer{Timeout: timeout}
	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp4", net.JoinHostPort(addr.String(), strconv.Itoa(port)))
	if err != nil {
		return OpenPort{}, false
	}
	defer conn.Close()
	rtt := math.Round(float64(time.Since(start).Microseconds())/10.0) / 100.0

	meta, ok := knownPortCatalog[port]
	if !ok {
		meta = portServiceInfo{Service: "TCP Service", Risk: "info"}
	}

	banner := grabShortBanner(conn, port)
	return OpenPort{
		Port:     port,
		Protocol: "tcp",
		Service:  meta.Service,
		Banner:   banner,
		Risk:     meta.Risk,
		Note:     meta.Note,
		RTTMS:    rtt,
	}, true
}

func grabShortBanner(conn net.Conn, port int) string {
	_ = conn.SetDeadline(time.Now().Add(250 * time.Millisecond))
	if port == 80 || port == 81 || port == 8000 || port == 8080 || port == 8081 || port == 5000 {
		_, _ = io.WriteString(conn, "HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
	}
	reader := bufio.NewReader(conn)
	for range 5 {
		line, err := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line != "" {
			if strings.HasPrefix(strings.ToLower(line), "server:") {
				return strings.TrimSpace(line[7:])
			}
			if !strings.HasPrefix(strings.ToUpper(line), "HTTP/") {
				if len(line) > 72 {
					line = line[:72]
				}
				return line
			}
		}
		if err != nil {
			break
		}
	}
	return ""
}

func CheckRouterVulnerabilities(ctx context.Context, gatewayIP string) (RouterVulnerabilityResult, error) {
	gatewayIP = strings.TrimSpace(gatewayIP)
	if gatewayIP == "" {
		return RouterVulnerabilityResult{}, errors.New("gateway IP address is required")
	}
	addr, err := resolveTargetIPv4(ctx, gatewayIP)
	if err != nil {
		return RouterVulnerabilityResult{}, err
	}

	routerPorts := []int{21, 22, 23, 53, 80, 443, 445, 1900, 5000, 7547, 8080, 8291, 8443, 49152}
	var openPorts []OpenPort
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, port := range routerPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			if open, ok := probeTCPPort(ctx, addr, p, 450*time.Millisecond); ok {
				mu.Lock()
				openPorts = append(openPorts, open)
				mu.Unlock()
			}
		}(port)
	}

	upnpEnabled, mappings := checkUPnPIGD(ctx, addr)
	natPmpEnabled := checkNATPMP(ctx, addr)
	wg.Wait()
	sort.Slice(openPorts, func(i, j int) bool { return openPorts[i].Port < openPorts[j].Port })

	var findings []RouterVulnerabilityFinding
	status := "Secure"

	if upnpEnabled {
		status = "Warning"
		detail := "Router responds to UPnP Internet Gateway Device (IGD) discovery."
		if len(mappings) > 0 {
			status = "Vulnerable"
			detail = fmt.Sprintf("UPnP IGD is active with %d external port forwarding rule(s) exposed.", len(mappings))
		}
		findings = append(findings, RouterVulnerabilityFinding{
			Severity:       "warning",
			Title:          "UPnP automatic port forwarding enabled",
			Detail:         detail,
			Recommendation: "Disable UPnP in your router administration settings unless explicitly required by gaming consoles.",
		})
	}

	if natPmpEnabled {
		if status == "Secure" {
			status = "Warning"
		}
		findings = append(findings, RouterVulnerabilityFinding{
			Severity:       "warning",
			Title:          "NAT-PMP / PCP port mapping active (UDP 5351)",
			Detail:         "Router accepts NAT-PMP requests that allow local applications to open external WAN ports without authentication.",
			Recommendation: "Disable NAT-PMP / UPnP port mapping if you do not need automatic port forwarding.",
		})
	}

	for _, open := range openPorts {
		switch open.Port {
		case 23:
			status = "Vulnerable"
			findings = append(findings, RouterVulnerabilityFinding{
				Severity:       "high",
				Title:          "Telnet management service exposed (TCP 23)",
				Detail:         "Router accepts unencrypted Telnet logins, exposing administrator credentials in cleartext.",
				Recommendation: "Disable Telnet immediately and use HTTPS or SSH for router administration.",
			})
		case 21:
			status = "Vulnerable"
			findings = append(findings, RouterVulnerabilityFinding{
				Severity:       "high",
				Title:          "FTP file service exposed on gateway (TCP 21)",
				Detail:         "Router USB/storage FTP server is reachable without transport encryption.",
				Recommendation: "Disable router FTP sharing if unused.",
			})
		case 7547:
			if status == "Secure" {
				status = "Warning"
			}
			findings = append(findings, RouterVulnerabilityFinding{
				Severity:       "warning",
				Title:          "TR-069 CWMP management port open (TCP 7547)",
				Detail:         "ISP remote provisioning port (TCP 7547) is listening on the gateway.",
				Recommendation: "Ensure TCP 7547 is firewalled from untrusted networks and router firmware is up to date.",
			})
		case 445:
			if status == "Secure" {
				status = "Warning"
			}
			findings = append(findings, RouterVulnerabilityFinding{
				Severity:       "warning",
				Title:          "SMB file sharing active on router (TCP 445)",
				Detail:         "Router network storage share is exposed over SMB.",
				Recommendation: "Require strong password authentication on router USB/SMB shares or disable if unused.",
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, RouterVulnerabilityFinding{
			Severity:       "info",
			Title:          "No high-risk UPnP, NAT-PMP, or legacy services detected",
			Detail:         "Gateway did not expose unencrypted Telnet, FTP, NAT-PMP, or external UPnP port mappings.",
			Recommendation: "Keep router firmware updated and use a strong administrator password.",
		})
	}

	return RouterVulnerabilityResult{
		GatewayIP:     addr.String(),
		Status:        status,
		UPnPEnabled:   upnpEnabled,
		NATPMPEnabled: natPmpEnabled,
		UPnPMappings:  mappings,
		OpenPorts:     openPorts,
		Findings:      findings,
	}, nil
}

var upnpControlURLPattern = regexp.MustCompile(`(?is)<serviceType>\s*(urn:schemas-upnp-org:service:WAN(?:IP|PPP)Connection:\d+)\s*</serviceType>.*?<controlURL>\s*([^<\s]+)\s*</controlURL>`)

func checkUPnPIGD(ctx context.Context, gatewayAddr netip.Addr) (bool, []UPnPMapping) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return false, nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(900 * time.Millisecond))

	request := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 1\r\n" +
		"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"

	_, _ = conn.WriteToUDP([]byte(request), &net.UDPAddr{IP: gatewayAddr.AsSlice(), Port: 1900})
	_, _ = conn.WriteToUDP([]byte(request), &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 1900})

	var location string
	buf := make([]byte, 2048)
	for {
		n, from, readErr := conn.ReadFromUDP(buf)
		if readErr != nil {
			break
		}
		if from == nil || from.IP.String() != gatewayAddr.String() {
			continue
		}
		for _, line := range strings.Split(string(buf[:n]), "\n") {
			line = strings.TrimSpace(line)
			if len(line) > 9 && strings.EqualFold(line[:9], "location:") {
				location = strings.TrimSpace(line[9:])
				break
			}
		}
		if location != "" {
			break
		}
	}
	if location == "" {
		return false, nil
	}

	client := &http.Client{Timeout: 1000 * time.Millisecond}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		return true, nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return true, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	_ = resp.Body.Close()

	match := upnpControlURLPattern.FindStringSubmatch(string(body))
	if len(match) < 3 {
		return true, nil
	}
	return true, nil
}

func checkNATPMP(_ context.Context, gatewayAddr netip.Addr) bool {
	conn, err := net.DialTimeout("udp4", net.JoinHostPort(gatewayAddr.String(), "5351"), 500*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	// NAT-PMP external address request: version 0, opcode 0
	if _, err := conn.Write([]byte{0x00, 0x00}); err != nil {
		return false
	}
	reply := make([]byte, 16)
	n, err := conn.Read(reply)
	return err == nil && n >= 12 && reply[1] == 128 && reply[2] == 0 && reply[3] == 0
}

var cameraVendorKeywords = []string{
	"hikvision", "dahua", "axis", "reolink", "wyze", "ezviz", "amcrest",
	"foscam", "uniview", "hanwha", "arlo", "ring", "vivotek", "mobotix",
	"altobeam", "ai-link", "espressif", "tuya", "gaoshengda", "bazz",
}

var cameraNameKeywords = []string{
	"cam", "ipc", "ipcam", "rtsp", "onvif", "dvr", "nvr", "cctv",
	"tapo", "ezviz", "reolink", "hikvision", "dahua", "wyze",
}

var cameraPorts = []int{554, 8554, 8000, 8899, 34567, 37777, 1935, 81, 8081, 80}

func DetectHiddenCameras(ctx context.Context, devices []DeviceInput) (HiddenCameraResult, error) {
	var suspects []HiddenCameraSuspect
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)

	for _, dev := range devices {
		ipAddr, err := netip.ParseAddr(strings.TrimSpace(dev.IP))
		if err != nil || !ipAddr.Is4() {
			continue
		}
		wg.Add(1)
		go func(item DeviceInput, addr netip.Addr) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			suspect, ok := evaluateCameraCandidate(ctx, item, addr)
			if ok {
				mu.Lock()
				suspects = append(suspects, suspect)
				mu.Unlock()
			}
		}(dev, ipAddr)
	}
	wg.Wait()

	sort.Slice(suspects, func(i, j int) bool {
		rank := func(c string) int {
			switch c {
			case "High":
				return 3
			case "Medium":
				return 2
			default:
				return 1
			}
		}
		if rank(suspects[i].Confidence) != rank(suspects[j].Confidence) {
			return rank(suspects[i].Confidence) > rank(suspects[j].Confidence)
		}
		return suspects[i].IP < suspects[j].IP
	})

	return HiddenCameraResult{
		ScannedHosts: len(devices),
		Suspects:     suspects,
	}, nil
}

func evaluateCameraCandidate(ctx context.Context, dev DeviceInput, addr netip.Addr) (HiddenCameraSuspect, bool) {
	var reasons []string
	var openCameraPorts []int
	score := 0

	vendorLower := strings.ToLower(dev.Vendor)
	for _, kw := range cameraVendorKeywords {
		if strings.Contains(vendorLower, kw) {
			if kw == "altobeam" || kw == "ai-link" || kw == "espressif" || kw == "tuya" || kw == "gaoshengda" {
				score += 1
				reasons = append(reasons, fmt.Sprintf("Embedded IoT/Camera Wi-Fi module (%s)", dev.Vendor))
			} else {
				score += 3
				reasons = append(reasons, fmt.Sprintf("Camera manufacturer OUI (%s)", dev.Vendor))
			}
			break
		}
	}

	nameLower := strings.ToLower(dev.Name + " " + dev.Type)
	for _, kw := range cameraNameKeywords {
		if strings.Contains(nameLower, kw) {
			score += 2
			reasons = append(reasons, fmt.Sprintf("Camera identifier in device name/type (%s)", dev.Name))
			break
		}
	}

	if dev.Online {
		for _, port := range cameraPorts {
			if _, ok := probeTCPPort(ctx, addr, port, 280*time.Millisecond); ok {
				openCameraPorts = append(openCameraPorts, port)
				switch port {
				case 554, 8554:
					score += 4
					reasons = append(reasons, fmt.Sprintf("RTSP live video streaming port %d open", port))
				case 8899, 8000, 34567, 37777:
					score += 4
					reasons = append(reasons, fmt.Sprintf("IP camera control/ONVIF port %d open", port))
				case 1935:
					score += 3
					reasons = append(reasons, "RTMP video stream port 1935 open")
				case 81, 8081:
					score += 2
					reasons = append(reasons, fmt.Sprintf("Alternative camera web stream port %d open", port))
				}
			}
		}
	}

	if score == 0 {
		return HiddenCameraSuspect{}, false
	}
	confidence := "Low"
	if score >= 4 {
		confidence = "High"
	} else if score >= 2 {
		confidence = "Medium"
	}

	return HiddenCameraSuspect{
		IP:         dev.IP,
		MAC:        dev.MAC,
		Name:       dev.Name,
		Vendor:     dev.Vendor,
		Confidence: confidence,
		OpenPorts:  openCameraPorts,
		Reasons:    reasons,
	}, true
}

func CheckInternetHealth(ctx context.Context, gatewayIP string) (InternetHealthResult, error) {
	targets := []struct {
		name     string
		address  string
		category string
	}{
		{name: "Cloudflare DNS", address: "1.1.1.1", category: "Global Anycast DNS"},
		{name: "Google Public DNS", address: "8.8.8.8", category: "Global Anycast DNS"},
		{name: "Quad9 Security DNS", address: "9.9.9.9", category: "Threat-Blocking DNS"},
		{name: "Cisco OpenDNS", address: "208.67.222.222", category: "Filtered Anycast DNS"},
	}

	type ipInfoResponse struct {
		IP      string `json:"ip"`
		Org     string `json:"org"`
		City    string `json:"city"`
		Region  string `json:"region"`
		Country string `json:"country"`
	}

	var info ipInfoResponse
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		reqCtx, cancel := context.WithTimeout(ctx, 3500*time.Millisecond)
		defer cancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, "https://ipinfo.io/json", nil)
		if err != nil {
			return
		}
		req.Header.Set("User-Agent", "NetWarden/2.3")
		resp, err := (&http.Client{Timeout: 3500 * time.Millisecond}).Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		_ = json.NewDecoder(io.LimitReader(resp.Body, 8192)).Decode(&info)
	}()

	var gatewayLatency float64
	if strings.TrimSpace(gatewayIP) != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if res, err := PingHost(ctx, gatewayIP, 3); err == nil && res.Received > 0 {
				gatewayLatency = res.AvgMS
			}
		}()
	}

	benchmarks := make([]ProviderBenchmark, len(targets))
	for idx, item := range targets {
		wg.Add(1)
		go func(i int, name, address, category string) {
			defer wg.Done()
			res, err := PingHost(ctx, address, 3)
			bm := ProviderBenchmark{
				Name:     name,
				Address:  address,
				Category: category,
			}
			if err == nil && res.Received > 0 {
				bm.Reachable = true
				bm.LatencyMS = res.AvgMS
				bm.JitterMS = res.JitterMS
				bm.LossPercent = res.LossPercent
			} else {
				bm.LossPercent = 100
			}
			benchmarks[i] = bm
		}(idx, item.name, item.address, item.category)
	}
	wg.Wait()

	sort.Slice(benchmarks, func(i, j int) bool {
		if benchmarks[i].Reachable != benchmarks[j].Reachable {
			return benchmarks[i].Reachable
		}
		return benchmarks[i].LatencyMS < benchmarks[j].LatencyMS
	})

	reachableCount := 0
	var sumLatency float64
	for i := range benchmarks {
		if benchmarks[i].Reachable {
			if reachableCount == 0 {
				benchmarks[i].Recommended = true
			}
			reachableCount++
			sumLatency += benchmarks[i].LatencyMS
		}
	}

	var internetLatency float64
	if reachableCount > 0 {
		internetLatency = math.Round((sumLatency/float64(reachableCount))*100) / 100
	}

	status := "Healthy"
	summary := "Internet connection and upstream DNS providers are reachable with normal latency."
	outage := false

	if reachableCount == 0 {
		status = "Outage Detected"
		outage = true
		if gatewayLatency > 0 {
			summary = "Local router is reachable, but all upstream internet backbone providers failed to respond (ISP outage)."
		} else {
			summary = "Neither local gateway nor internet providers responded. Check local Wi-Fi or Ethernet connection."
		}
	} else if reachableCount < len(benchmarks) || internetLatency > 180 {
		status = "Degraded"
		summary = "Partial packet loss or elevated upstream transit latency detected across internet providers."
	}

	return InternetHealthResult{
		Status:          status,
		Summary:         summary,
		PublicIP:        info.IP,
		ISP:             info.Org,
		City:            info.City,
		Region:          info.Region,
		Country:         info.Country,
		GatewayIP:       gatewayIP,
		GatewayLatency:  gatewayLatency,
		InternetLatency: internetLatency,
		OutageDetected:  outage,
		Providers:       benchmarks,
	}, nil
}

func FrequencyToChannel(freqMHz int) (int, string) {
	switch {
	case freqMHz == 2484:
		return 14, "2.4 GHz"
	case freqMHz >= 2412 && freqMHz <= 2472:
		return (freqMHz - 2407) / 5, "2.4 GHz"
	case freqMHz >= 5170 && freqMHz <= 5885:
		return (freqMHz - 5000) / 5, "5 GHz"
	case freqMHz >= 5955 && freqMHz <= 7115:
		return (freqMHz - 5950) / 5, "6 GHz"
	default:
		return 0, "Unknown"
	}
}

func EvaluateCollisionRisk(band string, sameChannelCount int, rssiDBm int) string {
	if band == "2.4 GHz" {
		if sameChannelCount >= 4 || (sameChannelCount >= 3 && rssiDBm > -72) {
			return "High"
		}
		if sameChannelCount >= 2 {
			return "Medium"
		}
		return "Low"
	}
	if sameChannelCount >= 4 {
		return "High"
	}
	if sameChannelCount >= 2 {
		return "Medium"
	}
	return "Low"
}

var freqDigitsPattern = regexp.MustCompile(`(\d{4})`)

func parseNMCLIWiFiOutput(raw string, vendorLookup func(net.HardwareAddr) string) []WiFiNetwork {
	var networks []WiFiNetwork
	channelCounts := make(map[int]int)

	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Format with -e no: SSID:AA:BB:CC:DD:EE:FF:CHAN:FREQ:SIGNAL
		parts := strings.Split(line, ":")
		if len(parts) < 9 {
			continue
		}
		signalStr := strings.TrimSpace(parts[len(parts)-1])
		freqStr := strings.TrimSpace(parts[len(parts)-2])
		chanStr := strings.TrimSpace(parts[len(parts)-3])
		bssidParts := parts[len(parts)-9 : len(parts)-3]
		ssid := strings.TrimSpace(strings.Join(parts[:len(parts)-9], ":"))
		if ssid == "" {
			ssid = "(Hidden Network)"
		}

		bssidRaw := strings.ToLower(strings.Join(bssidParts, ":"))
		mac, err := net.ParseMAC(bssidRaw)
		if err != nil {
			continue
		}
		vendor := ""
		if vendorLookup != nil {
			vendor = vendorLookup(mac)
		}

		channel, _ := strconv.Atoi(chanStr)
		freqMHz := 0
		if m := freqDigitsPattern.FindStringSubmatch(freqStr); len(m) > 1 {
			freqMHz, _ = strconv.Atoi(m[1])
		}
		computedChan, band := FrequencyToChannel(freqMHz)
		if channel == 0 {
			channel = computedChan
		}
		if band == "Unknown" {
			if channel >= 1 && channel <= 14 {
				band = "2.4 GHz"
				if freqMHz == 0 {
					if channel == 14 {
						freqMHz = 2484
					} else {
						freqMHz = 2407 + channel*5
					}
				}
			} else if channel >= 32 {
				band = "5 GHz"
				if freqMHz == 0 {
					freqMHz = 5000 + channel*5
				}
			}
		}

		quality, _ := strconv.Atoi(signalStr)
		quality = max(0, min(100, quality))
		rssi := (quality / 2) - 100

		channelCounts[channel]++
		networks = append(networks, WiFiNetwork{
			SSID:          ssid,
			BSSID:         mac.String(),
			Vendor:        vendor,
			RSSIDBm:       rssi,
			SignalQuality: quality,
			Channel:       channel,
			FrequencyMHz:  freqMHz,
			Band:          band,
		})
	}

	for i := range networks {
		same := channelCounts[networks[i].Channel]
		networks[i].SameChannelAP = same
		networks[i].CollisionRisk = EvaluateCollisionRisk(networks[i].Band, same, networks[i].RSSIDBm)
	}

	sort.Slice(networks, func(i, j int) bool {
		if networks[i].RSSIDBm != networks[j].RSSIDBm {
			return networks[i].RSSIDBm > networks[j].RSSIDBm
		}
		return networks[i].SSID < networks[j].SSID
	})
	return networks
}

func finalizePingStats(result *PingResult, rtts []float64) {
	if result.Sent > 0 {
		result.LossPercent = math.Round(float64(result.Sent-result.Received)/float64(result.Sent)*10000) / 100
	}
	if len(rtts) == 0 {
		return
	}
	minV, maxV, sum := rtts[0], rtts[0], 0.0
	var jitterSum float64
	for i, v := range rtts {
		if v < minV {
			minV = v
		}
		if v > maxV {
			maxV = v
		}
		sum += v
		if i > 0 {
			jitterSum += math.Abs(v - rtts[i-1])
		}
	}
	result.MinMS = math.Round(minV*100) / 100
	result.MaxMS = math.Round(maxV*100) / 100
	result.AvgMS = math.Round((sum/float64(len(rtts)))*100) / 100
	if len(rtts) > 1 {
		result.JitterMS = math.Round((jitterSum/float64(len(rtts)-1))*100) / 100
	}
}

func tcpLatencyProbe(ctx context.Context, addr netip.Addr, timeout time.Duration) (float64, error) {
	for _, port := range []int{80, 443, 53, 22, 445, 139, 8080} {
		dialer := net.Dialer{Timeout: timeout}
		start := time.Now()
		conn, err := dialer.DialContext(ctx, "tcp4", net.JoinHostPort(addr.String(), strconv.Itoa(port)))
		elapsed := float64(time.Since(start).Microseconds()) / 1000.0
		if err == nil {
			_ = conn.Close()
			return elapsed, nil
		}
		// A TCP RST ("connection refused") proves the host is alive on the LAN and gives accurate RTT!
		errLower := strings.ToLower(err.Error())
		if strings.Contains(errLower, "refused") || strings.Contains(errLower, " actively refused") {
			return elapsed, nil
		}
	}
	return 0, errors.New("request timed out")
}

func quickReverseLookup(ctx context.Context, ip string, timeout time.Duration) string {
	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(lookupCtx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(strings.TrimSpace(names[0]), ".")
}

var _ = bytes.Compare
