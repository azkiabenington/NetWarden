// Package nettools provides network troubleshooting and security auditing tools
// (Ping, Traceroute, Wi-Fi Scanner, Wake-on-LAN, Open Port Scanner, Router
// Vulnerability Check, Hidden Camera Detector, and Internet Outage/ISP Health).
package nettools

import "time"

type PingSample struct {
	Seq     int     `json:"seq"`
	Success bool    `json:"success"`
	RTTMS   float64 `json:"rttMs"`
	TTL     int     `json:"ttl,omitempty"`
	Error   string  `json:"error,omitempty"`
}

type PingResult struct {
	Target      string       `json:"target"`
	ResolvedIP  string       `json:"resolvedIp"`
	Sent        int          `json:"sent"`
	Received    int          `json:"received"`
	LossPercent float64      `json:"lossPercent"`
	MinMS       float64      `json:"minMs"`
	AvgMS       float64      `json:"avgMs"`
	MaxMS       float64      `json:"maxMs"`
	JitterMS    float64      `json:"jitterMs"`
	Samples     []PingSample `json:"samples"`
}

type TraceHop struct {
	Hop      int     `json:"hop"`
	IP       string  `json:"ip,omitempty"`
	Hostname string  `json:"hostname,omitempty"`
	RTTMS    float64 `json:"rttMs"`
	Reached  bool    `json:"reached"`
	Timeout  bool    `json:"timeout"`
}

type TraceRouteResult struct {
	Target     string     `json:"target"`
	ResolvedIP string     `json:"resolvedIp"`
	Reached    bool       `json:"reached"`
	Hops       []TraceHop `json:"hops"`
}

type WiFiNetwork struct {
	SSID          string `json:"ssid"`
	BSSID         string `json:"bssid"`
	Vendor        string `json:"vendor,omitempty"`
	RSSIDBm       int    `json:"rssiDbm"`
	SignalQuality int    `json:"signalQuality"`
	Channel       int    `json:"channel"`
	FrequencyMHz  int    `json:"frequencyMhz"`
	Band          string `json:"band"`
	CollisionRisk string `json:"collisionRisk"`
	SameChannelAP int    `json:"sameChannelAp"`
}

type WiFiScanResult struct {
	InterfaceName string        `json:"interfaceName"`
	ScannedAt     time.Time     `json:"scannedAt"`
	Networks      []WiFiNetwork `json:"networks"`
}

type OpenPort struct {
	Port     int     `json:"port"`
	Protocol string  `json:"protocol"`
	Service  string  `json:"service"`
	Banner   string  `json:"banner,omitempty"`
	Risk     string  `json:"risk"`
	Note     string  `json:"note,omitempty"`
	RTTMS    float64 `json:"rttMs"`
}

type PortScanResult struct {
	Target       string     `json:"target"`
	ResolvedIP   string     `json:"resolvedIp"`
	ProbedCount  int        `json:"probedCount"`
	DurationMS   int64      `json:"durationMs"`
	OpenPorts    []OpenPort `json:"openPorts"`
}

type UPnPMapping struct {
	Protocol       string `json:"protocol"`
	ExternalPort   int    `json:"externalPort"`
	InternalClient string `json:"internalClient"`
	InternalPort   int    `json:"internalPort"`
	Description    string `json:"description"`
	Enabled        bool   `json:"enabled"`
}

type RouterVulnerabilityFinding struct {
	Severity       string `json:"severity"`
	Title          string `json:"title"`
	Detail         string `json:"detail"`
	Recommendation string `json:"recommendation"`
}

type RouterVulnerabilityResult struct {
	GatewayIP       string                       `json:"gatewayIp"`
	Status          string                       `json:"status"`
	UPnPEnabled     bool                         `json:"upnpEnabled"`
	NATPMPEnabled   bool                         `json:"natPmpEnabled"`
	UPnPMappings    []UPnPMapping                `json:"upnpMappings"`
	OpenPorts       []OpenPort                   `json:"openPorts"`
	Findings        []RouterVulnerabilityFinding `json:"findings"`
}

type DeviceInput struct {
	IP     string
	MAC    string
	Name   string
	Vendor string
	Type   string
	Online bool
}

type HiddenCameraSuspect struct {
	IP         string   `json:"ip"`
	MAC        string   `json:"mac"`
	Name       string   `json:"name"`
	Vendor     string   `json:"vendor"`
	Confidence string   `json:"confidence"`
	OpenPorts  []int    `json:"openPorts"`
	Reasons    []string `json:"reasons"`
}

type HiddenCameraResult struct {
	ScannedHosts int                   `json:"scannedHosts"`
	Suspects     []HiddenCameraSuspect `json:"suspects"`
}

type ProviderBenchmark struct {
	Name        string  `json:"name"`
	Address     string  `json:"address"`
	Category    string  `json:"category"`
	Reachable   bool    `json:"reachable"`
	LatencyMS   float64 `json:"latencyMs"`
	JitterMS    float64 `json:"jitterMs"`
	LossPercent float64 `json:"lossPercent"`
	Recommended bool    `json:"recommended"`
}

type InternetHealthResult struct {
	Status          string              `json:"status"`
	Summary         string              `json:"summary"`
	PublicIP        string              `json:"publicIp,omitempty"`
	ISP             string              `json:"isp,omitempty"`
	City            string              `json:"city,omitempty"`
	Region          string              `json:"region,omitempty"`
	Country         string              `json:"country,omitempty"`
	GatewayIP       string              `json:"gatewayIp,omitempty"`
	GatewayLatency  float64             `json:"gatewayLatencyMs"`
	InternetLatency float64             `json:"internetLatencyMs"`
	OutageDetected  bool                `json:"outageDetected"`
	Providers       []ProviderBenchmark `json:"providers"`
}
