// Package metadata enriches device snapshots with user nicknames and embedded
// IEEE OUI vendor information.
package metadata

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/amdzy/NetWarden/internal/device"
)

//go:embed vendors.json
var vendorData []byte

type vendorRecord struct {
	Prefix string `json:"macPrefix"`
	Name   string `json:"vendorName"`
}

var vendorIndex struct {
	sync.Once
	values map[string]string
	err    error
}

type Resolver struct {
	mu           sync.RWMutex
	nicknames    map[string]string
	vendors      map[string]string
	hostnames    map[netip.Addr]hostnameEntry
	macHostnames map[string]hostnameEntry
	inflight     map[netip.Addr]map[string]struct{}
	lookup       func(context.Context, string) ([]string, error)
	refresh      func(string)
	ttl          time.Duration
	timeout      time.Duration
	localName    string
}

type hostnameEntry struct {
	name    string
	expires time.Time
}

func NewResolver(nicknames map[string]string) (*Resolver, error) {
	vendorIndex.Do(func() {
		var records []vendorRecord
		if err := json.Unmarshal(vendorData, &records); err != nil {
			vendorIndex.err = fmt.Errorf("decode embedded vendor database: %w", err)
			return
		}
		vendorIndex.values = make(map[string]string, len(records))
		for _, record := range records {
			prefix := normalizeHardwareAddress(record.Prefix)
			if prefix != "" && record.Name != "" {
				vendorIndex.values[prefix] = record.Name
			}
		}
	})
	if vendorIndex.err != nil {
		return nil, vendorIndex.err
	}
	copyNicknames := make(map[string]string, len(nicknames))
	for mac, nickname := range nicknames {
		copyNicknames[strings.ToLower(mac)] = nickname
	}
	localHost, _ := os.Hostname()
	return &Resolver{
		nicknames: copyNicknames, vendors: vendorIndex.values,
		hostnames: make(map[netip.Addr]hostnameEntry), macHostnames: make(map[string]hostnameEntry),
		inflight: make(map[netip.Addr]map[string]struct{}),
		lookup: lookupDeviceNames, ttl: 30 * time.Minute, timeout: 10 * time.Second,
		localName: cleanResolvedHostname(localHost),
	}, nil
}

func (r *Resolver) Enrich(snapshot device.Device) device.Metadata {
	r.mu.RLock()
	result := device.Metadata{Name: snapshot.IP.String(), Vendor: "Unknown"}
	mac := strings.ToLower(snapshot.MAC)
	nickname := r.nicknames[mac]
	now := time.Now()
	if nickname != "" {
		result.Name = nickname
	} else if snapshot.Role == device.RoleLocal && r.localName != "" {
		result.Name = r.localName
	} else if cached, ok := r.hostnames[snapshot.IP]; ok && now.Before(cached.expires) && cached.name != "" {
		result.Name = cached.name
	} else {
		for _, address := range snapshot.Addresses {
			if cached, ok := r.hostnames[address]; ok && now.Before(cached.expires) && cached.name != "" {
				result.Name = cached.name
				break
			}
		}
		if result.Name == snapshot.IP.String() {
			if cached, ok := r.macHostnames[mac]; ok && now.Before(cached.expires) && cached.name != "" {
				result.Name = cached.name
			}
		}
	}
	if normalizedMAC := normalizeHardwareAddress(mac); len(normalizedMAC) == 12 {
		result.Vendor = resolveVendor(normalizedMAC, r.vendors)
	}
	result.Type = identifyType(result.Name, result.Vendor)
	r.mu.RUnlock()
	if nickname == "" && snapshot.Role != device.RoleLocal {
		r.resolveHostname(snapshot.IP, mac)
		for _, address := range snapshot.Addresses {
			if address.Is4() && address != snapshot.IP {
				r.resolveHostname(address, mac)
			}
		}
	}
	return result
}

func resolveVendor(mac string, vendors map[string]string) string {
	if len(mac) != 12 {
		return "Unknown"
	}
	// IEEE assignments use 36-, 28-, and 24-bit prefixes. Checking the most
	// specific assignment first prevents a broad OUI from hiding MA-M/MA-S data.
	for _, length := range [...]int{9, 7, 6} {
		if vendor := vendors[mac[:length]]; vendor != "" {
			return vendor
		}
	}
	firstOctet, err := strconv.ParseUint(mac[:2], 16, 8)
	if err == nil && firstOctet&0x02 != 0 {
		return "Private / randomized"
	}
	return "Unknown"
}

func normalizeHardwareAddress(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	value = strings.NewReplacer(":", "", "-", "", ".", "").Replace(value)
	for _, character := range value {
		if !strings.ContainsRune("0123456789ABCDEF", character) {
			return ""
		}
	}
	return value
}

// SetRefresh installs the non-blocking callback used when an asynchronous
// hostname lookup changes metadata for a known MAC address.
func (r *Resolver) SetRefresh(refresh func(string)) {
	r.mu.Lock()
	r.refresh = refresh
	r.mu.Unlock()
}

// SetHostnameLookup replaces reverse DNS for tests or applications with a
// custom resolver. Lookups are deduplicated per address and cached.
func (r *Resolver) SetHostnameLookup(lookup func(string) ([]string, error), ttl time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if lookup != nil {
		r.lookup = func(_ context.Context, address string) ([]string, error) { return lookup(address) }
	}
	if ttl > 0 {
		r.ttl = ttl
	}
}

func (r *Resolver) resolveHostname(ip netip.Addr, mac string) {
	if !ip.IsValid() {
		return
	}
	r.mu.Lock()
	if cached, ok := r.hostnames[ip]; ok && time.Now().Before(cached.expires) {
		r.mu.Unlock()
		return
	}
	if waiters := r.inflight[ip]; waiters != nil {
		waiters[mac] = struct{}{}
		r.mu.Unlock()
		return
	}
	r.inflight[ip] = map[string]struct{}{mac: {}}
	lookup := r.lookup
	ttl := r.ttl
	timeout := r.timeout
	r.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		names, err := lookup(ctx, ip.String())
		name := ""
		if err == nil && len(names) > 0 {
			name = strings.TrimSuffix(strings.TrimSpace(names[0]), ".")
		}
		r.mu.Lock()
		waiters := r.inflight[ip]
		delete(r.inflight, ip)
		cacheTTL := ttl
		if name == "" && cacheTTL > 15*time.Second {
			cacheTTL = 15 * time.Second
		}
		entry := hostnameEntry{name: name, expires: time.Now().Add(cacheTTL)}
		r.hostnames[ip] = entry
		if name != "" {
			for waiter := range waiters {
				if waiter != "" {
					r.macHostnames[waiter] = entry
				}
			}
		}
		refresh := r.refresh
		r.mu.Unlock()
		if name != "" && refresh != nil {
			for waiter := range waiters {
				refresh(waiter)
			}
		}
	}()
}

func (r *Resolver) SetNickname(mac net.HardwareAddr, nickname string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nicknames[strings.ToLower(mac.String())] = nickname
}

func (r *Resolver) RemoveNickname(mac net.HardwareAddr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.nicknames, strings.ToLower(mac.String()))
}
