package metadata

import (
	"strings"

	"github.com/amdzy/NetWarden/internal/device"
)

// identifyType uses only strong hostname and vendor signals. Ambiguous vendors
// (for example Apple, Samsung, and Google) intentionally remain unknown unless
// the hostname provides a more specific clue.
func identifyType(name, vendor string) device.Type {
	name = strings.ToLower(name)
	vendor = strings.ToLower(vendor)

	for _, rule := range typeRules {
		for _, signal := range rule.names {
			if strings.Contains(name, signal) {
				return rule.deviceType
			}
		}
	}
	for _, rule := range typeRules {
		for _, signal := range rule.vendors {
			if strings.Contains(vendor, signal) {
				return rule.deviceType
			}
		}
	}
	return device.TypeUnknown
}

var typeRules = []struct {
	deviceType device.Type
	names      []string
	vendors    []string
}{
	{device.TypePrinter, []string{"printer", "laserjet", "officejet", "deskjet", "photosmart", "epson", "brn", "brw"}, []string{"hewlett packard", "brother industries", "lexmark", "seiko epson", "canon inc."}},
	{device.TypePhone, []string{"iphone", "android", "galaxy-s", "galaxy-a", "galaxy-m", "pixel-", "oneplus", "redmi", "poco-", "oppo-", "vivo-", "realme"}, nil},
	{device.TypeTablet, []string{"ipad", "tablet", "galaxy-tab", "kindle"}, nil},
	{device.TypeTV, []string{"smart-tv", "smarttv", "appletv", "apple-tv", "chromecast", "firetv", "fire-tv", "roku", "bravia", "webos", "tizen", "androidtv", "android-tv"}, []string{"roku", "vizio", "hisense", "tcl king"}},
	{device.TypeGameConsole, []string{"xbox", "playstation", "ps4", "ps5", "nintendo", "switch"}, []string{"nintendo co.", "sony interactive entertainment"}},
	{device.TypeSpeaker, []string{"homepod", "sonos", "echo-", "google-home", "nest-audio"}, []string{"sonos"}},
	{device.TypeCamera, []string{"camera", "cam-", "doorbell", "ring-", "arlo", "ipcam", "ipc-", "hikvision", "ezviz"}, []string{"arlo technologies", "ring llc", "hikvision", "dahua", "ezviz"}},
	{device.TypeNetwork, []string{"router", "gateway", "access-point", "accesspoint", "unifi", "deco-", "archer", "extender", "repeater", "mikrotik", "openwrt"}, []string{"ubiquiti", "netgear", "tp-link", "mikrotik", "aruba networks"}},
	{device.TypeComputer, []string{"macbook", "imac", "desktop", "laptop", "workstation", "raspberrypi", "raspberry-pi", "thinkpad", "surface", "zenbook", "ideapad"}, []string{"raspberry pi"}},
	{device.TypeSmartHome, []string{"thermostat", "smartplug", "smart-plug", "lightbulb", "light-bulb", "yeelight", "sonoff", "tuya", "tapo"}, []string{"espressif", "tuya", "shelly", "ai-link", "altobeam", "broadlink", "yeelink"}},
}
