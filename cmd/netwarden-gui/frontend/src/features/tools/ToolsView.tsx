import { useState } from "react"
import {
  Activity,
  Camera,
  ChevronRight,
  Globe,
  LoaderCircle,
  LockOpen,
  Play,
  Power,
  Radio,
  Route,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Zap,
} from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useDevices } from "@/features/devices/devices.queries"
import { cn } from "@/lib/utils"
import {
  useCheckInternetHealth,
  useCheckRouterVulnerabilities,
  useDetectHiddenCameras,
  usePingHost,
  useScanPorts,
  useScanWiFi,
  useTraceRoute,
  useWakeOnLAN,
} from "./tools.queries"

type ToolID =
  | "ping"
  | "traceroute"
  | "wifi"
  | "wol"
  | "ports"
  | "router"
  | "camera"
  | "internet"

type ToolDefinition = {
  id: ToolID
  category: "troubleshoot" | "security"
  title: string
  description: string
  accent: string
  icon: typeof Activity
}

const toolCatalog: ToolDefinition[] = [
  {
    id: "ping",
    category: "troubleshoot",
    title: "Ping",
    description: "Visualize network round-trip time to reach devices, servers and web domains.",
    accent: "bg-blue-500/15 text-blue-400 border-blue-500/30",
    icon: Activity,
  },
  {
    id: "traceroute",
    category: "troubleshoot",
    title: "Trace route",
    description: "Display the path and measure the transit delays of packets across a network.",
    accent: "bg-blue-500/15 text-blue-400 border-blue-500/30",
    icon: Route,
  },
  {
    id: "wifi",
    category: "troubleshoot",
    title: "Wi-Fi Scanner",
    description: "Scan nearby Wireless Access Points to display signal strength and likelihood of collisions.",
    accent: "bg-blue-500/15 text-blue-400 border-blue-500/30",
    icon: Radio,
  },
  {
    id: "wol",
    category: "troubleshoot",
    title: "Wake on LAN",
    description: "Wake up devices that have been set up to receive Wake-On-LAN packets.",
    accent: "bg-blue-500/15 text-blue-400 border-blue-500/30",
    icon: Power,
  },
  {
    id: "ports",
    category: "security",
    title: "Find open ports",
    description: "Probe a server or host for open ports to verify security policies of a network.",
    accent: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
    icon: LockOpen,
  },
  {
    id: "router",
    category: "security",
    title: "Router vulnerability check",
    description: "Find and fix open ports via UPnP and NAT-PMP that may lead to external access.",
    accent: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
    icon: ShieldAlert,
  },
  {
    id: "camera",
    category: "security",
    title: "Find hidden camera",
    description: "Detect hidden cameras in the current network via OUI, RTSP, ONVIF, and streaming signatures.",
    accent: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
    icon: Camera,
  },
  {
    id: "internet",
    category: "security",
    title: "Internet outages & Compare providers",
    description: "Look for ongoing internet outages, inspect your ISP, and benchmark the fastest DNS providers in your area.",
    accent: "bg-indigo-500/15 text-indigo-400 border-indigo-500/30",
    icon: Zap,
  },
]

export function ToolsView() {
  const [activeTool, setActiveTool] = useState<ToolID>("ping")
  const troubleshootTools = toolCatalog.filter((t) => t.category === "troubleshoot")
  const securityTools = toolCatalog.filter((t) => t.category === "security")

  return (
    <section className="space-y-6 py-7 sm:py-9">
      <div>
        <p className="mb-2 text-[10px] font-semibold tracking-[.18em] text-primary uppercase">
          Diagnostics & Security Suite
        </p>
        <h2 className="text-2xl font-semibold tracking-tight">Network Tools</h2>
        <p className="mt-2 text-sm text-muted-foreground">
          Troubleshoot latency and Wi-Fi channels, wake sleeping hosts, audit open ports, check router UPnP/NAT-PMP exposure, and detect hidden cameras.
        </p>
      </div>

      <div className="grid gap-6 lg:grid-cols-[380px_1fr]">
        <div className="space-y-5">
          <div className="space-y-2.5">
            <h3 className="px-1 text-xs font-semibold tracking-wide text-muted-foreground uppercase">
              Troubleshoot your network
            </h3>
            <div className="space-y-2">
              {troubleshootTools.map((tool) => (
                <ToolMenuCard
                  key={tool.id}
                  tool={tool}
                  active={activeTool === tool.id}
                  onSelect={() => setActiveTool(tool.id)}
                />
              ))}
            </div>
          </div>

          <div className="space-y-2.5">
            <h3 className="px-1 text-xs font-semibold tracking-wide text-muted-foreground uppercase">
              Improve your network security & ISP
            </h3>
            <div className="space-y-2">
              {securityTools.map((tool) => (
                <ToolMenuCard
                  key={tool.id}
                  tool={tool}
                  active={activeTool === tool.id}
                  onSelect={() => setActiveTool(tool.id)}
                />
              ))}
            </div>
          </div>
        </div>

        <div className="min-w-0">
          {activeTool === "ping" && <PingWorkspace />}
          {activeTool === "traceroute" && <TraceRouteWorkspace />}
          {activeTool === "wifi" && <WiFiScannerWorkspace />}
          {activeTool === "wol" && <WakeOnLANWorkspace />}
          {activeTool === "ports" && <OpenPortsWorkspace />}
          {activeTool === "router" && <RouterVulnerabilityWorkspace />}
          {activeTool === "camera" && <HiddenCameraWorkspace />}
          {activeTool === "internet" && <InternetHealthWorkspace />}
        </div>
      </div>
    </section>
  )
}

function ToolMenuCard({
  tool,
  active,
  onSelect,
}: {
  tool: ToolDefinition
  active: boolean
  onSelect: () => void
}) {
  const Icon = tool.icon
  return (
    <button
      type="button"
      onClick={onSelect}
      className={cn(
        "flex w-full items-center gap-3.5 rounded-xl border p-3.5 text-left transition-colors focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none",
        active
          ? "border-primary/50 bg-accent/80 shadow-sm"
          : "border-border/60 bg-card/60 hover:bg-accent/40",
      )}
    >
      <span className={cn("grid size-10 shrink-0 place-items-center rounded-xl border", tool.accent)}>
        <Icon className="size-5" />
      </span>
      <div className="min-w-0 flex-1">
        <p className="text-sm font-semibold">{tool.title}</p>
        <p className="mt-0.5 line-clamp-2 text-xs leading-relaxed text-muted-foreground">{tool.description}</p>
      </div>
      <ChevronRight className={cn("size-4 shrink-0 text-muted-foreground", active && "text-primary")} />
    </button>
  )
}

function PingWorkspace() {
  const { data: devices = [] } = useDevices()
  const [target, setTarget] = useState("1.1.1.1")
  const [count, setCount] = useState(5)
  const ping = usePingHost()

  return (
    <Card className="bg-card/60">
      <CardHeader className="border-b">
        <CardTitle>Ping</CardTitle>
        <CardDescription>
          Visualize network round-trip time (RTT), packet loss, and jitter to reach local devices, servers, or web domains.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6 py-6">
        <div className="grid gap-3 sm:grid-cols-[1fr_180px_110px_auto]">
          <div className="space-y-1.5">
            <Label htmlFor="ping-target">Host or IP address</Label>
            <Input
              id="ping-target"
              placeholder="e.g. 192.168.100.1, 1.1.1.1, google.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="ping-device-preset">Or pick LAN device</Label>
            <NativeSelect
              id="ping-device-preset"
              className="w-full"
              value=""
              onChange={(e) => {
                if (e.target.value) setTarget(e.target.value)
              }}
            >
              <NativeSelectOption value="">Select device…</NativeSelectOption>
              {devices.map((d) => (
                <NativeSelectOption key={d.mac} value={d.ip}>
                  {d.name || d.ip} ({d.ip})
                </NativeSelectOption>
              ))}
            </NativeSelect>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="ping-count">Probes</Label>
            <NativeSelect
              id="ping-count"
              className="w-full"
              value={count}
              onChange={(e) => setCount(Number(e.target.value))}
            >
              <NativeSelectOption value={4}>4 probes</NativeSelectOption>
              <NativeSelectOption value={5}>5 probes</NativeSelectOption>
              <NativeSelectOption value={10}>10 probes</NativeSelectOption>
            </NativeSelect>
          </div>
          <div className="flex items-end">
            <Button
              type="button"
              className="w-full"
              disabled={ping.isPending || !target.trim()}
              onClick={() => ping.mutate({ target: target.trim(), count })}
            >
              {ping.isPending ? <LoaderCircle className="animate-spin" /> : <Play />}
              Run Ping
            </Button>
          </div>
        </div>

        {ping.data && (
          <div className="space-y-5">
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <StatBox label="Average RTT" value={`${ping.data.avgMs} ms`} sub={`Resolved: ${ping.data.resolvedIp}`} />
              <StatBox label="Min / Max" value={`${ping.data.minMs} / ${ping.data.maxMs} ms`} />
              <StatBox label="Jitter" value={`${ping.data.jitterMs} ms`} />
              <StatBox
                label="Packet Loss"
                value={`${ping.data.lossPercent}%`}
                sub={`${ping.data.received}/${ping.data.sent} received`}
              />
            </div>

            <div className="rounded-lg border bg-background/30 p-4">
              <p className="mb-3 text-xs font-medium text-muted-foreground">Round-Trip Time (ms)</p>
              <div className="flex h-28 items-end gap-2">
                {ping.data.samples.map((s) => {
                  const maxRTT = Math.max(1, ping.data.maxMs)
                  const pct = s.success ? Math.max(12, Math.round((s.rttMs / maxRTT) * 100)) : 100
                  return (
                    <div key={s.seq} className="flex flex-1 flex-col items-center gap-1.5">
                      <span className="font-mono text-[10px] text-muted-foreground">
                        {s.success ? `${s.rttMs}ms` : "Loss"}
                      </span>
                      <div className="flex h-16 w-full items-end rounded bg-muted/40 p-0.5">
                        <div
                          className={cn(
                            "w-full rounded-sm transition-all",
                            s.success ? "bg-primary" : "bg-destructive/60",
                          )}
                          style={{ height: `${pct}%` }}
                        />
                      </div>
                      <span className="text-[10px] text-muted-foreground">#{s.seq}</span>
                    </div>
                  )
                })}
              </div>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

function TraceRouteWorkspace() {
  const { data: devices = [] } = useDevices()
  const [target, setTarget] = useState("1.1.1.1")
  const trace = useTraceRoute()

  return (
    <Card className="bg-card/60">
      <CardHeader className="border-b">
        <CardTitle>Trace route</CardTitle>
        <CardDescription>
          Display the hop-by-hop network path and measure transit delays across routers.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6 py-6">
        <div className="grid gap-3 sm:grid-cols-[1fr_200px_auto]">
          <div className="space-y-1.5">
            <Label htmlFor="trace-target">Destination host or IP</Label>
            <Input
              id="trace-target"
              placeholder="e.g. 1.1.1.1, 8.8.8.8, google.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="trace-device-preset">Or pick LAN device</Label>
            <NativeSelect
              id="trace-device-preset"
              className="w-full"
              value=""
              onChange={(e) => {
                if (e.target.value) setTarget(e.target.value)
              }}
            >
              <NativeSelectOption value="">Select device…</NativeSelectOption>
              {devices.map((d) => (
                <NativeSelectOption key={d.mac} value={d.ip}>
                  {d.name || d.ip} ({d.ip})
                </NativeSelectOption>
              ))}
            </NativeSelect>
          </div>
          <div className="flex items-end">
            <Button
              type="button"
              className="w-full"
              disabled={trace.isPending || !target.trim()}
              onClick={() => trace.mutate({ target: target.trim(), maxHops: 20 })}
            >
              {trace.isPending ? <LoaderCircle className="animate-spin" /> : <Route />}
              Trace Route
            </Button>
          </div>
        </div>

        {trace.data && (
          <div className="space-y-3">
            <div className="flex items-center justify-between text-xs text-muted-foreground">
              <span>
                Target: <strong className="text-foreground">{trace.data.target}</strong> ({trace.data.resolvedIp})
              </span>
              <Badge variant={trace.data.reached ? "default" : "secondary"}>
                {trace.data.reached ? `Destination reached in ${trace.data.hops.length} hops` : `${trace.data.hops.length} hops probed`}
              </Badge>
            </div>
            <div className="overflow-x-auto rounded-lg border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-16">Hop</TableHead>
                    <TableHead>Router IP</TableHead>
                    <TableHead>Hostname</TableHead>
                    <TableHead>Transit Delay</TableHead>
                    <TableHead>Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {trace.data.hops.map((hop) => (
                    <TableRow key={hop.hop}>
                      <TableCell className="font-mono text-xs">#{hop.hop}</TableCell>
                      <TableCell className="font-mono text-xs">{hop.ip || "* * *"}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{hop.hostname || "—"}</TableCell>
                      <TableCell className="font-mono text-xs">
                        {hop.timeout ? "Timed out" : `${hop.rttMs} ms`}
                      </TableCell>
                      <TableCell>
                        <Badge variant={hop.reached ? "default" : hop.timeout ? "secondary" : "outline"}>
                          {hop.reached ? "Destination" : hop.timeout ? "No reply" : "Transit hop"}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

function WiFiScannerWorkspace() {
  const wifi = useScanWiFi()
  const networks = wifi.data?.networks || []
  const count24 = networks.filter((n) => n.band === "2.4 GHz").length
  const count5 = networks.filter((n) => n.band !== "2.4 GHz").length

  return (
    <Card className="bg-card/60">
      <CardHeader className="flex-row items-center justify-between border-b">
        <div>
          <CardTitle>Wi-Fi Scanner</CardTitle>
          <CardDescription>
            Scan nearby Wireless Access Points to display signal strength (dBm), channel usage, and likelihood of collisions.
          </CardDescription>
        </div>
        <Button type="button" disabled={wifi.isPending} onClick={() => wifi.mutate()}>
          {wifi.isPending ? <LoaderCircle className="animate-spin" /> : <Radio />}
          Scan Nearby Wi-Fi
        </Button>
      </CardHeader>
      <CardContent className="space-y-5 py-6">
        {wifi.data ? (
          <>
            <div className="grid grid-cols-3 gap-3">
              <StatBox label="Access Points Found" value={String(networks.length)} sub={wifi.data.interfaceName} />
              <StatBox label="2.4 GHz Band" value={`${count24} APs`} sub="Channels 1–14" />
              <StatBox label="5 GHz / 6 GHz Band" value={`${count5} APs`} sub="High-capacity channels" />
            </div>
            <div className="overflow-x-auto rounded-lg border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>SSID</TableHead>
                    <TableHead>BSSID & Vendor</TableHead>
                    <TableHead>Signal</TableHead>
                    <TableHead>Channel & Band</TableHead>
                    <TableHead>Collision Likelihood</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {networks.map((net) => (
                    <TableRow key={`${net.bssid}-${net.channel}`}>
                      <TableCell className="font-medium">{net.ssid}</TableCell>
                      <TableCell>
                        <p className="font-mono text-xs">{net.bssid}</p>
                        <p className="text-[11px] text-muted-foreground">{net.vendor || "Unknown"}</p>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs">{net.rssiDbm} dBm</span>
                          <Badge variant="outline" className="text-[10px]">
                            {net.signalQuality}%
                          </Badge>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1.5">
                          <Badge variant="secondary">Ch {net.channel}</Badge>
                          <span className="text-xs text-muted-foreground">
                            {net.band} ({net.frequencyMhz} MHz)
                          </span>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant={
                            net.collisionRisk === "High"
                              ? "destructive"
                              : net.collisionRisk === "Medium"
                                ? "default"
                                : "outline"
                          }
                        >
                          {net.collisionRisk} ({net.sameChannelAp} AP{net.sameChannelAp === 1 ? "" : "s"} on Ch {net.channel})
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </>
        ) : (
          <div className="py-12 text-center text-sm text-muted-foreground">
            Click <strong>Scan Nearby Wi-Fi</strong> to inspect nearby Wireless Access Points, RSSI signal levels, and channel collisions.
          </div>
        )}
      </CardContent>
    </Card>
  )
}

function WakeOnLANWorkspace() {
  const { data: devices = [] } = useDevices()
  const [mac, setMac] = useState("")
  const [ip, setIp] = useState("")
  const wol = useWakeOnLAN()
  const peerDevices = devices.filter((d) => d.role === "Device")

  return (
    <Card className="bg-card/60">
      <CardHeader className="border-b">
        <CardTitle>Wake on LAN</CardTitle>
        <CardDescription>
          Send IEEE 802 Magic Packets (UDP ports 9 & 7) to wake sleeping computers and servers on your local network.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6 py-6">
        <div className="grid gap-3 sm:grid-cols-[1fr_180px_200px_auto]">
          <div className="space-y-1.5">
            <Label htmlFor="wol-mac">Target MAC address</Label>
            <Input
              id="wol-mac"
              className="font-mono"
              placeholder="00:11:22:33:44:55"
              value={mac}
              onChange={(e) => setMac(e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="wol-ip">Subnet IP (optional)</Label>
            <Input
              id="wol-ip"
              className="font-mono"
              placeholder="192.168.100.255"
              value={ip}
              onChange={(e) => setIp(e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="wol-preset">Pick known device</Label>
            <NativeSelect
              id="wol-preset"
              className="w-full"
              value=""
              onChange={(e) => {
                const chosen = peerDevices.find((d) => d.mac === e.target.value)
                if (chosen) {
                  setMac(chosen.mac)
                  setIp(chosen.ip)
                }
              }}
            >
              <NativeSelectOption value="">Select device…</NativeSelectOption>
              {peerDevices.map((d) => (
                <NativeSelectOption key={d.mac} value={d.mac}>
                  {d.name || d.ip} ({d.online ? "Online" : "Offline"})
                </NativeSelectOption>
              ))}
            </NativeSelect>
          </div>
          <div className="flex items-end">
            <Button
              type="button"
              className="w-full"
              disabled={wol.isPending || !mac.trim()}
              onClick={() => wol.mutate({ mac: mac.trim(), targetIP: ip.trim() })}
            >
              {wol.isPending ? <LoaderCircle className="animate-spin" /> : <Power />}
              Wake Device
            </Button>
          </div>
        </div>

        {peerDevices.length > 0 && (
          <div className="space-y-2">
            <p className="text-xs font-medium text-muted-foreground">Quick Wake Known Devices</p>
            <div className="grid gap-2 sm:grid-cols-2">
              {peerDevices.slice(0, 8).map((d) => (
                <div key={d.mac} className="flex items-center justify-between rounded-lg border bg-background/30 p-3">
                  <div className="min-w-0">
                    <p className="truncate text-xs font-medium">{d.name || d.ip}</p>
                    <p className="font-mono text-[10px] text-muted-foreground">
                      {d.ip} · {d.mac}
                    </p>
                  </div>
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    disabled={wol.isPending}
                    onClick={() => wol.mutate({ mac: d.mac, targetIP: d.ip })}
                  >
                    <Power className="size-3.5" />
                    Wake
                  </Button>
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

function OpenPortsWorkspace() {
  const { data: devices = [] } = useDevices()
  const [target, setTarget] = useState("192.168.100.1")
  const [preset, setPreset] = useState("common")
  const scan = useScanPorts()

  return (
    <Card className="bg-card/60">
      <CardHeader className="border-b">
        <CardTitle>Find open ports</CardTitle>
        <CardDescription>
          Probe a server or host for open TCP ports, grab service banners, and verify security policies on your network.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6 py-6">
        <div className="grid gap-3 sm:grid-cols-[1fr_180px_170px_auto]">
          <div className="space-y-1.5">
            <Label htmlFor="port-target">Target host or IP</Label>
            <Input
              id="port-target"
              placeholder="e.g. 192.168.100.1"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="port-device">Or pick LAN device</Label>
            <NativeSelect
              id="port-device"
              className="w-full"
              value=""
              onChange={(e) => {
                if (e.target.value) setTarget(e.target.value)
              }}
            >
              <NativeSelectOption value="">Select device…</NativeSelectOption>
              {devices.map((d) => (
                <NativeSelectOption key={d.mac} value={d.ip}>
                  {d.name || d.ip} ({d.ip})
                </NativeSelectOption>
              ))}
            </NativeSelect>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="port-preset">Scan profile</Label>
            <NativeSelect
              id="port-preset"
              className="w-full"
              value={preset}
              onChange={(e) => setPreset(e.target.value)}
            >
              <NativeSelectOption value="common">All Common (44 ports)</NativeSelectOption>
              <NativeSelectOption value="web">Web & HTTP Services</NativeSelectOption>
              <NativeSelectOption value="admin">Admin, DB & Shares</NativeSelectOption>
              <NativeSelectOption value="camera">Camera / RTSP / ONVIF</NativeSelectOption>
            </NativeSelect>
          </div>
          <div className="flex items-end">
            <Button
              type="button"
              className="w-full"
              disabled={scan.isPending || !target.trim()}
              onClick={() => scan.mutate({ target: target.trim(), preset })}
            >
              {scan.isPending ? <LoaderCircle className="animate-spin" /> : <LockOpen />}
              Scan Ports
            </Button>
          </div>
        </div>

        {scan.data && (
          <div className="space-y-4">
            <div className="flex items-center justify-between text-xs text-muted-foreground">
              <span>
                Scanned <strong className="text-foreground">{scan.data.probedCount} TCP ports</strong> on{" "}
                <strong className="text-foreground">{scan.data.resolvedIp}</strong> in {scan.data.durationMs} ms
              </span>
              <Badge variant={scan.data.openPorts.length > 0 ? "default" : "secondary"}>
                {scan.data.openPorts.length} open port{scan.data.openPorts.length === 1 ? "" : "s"}
              </Badge>
            </div>
            {scan.data.openPorts.length > 0 ? (
              <div className="overflow-x-auto rounded-lg border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Port</TableHead>
                      <TableHead>Service</TableHead>
                      <TableHead>Banner / Details</TableHead>
                      <TableHead>Latency</TableHead>
                      <TableHead>Security Risk</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {scan.data.openPorts.map((item) => (
                      <TableRow key={item.port}>
                        <TableCell className="font-mono text-xs font-semibold">
                          {item.port}/{item.protocol}
                        </TableCell>
                        <TableCell className="text-xs font-medium">{item.service}</TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          {item.banner ? <span className="font-mono">{item.banner}</span> : item.note || "Open"}
                        </TableCell>
                        <TableCell className="font-mono text-xs">{item.rttMs} ms</TableCell>
                        <TableCell>
                          <Badge
                            variant={
                              item.risk === "high"
                                ? "destructive"
                                : item.risk === "warning"
                                  ? "default"
                                  : "outline"
                            }
                          >
                            {item.risk.toUpperCase()}
                          </Badge>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            ) : (
              <div className="rounded-lg border bg-background/30 py-8 text-center text-xs text-muted-foreground">
                No open TCP ports detected on {scan.data.resolvedIp} for this scan profile.
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  )
}

function RouterVulnerabilityWorkspace() {
  const check = useCheckRouterVulnerabilities()

  return (
    <Card className="bg-card/60">
      <CardHeader className="flex-row items-center justify-between border-b">
        <div>
          <CardTitle>Router vulnerability check</CardTitle>
          <CardDescription>
            Audit your default gateway for UPnP IGD port forwarding, NAT-PMP exposure, and insecure management services (Telnet, FTP, TR-069).
          </CardDescription>
        </div>
        <Button type="button" disabled={check.isPending} onClick={() => check.mutate()}>
          {check.isPending ? <LoaderCircle className="animate-spin" /> : <ShieldAlert />}
          Run Router Check
        </Button>
      </CardHeader>
      <CardContent className="space-y-5 py-6">
        {check.data ? (
          <>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <StatBox label="Gateway IP" value={check.data.gatewayIp} />
              <StatBox label="Security Status" value={check.data.status} />
              <StatBox label="UPnP IGD" value={check.data.upnpEnabled ? "Enabled" : "Disabled"} />
              <StatBox label="NAT-PMP (UDP 5351)" value={check.data.natPmpEnabled ? "Enabled" : "Disabled"} />
            </div>

            <div className="space-y-3">
              <h4 className="text-xs font-semibold tracking-wide text-muted-foreground uppercase">
                Security Findings & Recommendations
              </h4>
              {check.data.findings.map((f, idx) => (
                <div key={idx} className="space-y-1.5 rounded-lg border bg-background/30 p-4">
                  <div className="flex items-center justify-between gap-2">
                    <p className="text-sm font-medium">{f.title}</p>
                    <Badge
                      variant={
                        f.severity === "high"
                          ? "destructive"
                          : f.severity === "warning"
                            ? "default"
                            : "outline"
                      }
                    >
                      {f.severity.toUpperCase()}
                    </Badge>
                  </div>
                  <p className="text-xs text-muted-foreground">{f.detail}</p>
                  <p className="text-xs text-primary">Recommendation: {f.recommendation}</p>
                </div>
              ))}
            </div>

            {check.data.openPorts.length > 0 && (
              <div className="space-y-2">
                <h4 className="text-xs font-semibold tracking-wide text-muted-foreground uppercase">
                  Listening Gateway Services ({check.data.openPorts.length})
                </h4>
                <div className="flex flex-wrap gap-2">
                  {check.data.openPorts.map((p) => (
                    <Badge key={p.port} variant="secondary" className="font-mono text-xs">
                      {p.port}/tcp · {p.service}
                    </Badge>
                  ))}
                </div>
              </div>
            )}
          </>
        ) : (
          <div className="py-12 text-center text-sm text-muted-foreground">
            Click <strong>Run Router Check</strong> to test your gateway for UPnP, NAT-PMP, TR-069, Telnet, FTP, and exposed administrative ports.
          </div>
        )}
      </CardContent>
    </Card>
  )
}

function HiddenCameraWorkspace() {
  const scan = useDetectHiddenCameras()

  return (
    <Card className="bg-card/60">
      <CardHeader className="flex-row items-center justify-between border-b">
        <div>
          <CardTitle>Find hidden camera</CardTitle>
          <CardDescription>
            Scan all discovered hosts on the current network for IP camera manufacturers, RTSP/RTMP video streams, and ONVIF/DVR control ports.
          </CardDescription>
        </div>
        <Button type="button" disabled={scan.isPending} onClick={() => scan.mutate()}>
          {scan.isPending ? <LoaderCircle className="animate-spin" /> : <Camera />}
          Scan for Cameras
        </Button>
      </CardHeader>
      <CardContent className="space-y-5 py-6">
        {scan.data ? (
          <>
            <div className="flex items-center justify-between rounded-lg border bg-background/30 p-4">
              <div>
                <p className="text-sm font-medium">
                  Scanned {scan.data.scannedHosts} network host{scan.data.scannedHosts === 1 ? "" : "s"}
                </p>
                <p className="text-xs text-muted-foreground">
                  Checked OUI hardware signatures and active RTSP (554/8554), ONVIF (8899), Hikvision (8000), Dahua (37777), Xiongmai (34567), and RTMP (1935) ports.
                </p>
              </div>
              <Badge variant={scan.data.suspects.length > 0 ? "default" : "outline"}>
                {scan.data.suspects.length} potential camera{scan.data.suspects.length === 1 ? "" : "s"}
              </Badge>
            </div>

            {scan.data.suspects.length > 0 ? (
              <div className="space-y-3">
                {scan.data.suspects.map((s) => (
                  <div key={s.mac || s.ip} className="space-y-2 rounded-lg border bg-background/30 p-4">
                    <div className="flex items-center justify-between gap-3">
                      <div>
                        <p className="text-sm font-semibold">{s.name || s.ip}</p>
                        <p className="font-mono text-xs text-muted-foreground">
                          {s.ip} · {s.mac} · {s.vendor || "Unknown vendor"}
                        </p>
                      </div>
                      <Badge
                        variant={
                          s.confidence === "High"
                            ? "destructive"
                            : s.confidence === "Medium"
                              ? "default"
                              : "secondary"
                        }
                      >
                        {s.confidence} Confidence
                      </Badge>
                    </div>
                    <ul className="list-inside list-disc space-y-1 text-xs text-muted-foreground">
                      {s.reasons.map((r, i) => (
                        <li key={i}>{r}</li>
                      ))}
                    </ul>
                    {s.openPorts && s.openPorts.length > 0 && (
                      <div className="flex flex-wrap gap-1.5 pt-1">
                        {s.openPorts.map((port) => (
                          <Badge key={port} variant="outline" className="font-mono text-[10px]">
                            TCP {port} OPEN
                          </Badge>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="rounded-lg border bg-background/30 py-8 text-center text-xs text-muted-foreground">
                <ShieldCheck className="mx-auto mb-2 size-6 text-primary" />
                No hidden cameras or active RTSP/ONVIF streaming endpoints detected on the current network.
              </div>
            )}
          </>
        ) : (
          <div className="py-12 text-center text-sm text-muted-foreground">
            Click <strong>Scan for Cameras</strong> to inspect all discovered LAN devices for surveillance and streaming signatures.
          </div>
        )}
      </CardContent>
    </Card>
  )
}

function InternetHealthWorkspace() {
  const check = useCheckInternetHealth()

  return (
    <Card className="bg-card/60">
      <CardHeader className="flex-row items-center justify-between border-b">
        <div>
          <CardTitle>Internet outages & Compare providers</CardTitle>
          <CardDescription>
            Verify ISP upstream connectivity, detect ongoing outages, and benchmark global DNS & backbone providers in your area.
          </CardDescription>
        </div>
        <Button type="button" disabled={check.isPending} onClick={() => check.mutate()}>
          {check.isPending ? <LoaderCircle className="animate-spin" /> : <Globe />}
          Check Internet & Providers
        </Button>
      </CardHeader>
      <CardContent className="space-y-5 py-6">
        {check.data ? (
          <>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <StatBox label="Connection Status" value={check.data.status} sub={check.data.publicIp || "Local check"} />
              <StatBox
                label="Active ISP"
                value={check.data.isp || "Detected ISP"}
                sub={[check.data.city, check.data.region, check.data.country].filter(Boolean).join(", ") || "Local Area"}
              />
              <StatBox
                label="Gateway Latency"
                value={check.data.gatewayLatencyMs ? `${check.data.gatewayLatencyMs} ms` : "—"}
                sub={check.data.gatewayIp || "Default router"}
              />
              <StatBox
                label="Backbone Latency"
                value={check.data.internetLatencyMs ? `${check.data.internetLatencyMs} ms` : "—"}
                sub="Upstream average"
              />
            </div>

            <div className="rounded-lg border bg-background/30 p-3.5 text-xs text-muted-foreground">
              {check.data.summary}
            </div>

            <div className="overflow-x-auto rounded-lg border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Provider</TableHead>
                    <TableHead>Address</TableHead>
                    <TableHead>Category</TableHead>
                    <TableHead>Latency</TableHead>
                    <TableHead>Jitter</TableHead>
                    <TableHead>Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {check.data.providers.map((p) => (
                    <TableRow key={p.address}>
                      <TableCell className="font-medium">
                        <div className="flex items-center gap-2">
                          <span>{p.name}</span>
                          {p.recommended && (
                            <Badge variant="default" className="gap-1 text-[10px]">
                              <Sparkles className="size-2.5" />
                              Best in your area
                            </Badge>
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="font-mono text-xs">{p.address}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{p.category}</TableCell>
                      <TableCell className="font-mono text-xs">
                        {p.reachable ? `${p.latencyMs} ms` : "Unreachable"}
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {p.reachable ? `${p.jitterMs} ms` : "—"}
                      </TableCell>
                      <TableCell>
                        <Badge variant={p.reachable ? "outline" : "destructive"}>
                          {p.reachable ? `${100 - p.lossPercent}% Reachable` : "Outage / Blocked"}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </>
        ) : (
          <div className="py-12 text-center text-sm text-muted-foreground">
            Click <strong>Check Internet & Providers</strong> to inspect your ISP status, check for upstream outages, and rank provider latency.
          </div>
        )}
      </CardContent>
    </Card>
  )
}

function StatBox({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="rounded-lg border bg-background/30 p-3.5">
      <p className="text-[11px] text-muted-foreground">{label}</p>
      <p className="mt-1 truncate text-base font-semibold" title={value}>
        {value}
      </p>
      {sub && (
        <p className="mt-0.5 truncate text-[10px] text-muted-foreground" title={sub}>
          {sub}
        </p>
      )}
    </div>
  )
}
