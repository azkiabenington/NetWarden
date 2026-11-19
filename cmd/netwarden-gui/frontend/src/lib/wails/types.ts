export type Adapter = { name: string; systemName: string; description: string; mac: string; prefixes: string[] }
export type Bootstrap = { interfaces: Adapter[]; selectedInterface: string; gatewayMAC: string }
export type DeviceControlState = "" | "active" | "continuous" | "restoring" | "failed"
export type Device = {
  ip: string
  addresses: string[]
  mac: string
  name: string
  vendor: string
  type: string
  role: string
  firstSeen: string
  lastSeen: string
  online: boolean
  controlState: DeviceControlState
  whitelisted?: boolean
}
export type GlobalBandwidthSettings = {
  trafficMonitoring: boolean
  bandwidthLimitEnabled: boolean
  downloadBitsPerSecond: number
  uploadBitsPerSecond: number
}
export type Conflict = {
  gatewayIP: string
  claimedMAC: string
  firstSeen: string
  lastSeen: string
  count: number
  active: boolean
}
export type RuntimeStatus = {
  Running: boolean
  Stopped: boolean
  Scanning: boolean
  PeriodicScanEnabled: boolean
  DeviceCount: number
  DroppedEvents: number
  Generation: number
  RestartCount: number
  Rebuilding: boolean
  LastRestartReason: string
  SupervisorDroppedEvents: number
  ConflictCount: number
  LastPersistenceError: string
  BandwidthAvailable: boolean
  ActiveBandwidthLimits: number
  BandwidthMonitoringAvailable: boolean
  ActiveBandwidthMonitors: number
  IPv6Available: boolean
  IPv6RouterIP: string
  IPv6RouterMAC: string
  IPv6PrefixCount: number
  IPv6RouterConflicts: number
}
export type IPv6Prefix = {
  prefix: string
  onLink: boolean
  autonomous: boolean
  validUntil: string
  preferredUntil: string
}
export type IPv6Router = { ip: string; mac: string; expiresAt: string; preference: number; prefixes: IPv6Prefix[] }
export type IPv6RouterConflict = {
  routerIP: string
  expectedMAC: string
  claimedMAC: string
  firstSeen: string
  lastSeen: string
  count: number
  active: boolean
}
export type IPv6Network = {
  localAddresses: string[]
  defaultRouter?: IPv6Router
  routers: IPv6Router[]
  conflictCount: number
  conflicts: IPv6RouterConflict[]
  trustedIdentities: Array<{ routerIP: string; mac: string }>
}
export type HistorySummary = { devices: number; conflicts: number; oldest?: string; newest?: string }
export type Activity = {
  at: string
  kind: string
  severity: "info" | "warning" | "error"
  title: string
  detail?: string
}
export type MonitoringSettings = {
  scanIntervalSeconds: number
  offlineAfterSeconds: number
  historyRetentionDays: number
  autoStart: boolean
  periodicDiscovery: boolean
}
export type NotificationSettings = {
  enabled: boolean
  newDevices: boolean
  knownDevices: boolean
  deviceOffline: boolean
  suspiciousDevices: boolean
}
export type ControlAudit = { at: string; operation: string; outcome: string; targets: string[] }
export type BandwidthLimit = {
  ip: string
  mac: string
  downloadBitsPerSecond: number
  uploadBitsPerSecond: number
  burstBytes: number
}
export type BandwidthTraffic = {
  mac: string
  uploadPackets: number
  uploadBytes: number
  downloadPackets: number
  downloadBytes: number
}
export type BandwidthMonitor = { ip: string; mac: string }
export type BandwidthHistoryPoint = {
  at: string
  uploadBytes: number
  downloadBytes: number
  uploadBPS: number
  downloadBPS: number
}
export type BandwidthMeasurement = {
  mac: string
  uploadBytes: number
  downloadBytes: number
  uploadBPS: number
  downloadBPS: number
  peakUploadBPS: number
  peakUploadAt?: string
  peakDownloadBPS: number
  peakDownloadAt?: string
  history: BandwidthHistoryPoint[]
}
export type BandwidthBucket = { start: string; uploadBytes: number; downloadBytes: number; peakUploadBPS: number; peakDownloadBPS: number }
export type BandwidthDeviceQueueDrops = { mac: string; uploadDrops: number; downloadDrops: number }
export type BandwidthHealth = {
  queueDrops: number
  uploadQueueDrops: number
  downloadQueueDrops: number
  monitorQueueDrops: number
  limitedQueueDrops: number
  canceledDrops: number
  sendErrors: number
  unmanagedFrames: number
  queueCapacity: number
  uploadQueueDepth: number
  downloadQueueDepth: number
  peakUploadDepth: number
  peakDownloadDepth: number
  queueByteCapacity: number
  uploadQueueBytes: number
  downloadQueueBytes: number
  peakUploadBytes: number
  peakDownloadBytes: number
  deviceQueueDrops: BandwidthDeviceQueueDrops[]
  recentQueueDrops: number
  recentSendErrors: number
  sampleSeconds: number
  activeWarning: boolean
  sampledAt: string
  samplingError?: string
}
export type AppInfo = { name: string; version: string; build: string }

export type PingSample = {
  seq: number
  success: boolean
  rttMs: number
  ttl?: number
  error?: string
}
export type PingResult = {
  target: string
  resolvedIp: string
  sent: number
  received: number
  lossPercent: number
  minMs: number
  avgMs: number
  maxMs: number
  jitterMs: number
  samples: PingSample[]
}
export type TraceHop = {
  hop: number
  ip?: string
  hostname?: string
  rttMs: number
  reached: boolean
  timeout: boolean
}
export type TraceRouteResult = {
  target: string
  resolvedIp: string
  reached: boolean
  hops: TraceHop[]
}
export type WiFiNetwork = {
  ssid: string
  bssid: string
  vendor?: string
  rssiDbm: number
  signalQuality: number
  channel: number
  frequencyMhz: number
  band: string
  collisionRisk: string
  sameChannelAp: number
}
export type WiFiScanResult = {
  interfaceName: string
  scannedAt: string
  networks: WiFiNetwork[]
}
export type OpenPort = {
  port: number
  protocol: string
  service: string
  banner?: string
  risk: string
  note?: string
  rttMs: number
}
export type PortScanResult = {
  target: string
  resolvedIp: string
  probedCount: number
  durationMs: number
  openPorts: OpenPort[]
}
export type UPnPMapping = {
  protocol: string
  externalPort: number
  internalClient: string
  internalPort: number
  description: string
  enabled: boolean
}
export type RouterVulnerabilityFinding = {
  severity: string
  title: string
  detail: string
  recommendation: string
}
export type RouterVulnerabilityResult = {
  gatewayIp: string
  status: string
  upnpEnabled: boolean
  natPmpEnabled: boolean
  upnpMappings: UPnPMapping[]
  openPorts: OpenPort[]
  findings: RouterVulnerabilityFinding[]
}
export type HiddenCameraSuspect = {
  ip: string
  mac: string
  name: string
  vendor: string
  confidence: string
  openPorts: number[]
  reasons: string[]
}
export type HiddenCameraResult = {
  scannedHosts: number
  suspects: HiddenCameraSuspect[]
}
export type ProviderBenchmark = {
  name: string
  address: string
  category: string
  reachable: boolean
  latencyMs: number
  jitterMs: number
  lossPercent: number
  recommended: boolean
}
export type InternetHealthResult = {
  status: string
  summary: string
  publicIp?: string
  isp?: string
  city?: string
  region?: string
  country?: string
  gatewayIp?: string
  gatewayLatencyMs: number
  internetLatencyMs: number
  outageDetected: boolean
  providers: ProviderBenchmark[]
}
