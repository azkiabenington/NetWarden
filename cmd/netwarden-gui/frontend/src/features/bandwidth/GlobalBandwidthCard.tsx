import { useEffect, useState } from "react"
import { Activity, Gauge, LoaderCircle, Plus, RotateCcw, ShieldCheck, X } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select"
import { Switch } from "@/components/ui/switch"
import { useDevices, useSetDeviceWhitelisted } from "@/features/devices/devices.queries"
import { useRateUnit } from "@/lib/measurement"
import { useGlobalBandwidthSettings, useSetGlobalBandwidthSettings } from "./bandwidth.queries"
import { displayRateValue, rateUnitLabel } from "./format"
import { bandwidthValidation, parseMbps } from "./validation"

export function GlobalBandwidthCard() {
  const { rateUnit } = useRateUnit()
  const unitLabel = rateUnitLabel(rateUnit)
  const { data: settings } = useGlobalBandwidthSettings()
  const saveGlobal = useSetGlobalBandwidthSettings()
  const { data: devices = [] } = useDevices()
  const setWhitelisted = useSetDeviceWhitelisted()

  const [download, setDownload] = useState("")
  const [upload, setUpload] = useState("")
  const [selectedMAC, setSelectedMAC] = useState("")

  useEffect(() => {
    setDownload(settings?.downloadBitsPerSecond ? displayRateValue(settings.downloadBitsPerSecond, rateUnit) : "")
    setUpload(settings?.uploadBitsPerSecond ? displayRateValue(settings.uploadBitsPerSecond, rateUnit) : "")
  }, [settings?.downloadBitsPerSecond, settings?.uploadBitsPerSecond, rateUnit])

  const validation = bandwidthValidation(download, upload)
  const peerDevices = devices.filter((device) => device.role === "Device")
  const whitelistedDevices = peerDevices.filter((device) => Boolean(device.whitelisted))
  const nonWhitelistedDevices = peerDevices.filter((device) => !device.whitelisted)

  const handleToggleTrafficMonitoring = (checked: boolean) => {
    saveGlobal.mutate({
      trafficMonitoring: checked,
      bandwidthLimitEnabled: Boolean(settings?.bandwidthLimitEnabled),
      downloadBitsPerSecond: settings?.downloadBitsPerSecond || 0,
      uploadBitsPerSecond: settings?.uploadBitsPerSecond || 0,
    })
  }

  const handleApplyGlobalLimit = () => {
    const multiplier = rateUnit === "megabytes" ? 8 : 1
    const dlBPS = (parseMbps(download) ?? 0) * multiplier
    const ulBPS = (parseMbps(upload) ?? 0) * multiplier
    saveGlobal.mutate({
      trafficMonitoring: Boolean(settings?.trafficMonitoring),
      bandwidthLimitEnabled: true,
      downloadBitsPerSecond: dlBPS,
      uploadBitsPerSecond: ulBPS,
    })
  }

  const handleDisableGlobalLimit = () => {
    saveGlobal.mutate({
      trafficMonitoring: Boolean(settings?.trafficMonitoring),
      bandwidthLimitEnabled: false,
      downloadBitsPerSecond: settings?.downloadBitsPerSecond || 0,
      uploadBitsPerSecond: settings?.uploadBitsPerSecond || 0,
    })
  }

  const handleAddWhitelist = () => {
    if (!selectedMAC) return
    setWhitelisted.mutate(
      { mac: selectedMAC, whitelisted: true },
      { onSuccess: () => setSelectedMAC("") },
    )
  }

  return (
    <Card className="mb-5 bg-card/60">
      <CardHeader className="border-b">
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <CardTitle className="text-base">Global Traffic, Bandwidth Limit & Whitelist</CardTitle>
            <CardDescription>
              Automatically monitor or limit all online devices, and protect whitelisted devices from limits and disconnection.
            </CardDescription>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant={settings?.trafficMonitoring ? "default" : "secondary"}>
              <Activity className="size-3" />
              {settings?.trafficMonitoring ? "Global Traffic Monitor: ON" : "Global Traffic Monitor: OFF"}
            </Badge>
            <Badge variant={settings?.bandwidthLimitEnabled ? "default" : "secondary"}>
              <Gauge className="size-3" />
              {settings?.bandwidthLimitEnabled ? "Global Bandwidth Limit: ON" : "Global Bandwidth Limit: OFF"}
            </Badge>
            <Badge variant="outline">
              <ShieldCheck className="size-3" />
              {whitelistedDevices.length} whitelisted
            </Badge>
          </div>
        </div>
      </CardHeader>
      <CardContent className="grid gap-6 py-5 lg:grid-cols-3">
        <div className="space-y-3 rounded-lg border bg-background/30 p-4">
          <div className="flex items-center justify-between gap-4">
            <div>
              <Label htmlFor="global-traffic-monitoring" className="text-sm font-medium">
                Global traffic monitoring
              </Label>
              <p className="mt-1 text-xs text-muted-foreground">
                Automatically start live upload/download monitoring for all online peer devices (including new devices).
              </p>
            </div>
            <Switch
              id="global-traffic-monitoring"
              checked={Boolean(settings?.trafficMonitoring)}
              disabled={saveGlobal.isPending}
              onCheckedChange={handleToggleTrafficMonitoring}
            />
          </div>
        </div>

        <div className="space-y-3 rounded-lg border bg-background/30 p-4">
          <div className="flex items-center justify-between">
            <h4 className="text-sm font-medium">Global bandwidth limit</h4>
            {settings?.bandwidthLimitEnabled && (
              <Badge variant="default" className="text-[10px]">
                Active
              </Badge>
            )}
          </div>
          <p className="text-xs text-muted-foreground">
            Applies to all online non-whitelisted devices ({nonWhitelistedDevices.filter((d) => d.online).length} online now).
          </p>
          <div className="grid grid-cols-2 gap-2">
            <div className="space-y-1.5">
              <Label htmlFor="global-download-limit" className="text-xs">
                Download {unitLabel}
              </Label>
              <Input
                id="global-download-limit"
                type="number"
                inputMode="decimal"
                min="0"
                step="0.1"
                placeholder="Unlimited"
                value={download}
                disabled={saveGlobal.isPending}
                onChange={(event) => setDownload(event.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="global-upload-limit" className="text-xs">
                Upload {unitLabel}
              </Label>
              <Input
                id="global-upload-limit"
                type="number"
                inputMode="decimal"
                min="0"
                step="0.1"
                placeholder="Unlimited"
                value={upload}
                disabled={saveGlobal.isPending}
                onChange={(event) => setUpload(event.target.value)}
              />
            </div>
          </div>
          {validation && (download !== "" || upload !== "") && (
            <p className="text-xs text-destructive" role="alert">
              {validation}
            </p>
          )}
          <div className="flex flex-wrap gap-2 pt-1">
            <Button
              type="button"
              size="sm"
              disabled={saveGlobal.isPending || Boolean(validation)}
              onClick={handleApplyGlobalLimit}
            >
              {saveGlobal.isPending ? <LoaderCircle className="animate-spin" /> : <Gauge />}
              {settings?.bandwidthLimitEnabled ? "Update global limit" : "Enable global limit"}
            </Button>
            {settings?.bandwidthLimitEnabled && (
              <Button
                type="button"
                variant="outline"
                size="sm"
                disabled={saveGlobal.isPending}
                onClick={handleDisableGlobalLimit}
              >
                <RotateCcw />
                Disable global limit
              </Button>
            )}
          </div>
        </div>

        <div className="space-y-3 rounded-lg border bg-background/30 p-4">
          <div className="flex items-center justify-between">
            <h4 className="text-sm font-medium">Device Whitelist</h4>
            <Badge variant="outline" className="text-[10px]">
              {whitelistedDevices.length} protected
            </Badge>
          </div>
          <p className="text-xs text-muted-foreground">
            Whitelisted devices are never throttled by bandwidth limits or disconnected.
          </p>
          <div className="flex gap-2">
            <NativeSelect
              aria-label="Select device to whitelist"
              className="min-w-0 flex-1"
              value={selectedMAC}
              disabled={setWhitelisted.isPending || nonWhitelistedDevices.length === 0}
              onChange={(event) => setSelectedMAC(event.target.value)}
            >
              <NativeSelectOption value="">
                {nonWhitelistedDevices.length ? "Select a device to whitelist…" : "All peer devices whitelisted"}
              </NativeSelectOption>
              {nonWhitelistedDevices.map((device) => (
                <NativeSelectOption key={device.mac} value={device.mac}>
                  {device.name || device.ip} ({device.ip})
                </NativeSelectOption>
              ))}
            </NativeSelect>
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={!selectedMAC || setWhitelisted.isPending}
              onClick={handleAddWhitelist}
            >
              <Plus />
              Add
            </Button>
          </div>
          {whitelistedDevices.length > 0 ? (
            <div className="flex max-h-28 flex-wrap gap-1.5 overflow-y-auto pt-1">
              {whitelistedDevices.map((device) => (
                <Badge key={device.mac} variant="secondary" className="flex items-center gap-1 pr-1">
                  <ShieldCheck className="size-3 text-primary" />
                  <span className="max-w-36 truncate" title={`${device.name} (${device.ip} · ${device.mac})`}>
                    {device.name || device.ip}
                  </span>
                  <button
                    type="button"
                    aria-label={`Remove ${device.name || device.ip} from whitelist`}
                    className="ml-0.5 rounded p-0.5 hover:bg-muted-foreground/20 focus-visible:ring-1 focus-visible:ring-ring focus-visible:outline-none"
                    disabled={setWhitelisted.isPending}
                    onClick={() => setWhitelisted.mutate({ mac: device.mac, whitelisted: false })}
                  >
                    <X className="size-3" />
                  </button>
                </Badge>
              ))}
            </div>
          ) : (
            <p className="text-xs text-muted-foreground italic">No devices whitelisted yet.</p>
          )}
        </div>
      </CardContent>
    </Card>
  )
}
