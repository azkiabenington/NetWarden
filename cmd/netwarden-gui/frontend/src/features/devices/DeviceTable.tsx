import { useEffect, useRef } from "react"
import { ArrowDown, ArrowUp, ChevronRight, LoaderCircle } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { announce } from "@/lib/accessibility"
import { formatDate } from "@/lib/format"
import type { Device } from "@/lib/wails/types"
import type { BandwidthLimit } from "@/lib/wails/types"
import { bandwidthSummary } from "@/features/bandwidth/format"
import { type DeviceSortKey, isControlEligible } from "./device-list"
import { useRateUnit } from "@/lib/measurement"

const sortableColumns: Array<{ key: DeviceSortKey; label: string }> = [
  { key: "name", label: "Device" },
  { key: "ip", label: "Address" },
  { key: "vendor", label: "Vendor" },
  { key: "type", label: "Type" },
  { key: "role", label: "Role" },
  { key: "online", label: "Status" },
  { key: "controlState", label: "Control" },
]

export function DeviceTable({
  devices,
  bandwidthByMAC,
  bandwidthBlockedMACs,
  checkedMACs,
  sortBy,
  descending,
  onSortChange,
  onCheckedChange,
  onCheckVisible,
  onOpen,
}: {
  devices: Device[]
  bandwidthByMAC: Map<string, BandwidthLimit>
  bandwidthBlockedMACs: Set<string>
  checkedMACs: Set<string>
  sortBy: DeviceSortKey
  descending: boolean
  onSortChange: (key: DeviceSortKey) => void
  onCheckedChange: (mac: string, checked: boolean) => void
  onCheckVisible: (checked: boolean) => void
  onOpen: (device: Device, trigger: HTMLElement) => void
}) {
  const eligible = devices.filter(
    (device) => isControlEligible(device) && !bandwidthBlockedMACs.has(device.mac.toLowerCase()),
  )
  const allChecked = eligible.length > 0 && eligible.every((device) => checkedMACs.has(device.mac))
  const someChecked = eligible.some((device) => checkedMACs.has(device.mac))
  const handleHeaderSort = (key: DeviceSortKey, label: string) => {
    const nextDescending = sortBy === key ? !descending : false
    onSortChange(key)
    announce(`Sorted by ${label}, ${nextDescending ? "descending" : "ascending"}, ${devices.length} rows`, "polite")
  }
  return (
    <div className="overflow-x-auto">
      <Table className="min-w-[1150px]">
        <TableHeader>
          <TableRow>
            <TableHead className="w-10">
              <SelectionCheckbox
                label="Select all eligible visible devices"
                checked={allChecked}
                indeterminate={someChecked && !allChecked}
                disabled={eligible.length === 0}
                onChange={onCheckVisible}
              />
            </TableHead>
            {sortableColumns.map(({ key, label }) => (
              <SortableTableHead
                key={key}
                label={label}
                active={sortBy === key}
                descending={descending}
                onSort={() => handleHeaderSort(key, label)}
              />
            ))}
            <TableHead scope="col">Bandwidth</TableHead>
            <SortableTableHead
              label="Last seen"
              active={sortBy === "lastSeen"}
              descending={descending}
              onSort={() => handleHeaderSort("lastSeen", "Last seen")}
            />
            <TableHead />
          </TableRow>
        </TableHeader>
        <TableBody>
          {devices.map((device) => (
            <DeviceRow
              key={device.mac}
              device={device}
              bandwidthLimit={bandwidthByMAC.get(device.mac.toLowerCase())}
              bandwidthBlocked={bandwidthBlockedMACs.has(device.mac.toLowerCase())}
              checked={checkedMACs.has(device.mac)}
              onCheckedChange={(checked) => onCheckedChange(device.mac, checked)}
              onOpen={(trigger) => onOpen(device, trigger)}
            />
          ))}
        </TableBody>
      </Table>
    </div>
  )
}

function DeviceRow({
  device,
  bandwidthLimit,
  bandwidthBlocked,
  checked,
  onCheckedChange,
  onOpen,
}: {
  device: Device
  bandwidthLimit?: BandwidthLimit
  bandwidthBlocked: boolean
  checked: boolean
  onCheckedChange: (checked: boolean) => void
  onOpen: (trigger: HTMLElement) => void
}) {
  const { rateUnit } = useRateUnit()
  const controlled = device.controlState !== ""
  const control =
    device.controlState === "active"
      ? "Disconnected"
      : device.controlState === "continuous"
        ? "Continuous"
        : device.controlState === "restoring"
          ? "Restoring"
          : device.controlState === "failed"
            ? "Recovery failed"
            : device.role !== "Device"
              ? "Protected"
              : device.online
                ? "Available"
                : "Offline"
  return (
    <TableRow
      tabIndex={0}
      role="button"
      aria-label={`Open details for ${device.name || device.ip}`}
      className="cursor-pointer focus-visible:bg-accent focus-visible:outline-none"
      onClick={(event) => onOpen(event.currentTarget)}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault()
          onOpen(event.currentTarget)
        }
      }}
    >
      <TableCell
        onClick={(event) => {
          event.stopPropagation()
          if (isControlEligible(device) && !bandwidthBlocked) {
            onCheckedChange(!checked)
          }
        }}
        onKeyDown={(event) => event.stopPropagation()}
      >
        <SelectionCheckbox
          label={`Select ${device.name || device.ip}`}
          checked={checked}
          disabled={!isControlEligible(device) || bandwidthBlocked}
          onChange={onCheckedChange}
        />
      </TableCell>
      <TableCell>
        <div className="flex items-center gap-3">
          <span
            className={`size-2 rounded-full ${device.online ? "bg-primary shadow-[0_0_8px_var(--primary)]" : "bg-muted-foreground/60"}`}
          />
          <div>
            <p className="font-medium">{device.name || device.ip}</p>
            <p className="font-mono text-[10px] text-muted-foreground">{device.mac}</p>
          </div>
        </div>
      </TableCell>
      <TableCell>
        <div className="flex items-center gap-1.5 font-mono text-xs">
          <span>{device.ip}</span>
          {device.addresses && device.addresses.length > 1 && (
            <Badge variant="outline" className="h-4 px-1 text-[10px] text-muted-foreground">
              +{device.addresses.length - 1}
            </Badge>
          )}
        </div>
      </TableCell>
      <TableCell className="max-w-48 truncate text-muted-foreground" title={device.vendor}>
        {device.vendor || "Unknown"}
      </TableCell>
      <TableCell>
        <Badge variant="secondary">{device.type || "Unknown"}</Badge>
      </TableCell>
      <TableCell>
        <Badge variant="outline">{device.role}</Badge>
      </TableCell>
      <TableCell>
        <Badge variant={device.online ? "default" : "secondary"}>{device.online ? "Online" : "Offline"}</Badge>
      </TableCell>
      <TableCell>
        <Badge variant={controlled ? "destructive" : "secondary"}>
          {device.controlState === "restoring" && <LoaderCircle className="animate-spin" />}
          {control}
        </Badge>
      </TableCell>
      <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
        {bandwidthSummary(bandwidthLimit, rateUnit)}
      </TableCell>
      <TableCell className="text-xs text-muted-foreground">{formatDate(device.lastSeen)}</TableCell>
      <TableCell>
        <ChevronRight className="size-4 text-muted-foreground" />
      </TableCell>
    </TableRow>
  )
}

function SortableTableHead({
  label,
  active,
  descending,
  onSort,
}: {
  label: string
  active: boolean
  descending: boolean
  onSort: () => void
}) {
  return (
    <TableHead scope="col" aria-sort={active ? (descending ? "descending" : "ascending") : undefined} className="p-0">
      <button
        type="button"
        onClick={onSort}
        className="flex h-10 min-h-6 w-full items-center gap-1 px-2 text-left font-medium text-foreground hover:text-primary focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
      >
        <span>{label}</span>
        {active &&
          (descending ? (
            <ArrowDown aria-hidden="true" className="size-3.5 text-primary" />
          ) : (
            <ArrowUp aria-hidden="true" className="size-3.5 text-primary" />
          ))}
      </button>
    </TableHead>
  )
}

function SelectionCheckbox({
  label,
  checked,
  indeterminate = false,
  disabled = false,
  onChange,
}: {
  label: string
  checked: boolean
  indeterminate?: boolean
  disabled?: boolean
  onChange: (checked: boolean) => void
}) {
  const ref = useRef<HTMLInputElement>(null)
  useEffect(() => {
    if (ref.current) ref.current.indeterminate = indeterminate
  }, [indeterminate])
  return (
    <input
      ref={ref}
      type="checkbox"
      className="size-4 rounded border-border accent-primary disabled:cursor-not-allowed disabled:opacity-40"
      aria-label={label}
      checked={checked}
      disabled={disabled}
      onChange={(event) => onChange(event.target.checked)}
    />
  )
}
