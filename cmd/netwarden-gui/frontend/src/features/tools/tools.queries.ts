import { useMutation } from "@tanstack/react-query"
import { toast } from "sonner"
import { errorMessage } from "@/lib/errors"
import { wailsClient } from "@/lib/wails/client"

export const usePingHost = () =>
  useMutation({
    mutationFn: ({ target, count }: { target: string; count: number }) => wailsClient.pingHost(target, count),
    onError: (error) => toast.error("Ping failed", { description: errorMessage(error) }),
  })

export const useTraceRoute = () =>
  useMutation({
    mutationFn: ({ target, maxHops }: { target: string; maxHops: number }) => wailsClient.traceRoute(target, maxHops),
    onError: (error) => toast.error("Trace route failed", { description: errorMessage(error) }),
  })

export const useScanWiFi = () =>
  useMutation({
    mutationFn: () => wailsClient.scanWiFi(),
    onError: (error) => toast.error("Wi-Fi scan failed", { description: errorMessage(error) }),
  })

export const useWakeOnLAN = () =>
  useMutation({
    mutationFn: ({ mac, targetIP }: { mac: string; targetIP: string }) => wailsClient.wakeOnLAN(mac, targetIP),
    onSuccess: () => toast.success("Wake-on-LAN magic packet sent"),
    onError: (error) => toast.error("Wake-on-LAN failed", { description: errorMessage(error) }),
  })

export const useScanPorts = () =>
  useMutation({
    mutationFn: ({ target, preset }: { target: string; preset: string }) => wailsClient.scanPorts(target, preset),
    onError: (error) => toast.error("Port scan failed", { description: errorMessage(error) }),
  })

export const useCheckRouterVulnerabilities = () =>
  useMutation({
    mutationFn: () => wailsClient.checkRouterVulnerabilities(),
    onError: (error) => toast.error("Router security check failed", { description: errorMessage(error) }),
  })

export const useDetectHiddenCameras = () =>
  useMutation({
    mutationFn: () => wailsClient.detectHiddenCameras(),
    onError: (error) => toast.error("Hidden camera scan failed", { description: errorMessage(error) }),
  })

export const useCheckInternetHealth = () =>
  useMutation({
    mutationFn: () => wailsClient.checkInternetHealth(),
    onError: (error) => toast.error("Internet check failed", { description: errorMessage(error) }),
  })
