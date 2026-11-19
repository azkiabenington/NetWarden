import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { announce } from "@/lib/accessibility"
import { errorMessage } from "@/lib/errors"
import { queryKeys } from "@/lib/query-keys"
import { wailsClient } from "@/lib/wails/client"
import type { GlobalBandwidthSettings } from "@/lib/wails/types"

export const useBandwidthLimits = () =>
  useQuery({ queryKey: queryKeys.bandwidthLimits, queryFn: wailsClient.bandwidthLimits, refetchInterval: 5_000 })

export const useGlobalBandwidthSettings = () =>
  useQuery({ queryKey: queryKeys.globalBandwidthSettings, queryFn: wailsClient.globalBandwidthSettings })

function useBandwidthAction<T>(action: (value: T) => Promise<void>, success: string) {
  const client = useQueryClient()
  return useMutation({
    mutationFn: action,
    onSuccess: async () => {
      await Promise.all([
        client.invalidateQueries({ queryKey: queryKeys.bandwidthLimits }),
        client.invalidateQueries({ queryKey: queryKeys.bandwidthMonitors }),
        client.invalidateQueries({ queryKey: queryKeys.globalBandwidthSettings }),
        client.invalidateQueries({ queryKey: queryKeys.devices }),
        client.invalidateQueries({ queryKey: queryKeys.status }),
      ])
      toast.success(success)
      announce(success)
    },
    onError: (error) => {
      const message = errorMessage(error)
      toast.error("Bandwidth request failed", { description: message })
      announce(`Bandwidth request failed. ${message}`, "assertive")
    },
  })
}

export const useSetBandwidthLimit = () =>
  useBandwidthAction(
    (value: { ip: string; mac: string; downloadBitsPerSecond: number; uploadBitsPerSecond: number }) =>
      wailsClient.setBandwidthLimit(value.ip, value.mac, value.downloadBitsPerSecond, value.uploadBitsPerSecond),
    "Bandwidth limit applied",
  )

export const useRemoveBandwidthLimit = () =>
  useBandwidthAction((mac: string) => wailsClient.removeBandwidthLimit(mac), "Bandwidth limit removed")

export const useClearBandwidthLimits = () =>
  useBandwidthAction(() => wailsClient.clearBandwidthLimits(), "All bandwidth limits removed")

export const useSetGlobalBandwidthSettings = () =>
  useBandwidthAction(
    (settings: GlobalBandwidthSettings) => wailsClient.setGlobalBandwidthSettings(settings),
    "Global bandwidth settings updated",
  )
