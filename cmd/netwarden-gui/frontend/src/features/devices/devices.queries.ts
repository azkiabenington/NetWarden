import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { queryKeys } from "@/lib/query-keys"
import { wailsClient } from "@/lib/wails/client"
import { errorMessage } from "@/lib/errors"

export const useDevices = () => useQuery({ queryKey: queryKeys.devices, queryFn: wailsClient.devices })

export function useSetNickname() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: ({ mac, nickname }: { mac: string; nickname: string }) => wailsClient.setNickname(mac, nickname),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: queryKeys.devices })
      toast.success("Nickname saved")
    },
    onError: (error) => toast.error("Could not save nickname", { description: errorMessage(error) }),
  })
}

export function useSetDeviceWhitelisted() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: ({ mac, whitelisted }: { mac: string; whitelisted: boolean }) =>
      wailsClient.setDeviceWhitelisted(mac, whitelisted),
    onSuccess: async (_, variables) => {
      await Promise.all([
        client.invalidateQueries({ queryKey: queryKeys.devices }),
        client.invalidateQueries({ queryKey: queryKeys.bandwidthLimits }),
        client.invalidateQueries({ queryKey: queryKeys.bandwidthMonitors }),
        client.invalidateQueries({ queryKey: queryKeys.status }),
      ])
      toast.success(variables.whitelisted ? "Added to whitelist" : "Removed from whitelist")
    },
    onError: (error) => toast.error("Could not update whitelist", { description: errorMessage(error) }),
  })
}
