import { useEffect, type ReactNode } from "react"
import { QueryClient, QueryClientProvider, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { Toaster } from "@/components/ui/sonner"
import { TooltipProvider } from "@/components/ui/tooltip"
import { ThemeProvider } from "next-themes"
import { subscribeRuntimeEvents } from "@/lib/wails/events"
import { queryKeys } from "@/lib/query-keys"
import { UnsavedChangesProvider } from "@/app/unsaved-changes"
import { LiveAnnouncer } from "@/components/LiveAnnouncer"
import { announce } from "@/lib/accessibility"
import { MeasurementProvider } from "@/lib/measurement"

const queryClient = new QueryClient({ defaultOptions: { queries: { staleTime: 2_000, retry: 1 } } })

function RuntimeEventBridge() {
  const client = useQueryClient()
  useEffect(() => {
    let lastInvalidate = 0
    let pendingTimer: ReturnType<typeof setTimeout> | null = null
    const scheduleInvalidate = () => {
      const now = Date.now()
      const elapsed = now - lastInvalidate
      if (elapsed >= 250) {
        lastInvalidate = now
        void client.invalidateQueries({ queryKey: queryKeys.runtime })
        return
      }
      if (!pendingTimer) {
        pendingTimer = setTimeout(() => {
          pendingTimer = null
          lastInvalidate = Date.now()
          void client.invalidateQueries({ queryKey: queryKeys.runtime })
        }, 250 - elapsed)
      }
    }
    const unsubscribe = subscribeRuntimeEvents({
      onChange: (event) => {
        scheduleInvalidate()
        if (event?.title)
          announce(
            [event.title, event.detail].filter(Boolean).join(". "),
            event.severity === "error" ? "assertive" : "polite",
          )
      },
      onError: (message) => {
        toast.error("Runtime error", { description: message })
        announce(`Runtime error. ${message}`, "assertive")
        void client.invalidateQueries({ queryKey: queryKeys.runtime })
      },
    })
    return () => {
      if (pendingTimer) clearTimeout(pendingTimer)
      unsubscribe()
    }
  }, [client])
  return null
}

export function AppProviders({ children }: { children: ReactNode }) {
  return (
    <ThemeProvider attribute="class" defaultTheme="system" enableSystem>
      <QueryClientProvider client={queryClient}>
        <UnsavedChangesProvider>
          <MeasurementProvider>
            <TooltipProvider>
              <RuntimeEventBridge />
              <LiveAnnouncer />
              {children}
              <Toaster richColors position="bottom-right" />
            </TooltipProvider>
          </MeasurementProvider>
        </UnsavedChangesProvider>
      </QueryClientProvider>
    </ThemeProvider>
  )
}
