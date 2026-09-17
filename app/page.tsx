"use client"

import { useTelemetry } from "@/hooks/use-telemetry"
import { ConsoleHeader } from "@/components/console-header"
import { FleetPanel } from "@/components/fleet-panel"
import { HandshakePanel } from "@/components/handshake-panel"
import { AdiPanel } from "@/components/adi-panel"
import { WasmPanel } from "@/components/wasm-panel"
import { FrameTelemetry } from "@/components/frame-telemetry"
import { EventLog } from "@/components/event-log"

export default function Page() {
  const { data, live, setLive } = useTelemetry(1200)

  return (
    <main className="mx-auto flex min-h-screen max-w-[1400px] flex-col gap-4 p-4 sm:p-6">
      <ConsoleHeader data={data} live={live} onToggleLive={() => setLive((v) => !v)} />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <FleetPanel data={data} />
        <FrameTelemetry data={data} />
        <HandshakePanel data={data} />
        <AdiPanel data={data} />
        <WasmPanel data={data} />
        <EventLog data={data} />
      </div>

      <footer className="flex flex-col items-center justify-between gap-2 border-t border-border pt-4 font-mono text-[11px] text-muted sm:flex-row">
        <span>
          simulated telemetry feed · no live node attached · models{" "}
          <span className="text-cyan/80">src/main.rs</span> control plane
        </span>
        <span>GPL-3.0 · YuKKi OS v6.6.6 Inet3</span>
      </footer>
    </main>
  )
}
