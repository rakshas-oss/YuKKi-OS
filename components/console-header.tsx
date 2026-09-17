"use client"

import type { Telemetry } from "@/lib/types"
import { StatusDot } from "./primitives"

function fmtUptime(sec: number) {
  const d = Math.floor(sec / 86400)
  const h = Math.floor((sec % 86400) / 3600)
  const m = Math.floor((sec % 3600) / 60)
  return `${d}d ${h}h ${m}m`
}

export function ConsoleHeader({
  data,
  live,
  onToggleLive,
}: {
  data: Telemetry
  live: boolean
  onToggleLive: () => void
}) {
  const boot = data.nodes.find((n) => n.role === "bootstrap")
  const peers = data.nodes.filter((n) => n.role === "peer")
  const authed = peers.filter((p) => p.handshake === "authenticated").length

  return (
    <header className="relative overflow-hidden rounded-lg border border-border bg-surface/70">
      <div className="pointer-events-none absolute inset-0 grid-fade" aria-hidden />
      <div className="relative flex flex-col gap-4 p-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-md border border-cyan/30 bg-cyan/5 font-mono text-cyan">
            <span className="text-sm">Y6</span>
          </div>
          <div className="flex flex-col">
            <h1 className="font-mono text-sm font-medium tracking-wide text-fg-bright">
              YuKKi OS · Mesh Operations Console
            </h1>
            <p className="font-mono text-[11px] text-muted">
              v6.6.6 Inet3 · rakshas-oss/YuKKi-OS
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-2 rounded-md border border-border bg-surface-2 px-3 py-2">
            <StatusDot tone={boot?.handshake === "authenticated" ? "green" : "red"} pulse />
            <span className="font-mono text-[11px] text-fg">
              bootstrap <span className="text-muted">{boot?.address}</span>
            </span>
          </div>
          <div className="flex items-center gap-2 rounded-md border border-border bg-surface-2 px-3 py-2">
            <span className="font-mono text-[11px] text-muted">peers</span>
            <span className="font-mono text-[11px] text-cyan">
              {authed}/{peers.length}
            </span>
          </div>
          <div className="hidden items-center gap-2 rounded-md border border-border bg-surface-2 px-3 py-2 md:flex">
            <span className="font-mono text-[11px] text-muted">uptime</span>
            <span className="font-mono text-[11px] text-fg">{fmtUptime(boot?.uptimeSec ?? 0)}</span>
          </div>
          <button
            type="button"
            onClick={onToggleLive}
            aria-pressed={live}
            className={`flex items-center gap-2 rounded-md border px-3 py-2 font-mono text-[11px] uppercase tracking-wider transition-colors ${
              live
                ? "border-green/40 bg-green/5 text-green"
                : "border-border-strong bg-surface-2 text-muted hover:text-fg"
            }`}
          >
            <StatusDot tone={live ? "green" : "muted"} pulse={live} />
            {live ? "Live" : "Paused"}
          </button>
        </div>
      </div>
    </header>
  )
}
