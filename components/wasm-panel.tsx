"use client"

import type { Telemetry, WasmExecution } from "@/lib/types"
import { Bar, Panel, Tag } from "./primitives"

function statusTone(s: WasmExecution["status"]) {
  if (s === "ok") return "green" as const
  if (s === "out-of-fuel") return "amber" as const
  return "red" as const
}

export function WasmPanel({ data }: { data: Telemetry }) {
  const recent = data.wasm.slice(0, 6)
  const trapped = data.wasm.filter((w) => w.status === "trapped").length

  return (
    <Panel
      title="Rustasm Sandbox"
      hint="Wasmtime · fuel + memory bounded"
      right={trapped > 0 ? <Tag tone="red">{trapped} trapped</Tag> : <Tag tone="green">isolated</Tag>}
    >
      <ul className="flex flex-col gap-2">
        {recent.length === 0 ? (
          <li className="py-6 text-center font-mono text-[11px] text-muted">no executions yet…</li>
        ) : (
          recent.map((w) => (
            <li key={w.id} className="flex flex-col gap-1.5 rounded-md border border-border bg-surface-2/60 p-2.5">
              <div className="flex items-center justify-between gap-2">
                <span className="truncate font-mono text-[11px] text-fg-bright">{w.module}</span>
                <Tag tone={statusTone(w.status)}>{w.status}</Tag>
              </div>
              <div className="flex items-center justify-between font-mono text-[10px] text-muted">
                <span>fuel {(w.fuelUsed / 1000).toFixed(0)}k / {(w.fuelBudget / 1000).toFixed(0)}k</span>
                <span>{w.durationUs}µs</span>
              </div>
              <Bar value={w.fuelUsed} max={w.fuelBudget} tone={statusTone(w.status)} />
              <div className="flex items-center justify-between font-mono text-[10px] text-muted">
                <span>mem {w.memPagesUsed}/{w.memPagesMax} pages</span>
              </div>
              <Bar value={w.memPagesUsed} max={w.memPagesMax} tone="cyan" />
            </li>
          ))
        )}
      </ul>
    </Panel>
  )
}
