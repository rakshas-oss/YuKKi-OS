"use client"

import type { LogEntry, Telemetry } from "@/lib/types"
import { Panel } from "./primitives"

function levelColor(level: LogEntry["level"]) {
  switch (level) {
    case "ok":
      return "text-green"
    case "warn":
      return "text-amber"
    case "error":
      return "text-red"
    default:
      return "text-muted"
  }
}

function fmtTime(ts: number) {
  const d = new Date(ts)
  return d.toLocaleTimeString("en-GB", { hour12: false })
}

export function EventLog({ data }: { data: Telemetry }) {
  return (
    <Panel title="Event Stream" hint="control-plane telemetry" className="lg:col-span-2">
      <div className="max-h-64 overflow-y-auto rounded-md border border-border bg-base/60 p-2">
        <ul className="flex flex-col gap-0.5 font-mono text-[11px]">
          {data.logs.map((entry) => (
            <li key={entry.id} className="flex items-start gap-2 px-1 py-0.5 leading-relaxed">
              <span className="shrink-0 text-muted/70">{fmtTime(entry.ts)}</span>
              <span className={`w-12 shrink-0 uppercase ${levelColor(entry.level)}`}>{entry.level}</span>
              <span className="w-14 shrink-0 text-cyan/80">{entry.source}</span>
              <span className="min-w-0 text-fg">{entry.message}</span>
            </li>
          ))}
        </ul>
      </div>
    </Panel>
  )
}
