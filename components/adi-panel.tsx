"use client"

import type { Telemetry } from "@/lib/types"
import { Bar, Metric, Panel, Tag } from "./primitives"

export function AdiPanel({ data }: { data: Telemetry }) {
  const adi = data.adi
  return (
    <Panel
      title="ADI Auto-Tuner"
      hint="dynamic integration · queue + hardware profile"
      right={<Tag tone={adi.hardwareProfile === "accelerated" ? "violet" : "muted"}>{adi.hardwareProfile}</Tag>}
    >
      <div className="grid grid-cols-2 gap-4">
        <Metric label="queue depth" value={adi.queueDepth} tone="cyan" />
        <Metric label="throughput" value={adi.encodeThroughputMbps} unit="Mbps" tone="fg" />
      </div>

      <div className="mt-4 flex flex-col gap-3">
        <div className="flex flex-col gap-1">
          <div className="flex items-center justify-between font-mono text-[11px]">
            <span className="text-muted">queue efficiency</span>
            <span className="text-fg">{adi.queueEfficiencyPct}%</span>
          </div>
          <Bar value={adi.queueEfficiencyPct} tone={adi.queueEfficiencyPct > 85 ? "green" : "amber"} />
        </div>

        <div className="flex flex-col gap-1">
          <div className="flex items-center justify-between font-mono text-[11px]">
            <span className="text-muted">PUF entropy seed</span>
            <span className="text-fg">{adi.pufEntropyBits} bits</span>
          </div>
          <Bar value={adi.pufEntropyBits} max={256} tone="violet" />
        </div>
      </div>

      <div className="mt-4 flex items-center justify-between border-t border-border pt-3 font-mono text-[11px]">
        <span className="text-muted">retunes this session</span>
        <span className="text-cyan">{adi.retunes}</span>
      </div>
    </Panel>
  )
}
