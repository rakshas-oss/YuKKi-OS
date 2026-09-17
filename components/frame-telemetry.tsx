"use client"

import type { Telemetry } from "@/lib/types"
import { Metric, Panel, Tag } from "./primitives"

export function FrameTelemetry({ data }: { data: Telemetry }) {
  const frames = data.frames
  const eps = data.epsilon
  const last = frames[frames.length - 1]
  const failsafes = frames.filter((f) => f.failsafe).length

  const w = 100
  const h = 40
  const maxD = Math.max(eps * 1.1, ...frames.map((f) => f.divergence))
  const step = frames.length > 1 ? w / (frames.length - 1) : w

  const points = frames
    .map((f, i) => `${(i * step).toFixed(2)},${(h - (f.divergence / maxD) * h).toFixed(2)}`)
    .join(" ")

  const epsY = h - (eps / maxD) * h

  return (
    <Panel
      title="Lorenz Frame Telemetry"
      hint="88-byte SpatiotemporalFrame · epsilon failsafe"
      right={<Tag tone={last?.failsafe ? "red" : "cyan"}>seq {last?.seq ?? 0}</Tag>}
    >
      <div className="grid grid-cols-3 gap-4">
        <Metric
          label="divergence"
          value={last?.divergence.toFixed(1) ?? "0.0"}
          tone={(last?.divergence ?? 0) > eps * 0.8 ? "amber" : "cyan"}
        />
        <Metric label="epsilon" value={eps.toFixed(0)} tone="red" />
        <Metric label="failsafes" value={failsafes} tone={failsafes > 0 ? "amber" : "green"} />
      </div>

      <div className="mt-4 overflow-hidden rounded-md border border-border bg-base/60 p-2">
        <svg viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" className="h-28 w-full">
          <line
            x1="0"
            y1={epsY}
            x2={w}
            y2={epsY}
            stroke="var(--color-red)"
            strokeWidth="0.4"
            strokeDasharray="1.5 1.5"
            opacity="0.7"
          />
          <polyline
            points={points}
            fill="none"
            stroke="var(--color-cyan)"
            strokeWidth="0.7"
            vectorEffect="non-scaling-stroke"
          />
          {frames.map((f, i) =>
            f.failsafe ? (
              <circle
                key={f.seq}
                cx={(i * step).toFixed(2)}
                cy={(h - (f.divergence / maxD) * h).toFixed(2)}
                r="0.9"
                fill="var(--color-red)"
              />
            ) : null,
          )}
        </svg>
      </div>

      <div className="mt-3 grid grid-cols-2 gap-3 font-mono text-[11px]">
        <div className="flex items-center justify-between rounded border border-border/60 bg-surface-2/40 px-2.5 py-1.5">
          <span className="text-muted">fluidity</span>
          <span className="text-fg">{last?.fluidity.toFixed(3) ?? "—"}</span>
        </div>
        <div className="flex items-center justify-between rounded border border-border/60 bg-surface-2/40 px-2.5 py-1.5">
          <span className="text-muted">drag</span>
          <span className="text-fg">{last?.drag.toFixed(3) ?? "—"}</span>
        </div>
      </div>
    </Panel>
  )
}
