"use client"

import type { MeshNode, Telemetry } from "@/lib/types"
import { Bar, Panel, StatusDot, Tag } from "./primitives"

function handshakeTone(state: MeshNode["handshake"]) {
  if (state === "authenticated") return "green" as const
  if (state === "handshaking") return "amber" as const
  return "red" as const
}

function NodeRow({ node, max }: { node: MeshNode; max: number }) {
  return (
    <li className="flex flex-col gap-2 rounded-md border border-border bg-surface-2/60 p-3">
      <div className="flex items-center justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2">
          <StatusDot tone={handshakeTone(node.handshake)} pulse={node.handshake !== "rejected"} />
          <span className="truncate font-mono text-xs text-fg-bright">{node.id}</span>
        </div>
        <Tag tone={node.role === "bootstrap" ? "violet" : "cyan"}>{node.role}</Tag>
      </div>

      <div className="flex items-center justify-between font-mono text-[11px] text-muted">
        <span className="truncate">{node.address}</span>
        <span className={node.lastPskProofOk ? "text-green" : "text-red"}>
          {node.lastPskProofOk ? "psk ok" : "psk fail"}
        </span>
      </div>

      <div className="grid grid-cols-3 gap-2 font-mono text-[11px]">
        <div className="flex flex-col">
          <span className="text-muted">rtt</span>
          <span className="text-fg">{node.latencyMs}ms</span>
        </div>
        <div className="flex flex-col">
          <span className="text-muted">frames/s</span>
          <span className="text-fg">{node.framesPerSec}</span>
        </div>
        <div className="flex flex-col">
          <span className="text-muted">q-depth</span>
          <span className="text-cyan">{node.queueDepth}</span>
        </div>
      </div>

      {node.role === "bootstrap" ? (
        <div className="flex flex-col gap-1">
          <div className="flex items-center justify-between font-mono text-[10px] text-muted">
            <span>connections</span>
            <span className="text-fg">
              {node.connections}/{max}
            </span>
          </div>
          <Bar value={node.connections} max={max} tone={node.connections > max * 0.85 ? "amber" : "cyan"} />
        </div>
      ) : null}
    </li>
  )
}

export function FleetPanel({ data }: { data: Telemetry }) {
  const sorted = [...data.nodes].sort((a, b) => (a.role === "bootstrap" ? -1 : b.role === "bootstrap" ? 1 : 0))
  return (
    <Panel
      title="Node Fleet"
      hint="authenticated peer mesh"
      right={<Tag tone="cyan">{data.nodes.length} nodes</Tag>}
      className="lg:row-span-2"
    >
      <ul className="flex max-h-[560px] flex-col gap-2 overflow-y-auto pr-1">
        {sorted.map((n) => (
          <NodeRow key={n.id} node={n} max={data.maxConnections} />
        ))}
      </ul>
    </Panel>
  )
}
