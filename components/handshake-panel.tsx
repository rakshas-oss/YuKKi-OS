"use client"

import type { HandshakeEvent, Telemetry } from "@/lib/types"
import { Panel, Tag } from "./primitives"

function stageTone(e: HandshakeEvent) {
  if (e.ok) return "green" as const
  if (e.stage === "rejected") return "red" as const
  return "amber" as const
}

function shortPsk(psk: string) {
  return `${psk.slice(0, 8)}…${psk.slice(-8)}`
}

export function HandshakePanel({ data }: { data: Telemetry }) {
  const recent = data.handshakes.slice(0, 8)
  const ok = data.handshakes.filter((h) => h.ok).length
  const total = data.handshakes.length || 1

  return (
    <Panel
      title="Control Plane"
      hint="X25519 · HKDF-SHA256 · ChaCha20-Poly1305"
      right={<Tag tone="green">{Math.round((ok / total) * 100)}% ok</Tag>}
    >
      <div className="mb-3 flex flex-col gap-2 rounded-md border border-border bg-surface-2/60 p-3 font-mono text-[11px]">
        <div className="flex items-center justify-between">
          <span className="text-muted">shared PSK (32B)</span>
          <span className="text-fg">{shortPsk(data.psk)}</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-muted">frame cap</span>
          <span className="text-fg">64 KiB · len-prefixed</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-muted">aead nonce</span>
          <span className="text-fg">12B · directional keys</span>
        </div>
      </div>

      <ul className="flex flex-col gap-1.5">
        {recent.length === 0 ? (
          <li className="py-6 text-center font-mono text-[11px] text-muted">awaiting handshakes…</li>
        ) : (
          recent.map((e) => (
            <li
              key={e.id}
              className="flex items-center justify-between gap-2 rounded border border-border/60 bg-surface-2/40 px-2.5 py-1.5"
            >
              <div className="flex min-w-0 items-center gap-2">
                <Tag tone={stageTone(e)}>{e.stage}</Tag>
                <span className="truncate font-mono text-[11px] text-muted">{e.peer}</span>
              </div>
              <span className="font-mono text-[11px] text-fg">{e.rttMs}ms</span>
            </li>
          ))
        )}
      </ul>
    </Panel>
  )
}
