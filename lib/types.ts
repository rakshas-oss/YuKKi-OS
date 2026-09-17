// Domain types for the YuKKi OS mesh operations console.
// These mirror concepts from the Rust crate (v6.6.6, Inet3 Edition):
//   - authenticated node fleet (bootstrap + peers, 128-connection cap)
//   - X25519 + PSK -> HKDF -> ChaCha20-Poly1305 control plane
//   - ADI auto-tuner (queue depth 60/120, hardware profile)
//   - Wasmtime sandbox (fuel- and memory-bounded execution)
//   - Lorenz frame generation with epsilon-threshold failsafe

export type NodeRole = "bootstrap" | "peer"

export type HandshakeState = "authenticated" | "handshaking" | "rejected"

export interface MeshNode {
  id: string
  role: NodeRole
  address: string
  handshake: HandshakeState
  connections: number // active authenticated connections
  latencyMs: number
  queueDepth: 60 | 120
  hardwareProfile: "baseline" | "accelerated"
  uptimeSec: number
  framesPerSec: number
  divergence: number // current Lorenz divergence
  lastPskProofOk: boolean
}

export interface HandshakeEvent {
  id: number
  ts: number
  peer: string
  stage: "x25519-exchange" | "psk-proof" | "hkdf-derive" | "aead-ready" | "rejected"
  ok: boolean
  rttMs: number
}

export interface AdiSnapshot {
  encodeThroughputMbps: number
  queueEfficiencyPct: number
  queueDepth: 60 | 120
  hardwareProfile: "baseline" | "accelerated"
  pufEntropyBits: number
  retunes: number
}

export interface WasmExecution {
  id: number
  ts: number
  module: string
  fuelBudget: number
  fuelUsed: number
  memPagesMax: number
  memPagesUsed: number
  status: "ok" | "trapped" | "out-of-fuel"
  durationUs: number
}

export interface FrameSample {
  seq: number
  divergence: number
  fluidity: number
  drag: number
  failsafe: boolean // epsilon-threshold reset fired
}

export type LogLevel = "info" | "warn" | "error" | "ok"

export interface LogEntry {
  id: number
  ts: number
  level: LogLevel
  source: string
  message: string
}

export interface Telemetry {
  epoch: number
  psk: string
  epsilon: number
  maxConnections: number
  nodes: MeshNode[]
  handshakes: HandshakeEvent[]
  adi: AdiSnapshot
  wasm: WasmExecution[]
  frames: FrameSample[]
  logs: LogEntry[]
}
