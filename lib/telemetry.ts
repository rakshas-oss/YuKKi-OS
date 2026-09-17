import type {
  AdiSnapshot,
  FrameSample,
  HandshakeEvent,
  LogEntry,
  MeshNode,
  Telemetry,
  WasmExecution,
} from "./types"

// A deterministic-ish, self-contained telemetry simulator.
//
// There is no live Rust node reachable from this web preview, so this module
// synthesizes a realistic control-plane feed grounded in the crate's model:
// a 128-connection bootstrap, authenticated peers, ADI retunes, Wasmtime
// executions, and a Lorenz integrator with an epsilon-threshold failsafe.

const MAX_CONNECTIONS = 128
const EPSILON = 42.0

const WASM_MODULES = [
  "route_optimizer.wasm",
  "frame_validator.wasm",
  "peer_scorer.wasm",
  "entropy_mixer.wasm",
  "payload_weave.wasm",
]

const PEER_CITIES = [
  "fra1",
  "iad1",
  "sfo1",
  "sin1",
  "nrt1",
  "gru1",
  "syd1",
  "cdg1",
  "lhr1",
  "ams1",
  "hkg1",
  "bom1",
]

let seqCounter = 1
let eventCounter = 1
let logCounter = 1

function rand(min: number, max: number) {
  return min + Math.random() * (max - min)
}

function pick<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)]
}

function hex(bytes: number) {
  const chars = "0123456789abcdef"
  let out = ""
  for (let i = 0; i < bytes * 2; i++) out += chars[Math.floor(Math.random() * 16)]
  return out
}

// Lorenz attractor state used to drive frame divergence.
const lorenz = { x: 0.1, y: 0, z: 0 }
const SIGMA = 10
const RHO = 28
const BETA = 8 / 3

function stepLorenz(dt: number) {
  const { x, y, z } = lorenz
  lorenz.x += SIGMA * (y - x) * dt
  lorenz.y += (x * (RHO - z) - y) * dt
  lorenz.z += (x * y - BETA * z) * dt
}

function divergenceMagnitude() {
  return Math.sqrt(lorenz.x ** 2 + lorenz.y ** 2 + lorenz.z ** 2)
}

function resetLorenz() {
  lorenz.x = 0.1
  lorenz.y = 0
  lorenz.z = 0
}

function makeBootstrap(): MeshNode {
  return {
    id: "boot-0",
    role: "bootstrap",
    address: "0.0.0.0:7660",
    handshake: "authenticated",
    connections: 96,
    latencyMs: 3,
    queueDepth: 120,
    hardwareProfile: "accelerated",
    uptimeSec: 84_233,
    framesPerSec: 0,
    divergence: 0,
    lastPskProofOk: true,
  }
}

function makePeer(i: number): MeshNode {
  const city = PEER_CITIES[i % PEER_CITIES.length]
  return {
    id: `peer-${city}-${i}`,
    role: "peer",
    address: `10.60.${i}.${Math.floor(rand(2, 250))}:9999`,
    handshake: Math.random() > 0.12 ? "authenticated" : "handshaking",
    connections: Math.floor(rand(1, 8)),
    latencyMs: Math.round(rand(6, 140)),
    queueDepth: Math.random() > 0.4 ? 120 : 60,
    hardwareProfile: Math.random() > 0.5 ? "accelerated" : "baseline",
    uptimeSec: Math.floor(rand(120, 60_000)),
    framesPerSec: Math.round(rand(40, 220)),
    divergence: rand(0, 30),
    lastPskProofOk: Math.random() > 0.05,
  }
}

export function initialTelemetry(): Telemetry {
  const nodes: MeshNode[] = [makeBootstrap(), ...Array.from({ length: 7 }, (_, i) => makePeer(i + 1))]

  const adi: AdiSnapshot = {
    encodeThroughputMbps: 918,
    queueEfficiencyPct: 91,
    queueDepth: 120,
    hardwareProfile: "accelerated",
    pufEntropyBits: 256,
    retunes: 3,
  }

  const frames: FrameSample[] = Array.from({ length: 48 }, () => {
    stepLorenz(0.01)
    return {
      seq: seqCounter++,
      divergence: divergenceMagnitude(),
      fluidity: rand(0.2, 0.95),
      drag: rand(0.05, 0.4),
      failsafe: false,
    }
  })

  const logs: LogEntry[] = [
    log("ok", "boot", "bootstrap bound 0.0.0.0:7660 (128-connection cap)"),
    log("ok", "adi", "auto-tune complete: queue_depth=120 profile=accelerated"),
    log("ok", "puf", "virtual PUF seeded 256 bits from micro-timing jitter"),
    log("info", "mesh", "7 authenticated peers registered"),
  ]

  return {
    epoch: 0,
    psk: hex(32),
    epsilon: EPSILON,
    maxConnections: MAX_CONNECTIONS,
    nodes,
    handshakes: [],
    adi,
    wasm: [],
    frames,
    logs,
  }
}

function log(level: LogEntry["level"], source: string, message: string): LogEntry {
  return { id: logCounter++, ts: Date.now(), level, source, message }
}

function makeHandshake(): HandshakeEvent {
  const peer = `10.60.${Math.floor(rand(1, 40))}.${Math.floor(rand(2, 250))}`
  const ok = Math.random() > 0.14
  const stage: HandshakeEvent["stage"] = ok ? "aead-ready" : pick(["psk-proof", "x25519-exchange", "rejected"])
  return {
    id: eventCounter++,
    ts: Date.now(),
    peer,
    stage,
    ok,
    rttMs: Math.round(rand(4, 90)),
  }
}

function makeWasm(): WasmExecution {
  const fuelBudget = 1_000_000
  const roll = Math.random()
  const status: WasmExecution["status"] = roll > 0.9 ? "out-of-fuel" : roll > 0.82 ? "trapped" : "ok"
  const fuelUsed =
    status === "out-of-fuel" ? fuelBudget : Math.floor(rand(20_000, 780_000))
  const memPagesMax = 256
  return {
    id: eventCounter++,
    ts: Date.now(),
    module: pick(WASM_MODULES),
    fuelBudget,
    fuelUsed,
    memPagesMax,
    memPagesUsed: Math.floor(rand(4, status === "trapped" ? 256 : 180)),
    status,
    durationUs: Math.round(rand(80, 4200)),
  }
}

// Advance the whole world one tick and return an updated snapshot.
export function tick(prev: Telemetry): Telemetry {
  const epoch = prev.epoch + 1

  // Advance Lorenz frames.
  const newFrames: FrameSample[] = []
  const framesThisTick = 3
  const logs: LogEntry[] = []
  for (let i = 0; i < framesThisTick; i++) {
    stepLorenz(0.012)
    let failsafe = false
    let d = divergenceMagnitude()
    if (d > prev.epsilon) {
      resetLorenz()
      failsafe = true
      d = divergenceMagnitude()
      logs.push(log("warn", "lorenz", `epsilon failsafe fired (d>${prev.epsilon}) — attractor reset to stable point`))
    }
    newFrames.push({
      seq: seqCounter++,
      divergence: d,
      fluidity: rand(0.2, 0.95),
      drag: rand(0.05, 0.4),
      failsafe,
    })
  }
  const frames = [...prev.frames, ...newFrames].slice(-64)

  // Nodes drift.
  const nodes = prev.nodes.map((n) => {
    if (n.role === "bootstrap") {
      const connections = clamp(
        n.connections + Math.round(rand(-3, 4)),
        60,
        prev.maxConnections,
      )
      return { ...n, connections, uptimeSec: n.uptimeSec + 1 }
    }
    const jitter = rand(-8, 8)
    const handshake =
      n.handshake === "handshaking" && Math.random() > 0.6 ? "authenticated" : n.handshake
    return {
      ...n,
      handshake,
      latencyMs: Math.max(4, Math.round(n.latencyMs + jitter)),
      framesPerSec: clamp(Math.round(n.framesPerSec + rand(-12, 12)), 20, 240),
      connections: clamp(n.connections + Math.round(rand(-1, 1)), 0, 12),
      divergence: newFrames[newFrames.length - 1]?.divergence ?? n.divergence,
      uptimeSec: n.uptimeSec + 1,
    }
  })

  // Occasionally add a peer or drop one.
  if (Math.random() > 0.9 && nodes.length < 14) {
    const p = makePeer(nodes.length + Math.floor(rand(1, 40)))
    nodes.push(p)
    logs.push(log("info", "mesh", `peer ${p.id} handshaking from ${p.address}`))
  } else if (Math.random() > 0.94 && nodes.filter((n) => n.role === "peer").length > 4) {
    const idx = nodes.findIndex((n) => n.role === "peer")
    if (idx >= 0) {
      const dropped = nodes.splice(idx, 1)[0]
      logs.push(log("warn", "mesh", `peer ${dropped.id} disconnected (session closed)`))
    }
  }

  // Handshake events.
  const handshakeEvents: HandshakeEvent[] = []
  if (Math.random() > 0.45) {
    const h = makeHandshake()
    handshakeEvents.push(h)
    if (!h.ok) {
      logs.push(log("error", "crypto", `handshake rejected from ${h.peer} @ ${h.stage}`))
    } else {
      logs.push(log("ok", "crypto", `AEAD keys derived for ${h.peer} (${h.rttMs}ms)`))
    }
  }
  const handshakes = [...handshakeEvents, ...prev.handshakes].slice(0, 40)

  // Wasm executions.
  const wasmEvents: WasmExecution[] = []
  if (Math.random() > 0.5) {
    const w = makeWasm()
    wasmEvents.push(w)
    if (w.status === "out-of-fuel") {
      logs.push(log("warn", "wasm", `${w.module} halted: fuel budget exhausted`))
    } else if (w.status === "trapped") {
      logs.push(log("error", "wasm", `${w.module} trapped — isolated, host memory intact`))
    }
  }
  const wasm = [...wasmEvents, ...prev.wasm].slice(0, 40)

  // ADI occasionally retunes.
  let adi = prev.adi
  if (Math.random() > 0.93) {
    const newDepth: 60 | 120 = adi.queueDepth === 120 ? 60 : 120
    adi = {
      ...adi,
      queueDepth: newDepth,
      queueEfficiencyPct: clamp(Math.round(rand(78, 97)), 60, 100),
      encodeThroughputMbps: Math.round(rand(720, 1020)),
      hardwareProfile: newDepth === 120 ? "accelerated" : "baseline",
      retunes: adi.retunes + 1,
    }
    logs.push(
      log("info", "adi", `retune: queue_depth=${newDepth} profile=${adi.hardwareProfile} eff=${adi.queueEfficiencyPct}%`),
    )
  } else {
    adi = {
      ...adi,
      queueEfficiencyPct: clamp(adi.queueEfficiencyPct + Math.round(rand(-2, 2)), 60, 100),
      encodeThroughputMbps: clamp(adi.encodeThroughputMbps + Math.round(rand(-14, 14)), 680, 1040),
    }
  }

  const mergedLogs = [...logs.reverse(), ...prev.logs].slice(0, 120)

  return {
    ...prev,
    epoch,
    nodes,
    handshakes,
    adi,
    wasm,
    frames,
    logs: mergedLogs,
  }
}

function clamp(v: number, min: number, max: number) {
  return Math.max(min, Math.min(max, v))
}
