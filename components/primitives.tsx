import type { ReactNode } from "react"

export function Panel({
  title,
  hint,
  right,
  children,
  className = "",
}: {
  title: string
  hint?: string
  right?: ReactNode
  children: ReactNode
  className?: string
}) {
  return (
    <section
      className={`flex flex-col rounded-lg border border-border bg-surface/70 backdrop-blur-sm ${className}`}
    >
      <header className="flex items-center justify-between gap-3 border-b border-border px-4 py-3">
        <div className="flex min-w-0 flex-col">
          <h2 className="font-mono text-[11px] uppercase tracking-[0.18em] text-cyan">{title}</h2>
          {hint ? <span className="truncate text-[11px] text-muted">{hint}</span> : null}
        </div>
        {right}
      </header>
      <div className="flex-1 p-4">{children}</div>
    </section>
  )
}

export function StatusDot({
  tone,
  pulse = false,
}: {
  tone: "green" | "amber" | "red" | "cyan" | "muted"
  pulse?: boolean
}) {
  const map: Record<string, string> = {
    green: "bg-green",
    amber: "bg-amber",
    red: "bg-red",
    cyan: "bg-cyan",
    muted: "bg-muted",
  }
  return (
    <span className="relative inline-flex h-2 w-2">
      <span className={`inline-flex h-2 w-2 rounded-full ${map[tone]} ${pulse ? "pulse-dot" : ""}`} />
    </span>
  )
}

export function Metric({
  label,
  value,
  unit,
  tone = "fg",
}: {
  label: string
  value: string | number
  unit?: string
  tone?: "fg" | "cyan" | "amber" | "red" | "green"
}) {
  const toneMap: Record<string, string> = {
    fg: "text-fg-bright",
    cyan: "text-cyan",
    amber: "text-amber",
    red: "text-red",
    green: "text-green",
  }
  return (
    <div className="flex flex-col gap-1">
      <span className="font-mono text-[10px] uppercase tracking-[0.16em] text-muted">{label}</span>
      <span className={`font-mono text-2xl leading-none ${toneMap[tone]}`}>
        {value}
        {unit ? <span className="ml-1 text-xs text-muted">{unit}</span> : null}
      </span>
    </div>
  )
}

export function Bar({
  value,
  max = 100,
  tone = "cyan",
}: {
  value: number
  max?: number
  tone?: "cyan" | "amber" | "red" | "green" | "violet"
}) {
  const pct = Math.max(0, Math.min(100, (value / max) * 100))
  const toneMap: Record<string, string> = {
    cyan: "bg-cyan",
    amber: "bg-amber",
    red: "bg-red",
    green: "bg-green",
    violet: "bg-violet",
  }
  return (
    <div className="h-1.5 w-full overflow-hidden rounded-full bg-surface-2">
      <div
        className={`h-full rounded-full ${toneMap[tone]} transition-all duration-500`}
        style={{ width: `${pct}%` }}
      />
    </div>
  )
}

export function Tag({
  children,
  tone = "muted",
}: {
  children: ReactNode
  tone?: "cyan" | "amber" | "red" | "green" | "violet" | "muted"
}) {
  const toneMap: Record<string, string> = {
    cyan: "border-cyan/30 text-cyan bg-cyan/5",
    amber: "border-amber/30 text-amber bg-amber/5",
    red: "border-red/30 text-red bg-red/5",
    green: "border-green/30 text-green bg-green/5",
    violet: "border-violet/30 text-violet bg-violet/5",
    muted: "border-border-strong text-muted bg-surface-2",
  }
  return (
    <span
      className={`inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider ${toneMap[tone]}`}
    >
      {children}
    </span>
  )
}
