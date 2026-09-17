"use client"

import { useEffect, useRef, useState } from "react"
import { initialTelemetry, tick } from "@/lib/telemetry"
import type { Telemetry } from "@/lib/types"

export function useTelemetry(intervalMs = 1200) {
  const [data, setData] = useState<Telemetry>(() => initialTelemetry())
  const [live, setLive] = useState(true)
  const liveRef = useRef(live)
  liveRef.current = live

  useEffect(() => {
    const handle = setInterval(() => {
      if (!liveRef.current) return
      setData((prev) => tick(prev))
    }, intervalMs)
    return () => clearInterval(handle)
  }, [intervalMs])

  return { data, live, setLive }
}
