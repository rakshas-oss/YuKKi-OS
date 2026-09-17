import type { Metadata, Viewport } from "next"
import { GeistSans } from "geist/font/sans"
import { GeistMono } from "geist/font/mono"
import "./globals.css"

export const metadata: Metadata = {
  title: "YuKKi OS · Mesh Operations Console",
  description:
    "Real-time operations console for YuKKi OS v6.6.6 (Inet3 Edition) — authenticated mesh fleet, X25519/AEAD control plane, ADI auto-tuning, Wasmtime sandbox, and Lorenz frame telemetry.",
  generator: "v0.app",
}

export const viewport: Viewport = {
  themeColor: "#05070a",
  colorScheme: "dark",
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className={`${GeistSans.variable} ${GeistMono.variable}`}>
      <body>{children}</body>
    </html>
  )
}
