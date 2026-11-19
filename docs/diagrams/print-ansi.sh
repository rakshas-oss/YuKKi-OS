#!/usr/bin/env bash
# ANSI true-colour architecture sketch for YuKKi-OS.
set -euo pipefail

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  cyan=$'\033[38;2;62;224;245m'; blue=$'\033[38;2;94;184;255m'
  violet=$'\033[38;2;190;153;255m'; gold=$'\033[38;2;255;211;116m'
  orange=$'\033[38;2;255;170;103m'; green=$'\033[38;2;103;224;169m'
  dim=$'\033[38;2;145;166;186m'; bold=$'\033[1m'; reset=$'\033[0m'
else
  cyan= blue= violet= gold= orange= green= dim= bold= reset=
fi
emit() { printf '%b\n' "$*"; }

emit "${bold}${cyan}╔══════════════════════════════════════════════════════════════════════════════╗${reset}"
emit "${bold}${cyan}║  YuKKi-OS  /  CONTROL + RUNTIME PLANE                                      ║${reset}"
emit "${cyan}╚══════════════════════════════════════════════════════════════════════════════╝${reset}"
emit "${blue} INPUTS${reset}       peers · stream producers · browser clients · multivariate sources"
emit "    │"
emit "${cyan}    ▼${reset}  ${bold}AUTHENTICATED COORDINATION${reset}  X25519 · PSK · HKDF · ChaCha20-Poly1305"
emit "    │"
emit "${bold}${cyan}┌────────────────────────────────────────────────────────────────────────────┐${reset}"
emit "${cyan}│  YUKKI-OS HOST SERVICES                                                     │${reset}"
emit "${cyan}├──────────────────────────────────┬─────────────────────────────────────────┤${reset}"
emit "${cyan}│${reset} ${blue}STREAMS + GATEWAY${reset}                ${cyan}│${reset} ${violet}WASMTIME GUEST HOST${reset}                      ${cyan}│${reset}"
emit "${cyan}│${reset} YKMC chunks · registry · relay    ${cyan}│${reset} sandbox · compilation · composition    ${cyan}│${reset}"
emit "${cyan}├──────────────────────────────────┼─────────────────────────────────────────┤${reset}"
emit "${cyan}│${reset} ${gold}RUNTIME PRIMITIVES${reset}               ${cyan}│${reset} ${gold}SPATIAL + NATIVE NUMERICS${reset}               ${cyan}│${reset}"
emit "${cyan}│${reset} bounded MPMC · NUMA discovery     ${cyan}│${reset} spatial WASM · JSONL · CPU eigensolver ${cyan}│${reset}"
emit "${cyan}├──────────────────────────────────┴─────────────────────────────────────────┤${reset}"
emit "${cyan}│${reset} ${orange}BROKER ADAPTER${reset}  BRK1/v1 · BRK2/v2  |  WSM1 task/lifecycle when enabled   ${cyan}│${reset}"
emit "${cyan}└────────────────────────────────────────────────────────────────────────────┘${reset}"
emit "                                     ${orange}│ BRK1 / BRK2${reset}"
emit "                                     ${orange}▼${reset}"
emit "${bold}${orange}                       OVERHAULED EXECUTION BROKER${reset}"
emit "                       ${green}CPU baseline${reset} · optional GPU / NPU"
emit "                       BRK2 field 7 reports backend actually selected"
emit ""
emit "${dim}BOUNDARIES: NUMA discovery is not a complete NUMA scheduler. Browser spatial"
emit "WASM is separate from the native node. Benchmark direct BRK2 traffic is not"
emit "WSM1 guest execution. Accelerator use is optional; broker TCP is not TLS.${reset}"
