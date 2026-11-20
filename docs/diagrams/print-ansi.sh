#!/usr/bin/env bash
set -euo pipefail
# ANSI true-colour architecture sketch for YuKKi-OS v6.14.
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
 cyan=$'\033[38;2;62;224;245m'; violet=$'\033[38;2;190;153;255m'; gold=$'\033[38;2;255;211;116m'; orange=$'\033[38;2;255;170;103m'; dim=$'\033[38;2;145;166;186m'; bold=$'\033[1m'; reset=$'\033[0m'
else cyan= violet= gold= orange= dim= bold= reset=; fi
emit(){ printf '%b\n' "$*"; }
emit "${bold}${cyan}╔══════════════════════════════════════════════════════════════════════════════╗"
emit "║  YuKKi-OS / CONTROL + WORKLOAD POLICY                                      ║"
emit "╚══════════════════════════════════════════════════════════════════════════════╝${reset}"
emit "INPUTS → authenticated mesh · gateway · Wasmtime · spatial / multivariate data"
emit "${violet}WORKER POLICY${reset} Control · RealtimeSpatial · Throughput · ExactCpu · Inference"
emit "${gold}BRK2 field 9 deadline · 11 class · 12 logical affinity · 13 preferred NUMA hint${reset}"
emit "${orange}BRK2 → OVERHAULED${reset} isolated pools · broker-local Linux affinity · backend dispatch"
emit "${dim}YuKKi chooses workload meaning and emits hints. Overhauled discovers its own"
emit "process-allowed CPUs and applies best-effort worker affinity. Hints are not"
emit "placement guarantees; no hard RT or NUMA-local memory guarantee is implied.${reset}"
