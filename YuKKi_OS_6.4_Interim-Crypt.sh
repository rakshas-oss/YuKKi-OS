#!/usr/bin/env bash
# ==============================================================================
# OPEN-SOURCE GENESIS: YUKKI OS V6.4.0 (INTERIM-CRYPT EDITION)
# ARCHITECT: Aditya Muralidhar (Rakshas International Unlimited)
# LICENSE: GNU General Public License Version 3 (GPL-3)
# PARADIGM: 6D Lorenz-Weave + P2P File Ops + Uncloneable Encryption
# ==============================================================================

# Bash strict error handling
set -euo pipefail

EXECUTABLE_NAME="yukki_core_node"

# Bash color styling
TEAL='\033[38;5;37m'
GOLD='\033[38;5;136m'
RESET='\033[0m'

echo -e "${GOLD}======================================================================${RESET}"
echo -e "${GOLD}    __  __      _  ___  ___    ____  ____    ____                     ${RESET}"
echo -e "${GOLD}    \\ \\/ /_  _ | |/ / |/ /_   / __ \\/ ___|  / ___|                    ${RESET}"
echo -e "${GOLD}     \\  /| | | | ' /| ' /(_) | |  | \\___ \\ | |                        ${RESET}"
echo -e "${GOLD}     / / | |_| | . \\| . \\_   | |__| |___) || |___                     ${RESET}"
echo -e "${GOLD}    /_/   \\__,_|_|\\_\\_|\\_(_)  \\____/|____/  \\____| 6.4 INTERIM-CRYPT  ${RESET}"
echo -e "${GOLD}======================================================================${RESET}"

echo -e "${TEAL}[*] Initiating Spatiotemporal Genesis of YuKKi OS 6.4...${RESET}"
echo -e "${TEAL}[*] Using persistent repository source layout...${RESET}"
mkdir -p src/memory

# Check for LEGACY_MODE environment variable securely defaulting to 0
if [[ "${LEGACY_MODE:-0}" == "1" ]]; then
    echo -e "${GOLD}[!] LEGACY_MODE Detected. Cross-compiling statically via MUSL...${RESET}"
    cargo build --release --target=x86_64-unknown-linux-musl
    BUILD_PATH="target/x86_64-unknown-linux-musl/release/$EXECUTABLE_NAME"
else
    cargo build --release
    BUILD_PATH="target/release/$EXECUTABLE_NAME"
fi

echo -e "${GOLD}======================================================================${RESET}"
echo -e "${TEAL}[+] CONGRATULATIONS: YuKKi OS 6.4.0 Interim-Crypt compilation successful.${RESET}"
echo -e "${TEAL}[+] Target Binary Location: $BUILD_PATH${RESET}"
echo -e "${GOLD}======================================================================${RESET}"
echo -e "${TEAL}  BUILD CONTENTS (GPL-3 - INTERIM-CRYPT):${RESET}"
echo -e "  - Integrated real-time Lorenz Chaos attractor mathematical manifolds."
echo -e "  - Uncloneable Pauli/Clifford encryption bindings at the bit level."
echo -e "  - Zero-latency memory bypass aligned explicitly to 88-byte bounds."
echo -e "  - P2P distributed networking with dual-port architecture (JSON + Binary)."
echo -e "  - Restored v4 Filesystem Utilities (Browse, Asynchronous Transfer)."
echo -e "  - Information-Theoretic security model for payload protection."
echo -e "  - Hardware layout restricted to purely electrical flat topology."
echo -e "${GOLD}======================================================================${RESET}"

exit 0
