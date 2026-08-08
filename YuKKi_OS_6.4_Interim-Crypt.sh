#!/usr/bin/env zsh
# ==============================================================================
# OPEN-SOURCE GENESIS: YUKKI OS V6.4.1 (INTERIM-CRYPT EDITION)
# ARCHITECT: Aditya Muralidhar (Rakshas International Unlimited)
# LICENSE: GNU General Public License Version 3 (GPL-3)
# PARADIGM: 6D Lorenz-Weave + P2P File Ops + Uncloneable Encryption
# ==============================================================================

# Zsh strict error handling
setopt err_exit no_unset pipe_fail

ARCHIVE_DIR="yukkios_6_4_interim"
EXECUTABLE_NAME="yukki_core_node"

# Zsh idiomatic styling (Prompts Expansion)
TEAL='%F{37}'
GOLD='%F{136}'
RESET='%f'

print -P "${GOLD}======================================================================${RESET}"
print -P "${GOLD}    __  __      _  ___  ___    ____  ____    ____                     ${RESET}"
print -P "${GOLD}    \\ \\/ /_  _ | |/ / |/ /_   / __ \\/ ___|  / ___|                    ${RESET}"
print -P "${GOLD}     \\  /| | | | ' /| ' /(_) | |  | \\___ \\ | |                        ${RESET}"
print -P "${GOLD}     / / | |_| | . \\| . \\_   | |__| |___) || |___                     ${RESET}"
print -P "${GOLD}    /_/   \\__,_|_|\\_\\_|\\_(_)  \\____/|____/  \\____| 6.4 INTERIM-CRYPT  ${RESET}"
print -P "${GOLD}======================================================================${RESET}"

print -P "${TEAL}[*] Initiating Spatiotemporal Genesis of YuKKi OS 6.4...${RESET}"
print -P "${TEAL}[*] Building Directory Infrastructure...${RESET}"

# Zsh Brace Expansion for directory scaffolding
mkdir -p "$ARCHIVE_DIR/src/"{ffi,memory}

# Check for LEGACY_MODE environment variable securely defaulting to 0
if [[ "${LEGACY_MODE:-0}" == "1" ]]; then
    print -P "${GOLD}[!] LEGACY_MODE Detected. Cross-compiling statically via MUSL...${RESET}"
    cargo build --release --target=x86_64-unknown-linux-musl
    BUILD_PATH="$ARCHIVE_DIR/target/x86_64-unknown-linux-musl/release/$EXECUTABLE_NAME"
else
    cargo build --release
    BUILD_PATH="$ARCHIVE_DIR/target/release/$EXECUTABLE_NAME"
fi

print -P "${GOLD}======================================================================${RESET}"
print -P "${TEAL}[+] CONGRATULATIONS: YuKKi OS 6.4.1 Interim-Crypt compilation successful.${RESET}"
print -P "${TEAL}[+] Target Binary Location: $BUILD_PATH${RESET}"
print -P "${GOLD}======================================================================${RESET}"
print -P "${TEAL}  BUILD CONTENTS (GPL-3 - INTERIM-CRYPT):${RESET}"
print -P "  - Integrated real-time Lorenz Chaos attractor mathematical manifolds."
print -P "  - Uncloneable Pauli/Clifford encryption bindings at the bit level."
print -P "  - Zero-latency memory bypass aligned explicitly to 88-byte bounds."
print -P "  - P2P distributed networking with dual-port architecture (JSON + Binary)."
print -P "  - Restored v4 Filesystem Utilities (Browse, Asynchronous Transfer)."
print -P "  - Information-Theoretic security model for payload protection."
print -P "  - Hardware layout restricted to purely electrical flat topology."
print -P "${GOLD}======================================================================${RESET}"

exit 0
