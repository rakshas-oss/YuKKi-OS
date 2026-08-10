# DEPRECATED: This script belongs to YuKKi OS v6.4.3 (legacy). Use scripts/deploy/ for current deployment.
#!/usr/bin/env zsh
# ==============================================================================
# OPEN-SOURCE GENESIS: YUKKI OS V6.4.3 (OUT-OF-BAND INTEGRITY EDITION)
# ARCHITECT: Aditya Muralidhar (Rakshas International Unlimited)
# LICENSE: GNU General Public License Version 3 (GPL-3)
# PARADIGM: 6D Lorenz-Weave + OOB Rolling Hash Integrity + 60-Frame Sync Trigger
#           + Node Quarantine/Blacklist + ChaCha20 Payload Binding
# ==============================================================================

# Zsh strict error handling
setopt err_exit no_unset pipe_fail

ARCHIVE_DIR="yukkios_6_4_interim"
EXECUTABLE_NAME="yukkios_6_4_interim"
LEGACY_MODE_VALUE="${LEGACY_MODE:-0}"
SCRIPT_DIR="${0:A:h}"
ARCHIVE_PATH="${SCRIPT_DIR}/${ARCHIVE_DIR}"

typeset -a REQUIRED_FILES=(
    "Cargo.toml"
    "Cargo.lock"
    "build.rs"
    "LICENSE"
    "vault_license.txt"
    "src/main.rs"
    "src/ffi/laminar_api.h"
    "src/ffi/chaos_weave.c"
)

# Zsh idiomatic styling (Prompts Expansion)
TEAL='%F{37}'
GOLD='%F{136}'
RESET='%f'

die() {
    print -u2 -P "${GOLD}[x] $1${RESET}"
    exit 1
}

require_command() {
    local command_name="$1"
    local hint="$2"

    if ! command -v "$command_name" >/dev/null 2>&1; then
        die "Missing required tool: ${command_name}. ${hint}"
    fi
}

ensure_c_compiler() {
    local compiler_name="${${CC:-cc}%% *}"

    if command -v "$compiler_name" >/dev/null 2>&1; then
        return
    fi

    for compiler_name in clang gcc cc; do
        if command -v "$compiler_name" >/dev/null 2>&1; then
            return
        fi
    done

    die "No C compiler detected. Install a C99-compatible compiler or set CC to one."
}

validate_legacy_mode() {
    case "$LEGACY_MODE_VALUE" in
        0|1) ;;
        *)
            die "LEGACY_MODE must be 0 or 1. Received: ${LEGACY_MODE_VALUE}"
            ;;
    esac
}

ensure_required_templates() {
    local relative_path

    for relative_path in "${REQUIRED_FILES[@]}"; do
        if [[ ! -f "${SCRIPT_DIR}/${relative_path}" ]]; then
            die "Required template file is missing: ${SCRIPT_DIR}/${relative_path}"
        fi
    done
}

prepare_archive_dir() {
    local relative_path destination_path

    if [[ -e "$ARCHIVE_PATH" && ! -d "$ARCHIVE_PATH" ]]; then
        die "Cannot create genesis directory because ${ARCHIVE_PATH} already exists and is not a directory."
    fi

    if [[ -d "$ARCHIVE_PATH" ]]; then
        print -P "${TEAL}[*] Existing genesis directory detected. Refreshing scaffold files in place...${RESET}"
    fi

    mkdir -p "$ARCHIVE_PATH/src/ffi" "$ARCHIVE_PATH/src/memory"

    for relative_path in "${REQUIRED_FILES[@]}"; do
        destination_path="${ARCHIVE_PATH}/${relative_path}"
        mkdir -p "${destination_path:h}"
        cp -f "${SCRIPT_DIR}/${relative_path}" "$destination_path"
    done
}

ensure_legacy_target() {
    local musl_compiler="${${CC_x86_64_unknown_linux_musl:-${TARGET_CC:-x86_64-linux-musl-gcc}}%% *}"

    if [[ "$LEGACY_MODE_VALUE" != "1" ]]; then
        return
    fi

    require_command rustup "Install rustup to manage the MUSL target required by LEGACY_MODE=1."

    if ! rustup target list --installed | grep -qx 'x86_64-unknown-linux-musl'; then
        die "LEGACY_MODE=1 requires the x86_64-unknown-linux-musl Rust target. Install it with: rustup target add x86_64-unknown-linux-musl"
    fi

    if ! command -v "$musl_compiler" >/dev/null 2>&1; then
        die "LEGACY_MODE=1 requires a MUSL C toolchain. Install ${musl_compiler} or set CC_x86_64_unknown_linux_musl/TARGET_CC to a compatible compiler."
    fi
}

print -P "${GOLD}======================================================================${RESET}"
print -P "${GOLD}    __  __      _  ___  ___    ____  ____    ____                     ${RESET}"
print -P "${GOLD}    \\ \\/ /_  _ | |/ / |/ /_   / __ \\/ ___|  / ___|                    ${RESET}"
print -P "${GOLD}     \\  /| | | | ' /| ' /(_) | |  | \\___ \\ | |                        ${RESET}"
print -P "${GOLD}     / / | |_| | . \\| . \\_   | |__| |___) || |___                     ${RESET}"
print -P "${GOLD}    /_/   \\__,_|_|\\_\\_|\\_(_)  \\____/|____/  \\____| 6.4.3 OOB-INTEGRITY${RESET}"
print -P "${GOLD}======================================================================${RESET}"

print -P "${TEAL}[*] Initiating Spatiotemporal Genesis of YuKKi OS 6.4.3...${RESET}"
print -P "${TEAL}[*] Building Directory Infrastructure...${RESET}"

validate_legacy_mode
require_command cargo "Install Rust and Cargo before running the genesis build."
ensure_c_compiler
ensure_required_templates
ensure_legacy_target
prepare_archive_dir

if [[ "$LEGACY_MODE_VALUE" == "1" ]]; then
    print -P "${GOLD}[!] LEGACY_MODE Detected. Cross-compiling statically via MUSL...${RESET}"
    if ! (
        cd "$ARCHIVE_PATH"
        cargo build --release --target=x86_64-unknown-linux-musl
    ); then
        die "LEGACY_MODE build failed inside ${ARCHIVE_PATH}."
    fi
    BUILD_PATH="${ARCHIVE_PATH}/target/x86_64-unknown-linux-musl/release/${EXECUTABLE_NAME}"
else
    if ! (
        cd "$ARCHIVE_PATH"
        cargo build --release
    ); then
        die "Release build failed inside ${ARCHIVE_PATH}."
    fi
    BUILD_PATH="${ARCHIVE_PATH}/target/release/${EXECUTABLE_NAME}"
fi

print -P "${GOLD}======================================================================${RESET}"
print -P "${TEAL}[+] CONGRATULATIONS: YuKKi OS 6.4.3 Out-of-Band Integrity Edition compilation successful.${RESET}"
print -P "${TEAL}[+] Target Binary Location: $BUILD_PATH${RESET}"
print -P "${GOLD}======================================================================${RESET}"
print -P "${TEAL}  BUILD CONTENTS (GPL-3 - OUT-OF-BAND INTEGRITY EDITION):${RESET}"
print -P "  - OOB FNV-1a rolling hash stream integrity (non-cryptographic; see disclaimer)."
print -P "  - 60-frame sync trigger: OOB integrity hash broadcast at every 60-frame boundary."
print -P "  - Node quarantine/blacklist: misbehaving peers excluded from OOB sync and weave."
print -P "  - ChaCha20 keystream payload binding with sequence-derived nonce semantics."
print -P "  - Integrated real-time Lorenz Chaos attractor mathematical manifolds."
print -P "  - Zero-latency memory bypass aligned explicitly to 88-byte bounds."
print -P "  - P2P distributed networking with dual-port architecture (JSON + Binary)."
print -P "  - Restored v4 Filesystem Utilities (Browse, Asynchronous Transfer)."
print -P "  - laminar_api.h: portable packed-struct alignment (GCC/Clang + MSVC fallback)."
print -P "  - Hardware layout restricted to purely electrical flat topology."
print -P "  SECURITY NOTE: OOB hash shim is FNV-1a derivative, NOT full BLAKE3."
print -P "                 Do not rely on it for adversarial integrity guarantees."
print -P "${GOLD}======================================================================${RESET}"

exit 0
