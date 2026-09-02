# Deploy Scripts — YuKKi OS

## `deploy_yukki_6_6_6_inet3.zsh`

Self-contained deployment script that scaffolds a standalone copy of the YuKKi OS Inet3 source tree and builds it with `cargo build --release`. It is kept as a legacy/standalone convenience path and internally retains some v6.6.4-era identifiers; for the canonical, actively maintained v6.6.6 source tree, build from the repository root as described in the top-level [README](../../README.md).

### Usage

```bash
chmod +x deploy_yukki_6_6_6_inet3.zsh
./deploy_yukki_6_6_6_inet3.zsh
```

This script generates a self-contained source tree in `./yukkios_6_6_6_inet3/`, builds the binary with `cargo build --release`, and prints a deployment confirmation.

### Requirements

- `zsh` shell
- Rust stable toolchain (`rustup`)
- C99 compiler (`gcc` or `clang`)
