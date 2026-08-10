# Deploy Scripts — YuKKi OS v6.6.4

## `deploy_yukki_6_6_4_apex.zsh`

Automated deployment script for YuKKi OS v6.6.4 Apex Synthesis Edition.

### Usage

```bash
chmod +x deploy_yukki_6_6_4_apex.zsh
./deploy_yukki_6_6_4_apex.zsh
```

This script generates the full v6.6.4 source tree, builds the binary with `cargo build --release`, and prints a deployment confirmation.

### Requirements

- `zsh` shell
- Rust stable toolchain (`rustup`)
- C99 compiler (`gcc` or `clang`)
