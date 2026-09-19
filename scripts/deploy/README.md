# Deploy Scripts — YuKKi OS v6.7.0

## Script

- `deploy_yukki_6_7_0_inet3.zsh`

This script is a thin deployment helper for the current repository source. It does **not** scaffold legacy source trees.

## What it does

1. validates toolchain prerequisites (`cargo`, C compiler)
2. runs `cargo build --release --locked` from repository root
3. optionally installs `target/release/yukki_core_node` into `/usr/local/libexec/yukki`

## Usage

```bash
cd scripts/deploy
chmod +x deploy_yukki_6_7_0_inet3.zsh
./deploy_yukki_6_7_0_inet3.zsh --build-only
# or
./deploy_yukki_6_7_0_inet3.zsh --install
```

## Notes

- Runtime env (`YUKKI_PSK_HEX`, broker vars) is not embedded by the script.
- See `docs/DEPLOYMENT.md` and `docs/SYSADMIN_HOWTO.md` for run/service configuration.
