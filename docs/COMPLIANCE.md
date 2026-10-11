# License Compliance Policy

## Scope

This repository is a **GPL-3.0-only** project. The policy below governs **third-party dependencies** in the Cargo dependency graph.

## Policy

- Workspace/project crates may be GPL-3.0-only.
- Third-party dependencies must use approved permissive licenses.
- Copyleft dependency licenses are disallowed unless explicitly approved.

## Enforcement

The repository uses `cargo-deny` with `deny.toml` at repository root.

Primary local check:

```bash
cargo deny check licenses bans advisories
```

## Approved dependency licenses

- MIT
- Apache-2.0
- BSD-2-Clause
- BSD-3-Clause
- ISC
- Zlib
- Unicode-DFS-2016
- 0BSD
- CC0-1.0

## Disallowed dependency licenses

- GPL-2.0 variants
- GPL-3.0 variants
- LGPL-2.x/3.x variants
- AGPL-3.0 variants

## Multi-license crate resolution

When a dependency offers `OR` choices, YuKKi-OS resolves to an approved permissive branch where available.

Current explicit clarifications:

- `ittapi` → `BSD-3-Clause`
- `ittapi-sys` → `BSD-3-Clause`
- `r-efi` (5.3.0 / 6.0.0) → `MIT`

## Exceptions

Only workspace crates are exempted for GPL-3.0-only as defined in `deny.toml`.
No third-party copyleft exceptions are currently approved.
