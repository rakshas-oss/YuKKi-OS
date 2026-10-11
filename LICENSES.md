# Third-Party License Inventory

This project is GPL-3.0-only at the workspace level. Third-party dependencies must remain compatible with the project’s security and distribution posture.

## Project-level license

- Workspace crates: `GPL-3.0-only`
- Dependency policy: permissive-only for third-party code

## Dependencies explicitly allowed

The following are currently accepted under the repository policy:

- `MIT`
- `Apache-2.0`
- `BSD-2-Clause`
- `BSD-3-Clause`
- `ISC`
- `Zlib`
- `Unicode-DFS-2016`
- `0BSD`
- `CC0-1.0`

## Dependencies explicitly resolved to permissive branches

These crates are dual-licensed and are resolved to the permissive branch:

- `ittapi` 0.4.0 → `BSD-3-Clause`
- `ittapi-sys` 0.4.0 → `BSD-3-Clause`
- `r-efi` 5.3.0 → `MIT`
- `r-efi` 6.0.0 → `MIT`

## Disallowed dependency licenses

The following are not permitted in third-party dependencies:

- GPL-2.0 / GPL-3.0
- LGPL-2.x / LGPL-3.x
- AGPL-3.0
- Any other strong copyleft licensing family

## Compliance check

Run the following before merging:

```bash
cargo deny check licenses bans advisories
```

See also: [docs/COMPLIANCE.md](docs/COMPLIANCE.md)
