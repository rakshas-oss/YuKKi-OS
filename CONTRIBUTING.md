# Contributing to YuKKi OS

Thank you for your interest in contributing to YuKKi OS. This document outlines guidelines for contributing to the project.

## Code of Conduct

Please be respectful of all contributors. This is research/demo software — contributions that extend its educational value are most welcome.

## Getting Started

1. Fork the repository and create your feature branch from the latest `main`.
2. Ensure your environment meets the [Build Prerequisites](README.md#build-prerequisites).
3. Make your changes in the appropriate versioned subdirectory (e.g., `yukkios_6_6_sentinel/`).

## Code Style

### Rust
- Run `cargo fmt` before committing.
- Run `cargo clippy -- -D warnings` and fix all warnings.
- Keep `unsafe` blocks minimal and document each invariant inline.

### C (FFI layer)
- Follow C99 style as used in `src/ffi/chaos_weave.c`.
- Every exported function must have a null-pointer guard.
- All heap allocations must be paired with explicit `secure_wipe` + `free` on exit paths.

## Testing

- Add unit tests in `#[cfg(test)]` modules within Rust source files.
- Integration tests go in `tests/` under the relevant versioned directory.
- Run `cargo test` before opening a PR.

## Commit Messages

Use the imperative mood, 72-character subject line, and reference relevant issue numbers:

```
fix: null-ptr guard in chaos_engine_init (#42)
```

## Pull Request Process

1. Ensure `cargo fmt`, `cargo clippy`, and `cargo test` all pass.
2. Update documentation in `docs/` if your change affects architecture, API, or deployment.
3. Fill in the [PR template](.github/pull_request_template.md).
4. Request review from a maintainer.

## Security Reporting

Do **not** open a public issue for security vulnerabilities. Instead, see [docs/SECURITY.md](docs/SECURITY.md) for the responsible disclosure process.

## License

By contributing you agree that your contributions will be licensed under the GPL-3.0 License as described in [LICENSE](LICENSE).
