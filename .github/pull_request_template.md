## Summary

<!-- One-paragraph description of what this PR does. -->

## Related Issue

Closes #<!-- issue number -->

## Type of Change

- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] Breaking change (ABI / protocol / API)
- [ ] Documentation update
- [ ] Refactor / cleanup
- [ ] CI/CD or build tooling change

## Changes Made

<!-- Bullet-point list of files changed and what was changed. -->

## ABI / Protocol Impact

<!-- If SpatiotemporalFrame or any FFI function signature changed, describe the impact. -->
- [ ] No ABI changes
- [ ] ABI change — consumers must recompile

## Testing

- [ ] `cargo fmt` passes
- [ ] `cargo clippy -- -D warnings` passes
- [ ] `cargo test --lib` passes
- [ ] `cargo test --test integration_tests` passes
- [ ] Manually tested with bootstrap + peer node

### Test platforms verified:

- [ ] Linux x86_64
- [ ] macOS (Intel / Apple Silicon)
- [ ] Windows MSVC
- [ ] ARM64 / ARMv7

## Configuration

<!-- List any new environment variables, feature flags, or configuration changes. -->

N/A

## Cryptographic Changes

- [ ] This PR modifies cryptographic primitives (X25519, ChaCha20-Poly1305)
- [ ] This PR modifies key derivation or nonce generation logic
- [ ] This PR modifies the secure handshake flow
- [ ] **No cryptographic changes** in this PR

> If any crypto box is checked, attach a brief justification and confirm peer review by someone with cryptography expertise.

## Performance Impact

- [ ] No performance impact expected
- [ ] Performance improvement (describe below)
- [ ] Potential performance regression (describe below and provide benchmark data)

<!-- Optional: paste benchmark output -->

## Documentation

- [ ] `docs/` updated where relevant
- [ ] `docs/CHANGELOG.md` entry added
- [ ] README updated if build/run steps changed

## Security Checklist

- [ ] No new `unsafe` blocks, OR each new `unsafe` block has documented invariants
- [ ] No secrets or credentials in changed files
- [ ] `cargo audit` run with no high/critical findings
- [ ] License of any new dependency is compatible (MIT / Apache-2.0)
