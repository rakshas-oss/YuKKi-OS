# v6.7.0 — Inet3 Production Refresh

Tag: v6.7.0

Release date: 2026-09-19

Summary

v6.7.0 establishes the current YuKKi OS baseline for the Inet3 production refresh. This release aligns the project version metadata and documentation under a single v6.7.0 line while preserving the existing implementation stack: X25519-based authenticated control-plane security, ChaCha20-Poly1305 AEAD encryption, Wasmtime-backed sandboxing, and ADI auto-tuning behavior.

This release is primarily a versioning and documentation refresh rather than a change in the transport or cryptographic architecture already introduced in the v6.6.x Inet3 sequence.

Highlights

- Version baseline refresh across Cargo metadata and library documentation
- README and repository docs unified under the v6.7.0 release line
- Architectural references and deployment notes kept aligned with the current Inet3 implementation
- Changelog and version history updated to preserve archived release context
- Security and API documentation updated to reflect the in-repo baseline

Dependency baseline

- `x25519-dalek = "3.0"` (with `static_secrets`)
- `chacha20poly1305 = "0.11"`
- `wasmtime = "48.0"`
- `zeroize = "1.9"` (with `derive`)
- `hkdf = "0.13"`
- `sha2 = "0.11"`

Upgrade notes / compatibility

- This release preserves the established v6.6.x Inet3 implementation and intended operational model.
- No protocol break is introduced by the version metadata refresh itself.
- Downstream consumers should continue to track the current dependency baseline and project documentation for build and deployment guidance.

Security

- The repository remains research/demo software and is not a substitute for a formal production security review.
- Shared PSK-based peer trust remains a known operational limitation.
- Memory-wiping and sandbox isolation remain as documented in the current security baseline.

Testing checklist

- [ ] Full CI build and test pass on the refreshed v6.7.0 baseline
- [ ] Documentation links and version strings remain consistent across repo files
- [ ] Release metadata matches the checked-out branch state
- [ ] Build artifacts remain compatible with the current Cargo.lock baseline

Release artifacts

- Tag: v6.7.0
- Binaries: build locally with `cargo build --release`

Maintainers / contributors

- Release manager: rakshas-oss
- Full contributor list available from git history (`git shortlog -sne`)
