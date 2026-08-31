# YuKKi OS — Production Readiness Project Board

Tracks remaining work before v6.6.6 can be considered production-ready.

**Current completion:** ~30%

---

## Priority Legend

| Label | Meaning |
|---|---|
| **P0** | Blocking — must be resolved before any production deployment |
| **P1** | High priority — should be resolved in the next milestone |
| **P2** | Nice to have — improves quality but not blocking |

---

## Security Hardening

| Status | Priority | Task |
|---|---|---|
| ☐ | P0 | Full dependency security audit (`cargo audit`) with zero high/critical findings |
| ☐ | P0 | Key derivation function (KDF) review — replace raw shared-secret bytes with HKDF |
| ☐ | P0 | Mutual authentication during handshake (currently unauthenticated X25519) |
| ☐ | P0 | DDoS / connection-flood protection on TCP listeners |
| ☐ | P1 | Formal review of all `unsafe` blocks with documented invariants |
| ☐ | P1 | Rate limiting on P2P and binary listeners |
| ☐ | P1 | Nonce exhaustion protection and rotation strategy |
| ☐ | P2 | Penetration test of the mesh overlay |

---

## Code Quality & Testing

| Status | Priority | Task |
|---|---|---|
| ✅ | P0 | Unit tests for all core modules (41+ tests) |
| ✅ | P0 | Integration test suite (30+ tests) |
| ✅ | P0 | CI pipeline with multi-platform builds |
| ✅ | P0 | Cargo fmt and Clippy enforcement |
| ☐ | P0 | Code coverage ≥ 70% (tarpaulin + Codecov) |
| ☐ | P1 | Fuzz testing for frame parsing and encryption paths |
| ☐ | P1 | Property-based tests for Lorenz state progression |
| ☐ | P2 | Mutation testing |

---

## Documentation & DevOps

| Status | Priority | Task |
|---|---|---|
| ✅ | P0 | GitHub Actions CI/CD workflows |
| ✅ | P0 | Pull request template |
| ✅ | P0 | Branch protection rules documented |
| ✅ | P1 | Project board / production readiness tracker |
| ☐ | P0 | Apply branch protection rules in GitHub Settings |
| ☐ | P0 | CHANGELOG maintained for every release |
| ☐ | P1 | CODEOWNERS file |
| ☐ | P1 | API documentation (`cargo doc`) published |
| ☐ | P1 | Deployment runbook |
| ☐ | P2 | Architecture decision records (ADRs) |

---

## Platform & Infrastructure

| Status | Priority | Task |
|---|---|---|
| ✅ | P1 | Linux x86_64 build |
| ✅ | P1 | Linux MUSL static build |
| ✅ | P1 | macOS (Intel + Apple Silicon) build |
| ✅ | P1 | Windows MSVC build |
| ✅ | P1 | ARM64 / ARMv7 cross-compilation |
| ✅ | P2 | WebAssembly target |
| ☐ | P1 | Docker image with pinned base image and non-root user |
| ☐ | P1 | Container image signing (cosign / sigstore) |
| ☐ | P2 | Kubernetes / systemd deployment manifests |

---

## Operational Readiness

| Status | Priority | Task |
|---|---|---|
| ☐ | P0 | Structured logging (JSON) with configurable verbosity |
| ☐ | P0 | Graceful shutdown handling (SIGTERM / SIGINT) |
| ☐ | P1 | Health check endpoint |
| ☐ | P1 | Prometheus metrics endpoint |
| ☐ | P1 | Distributed tracing (OpenTelemetry) |
| ☐ | P1 | Configurable via environment variables and config file |
| ☐ | P2 | Alerting runbook |

---

## Next Steps (post-merge)

1. Apply branch protection rules via GitHub Settings (see `docs/BRANCH_PROTECTION_RULES.md`)
2. Enable Codecov integration with the repository secret `CODECOV_TOKEN`
3. Monitor first CI runs for any flaky tests
4. Begin P0 security hardening items (KDF, mutual auth)
5. Write deployment documentation and Docker image
