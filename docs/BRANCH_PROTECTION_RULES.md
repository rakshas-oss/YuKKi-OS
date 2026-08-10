# Branch Protection Rules — `main`

This document describes the branch protection configuration that must be applied to the `main` branch via **GitHub Settings → Branches → Branch protection rules**.

## Required Status Checks

The following CI jobs must pass before a pull request can be merged:

| Workflow | Job |
|---|---|
| Test & Code Quality | `test (ubuntu-latest)` |
| Test & Code Quality | `test (macos-latest)` |
| Test & Code Quality | `test (windows-latest)` |
| Test & Code Quality | `fmt` |
| Test & Code Quality | `clippy` |
| Test & Code Quality | `security-audit` |
| Integration Tests | `mesh-integration` |
| Integration Tests | `crypto-integration` |
| Integration Tests | `abi-ffi` |
| Integration Tests | `wasm-sandbox` |
| Integration Tests | `adi-calibration` |
| Multi-Platform Build | `build-linux (x86_64-unknown-linux-gnu)` |
| Multi-Platform Build | `build-linux (x86_64-unknown-linux-musl)` |

## Code Reviews

- **Required approvals:** 1
- **Code owner reviews required:** yes (see `CODEOWNERS` when added)
- **Dismiss stale reviews:** yes — a new push dismisses any existing approvals

## Branch Currency

- **Require branches to be up to date before merging:** yes

This ensures that all required status checks ran against the latest `main`, preventing integration regressions.

## Linear History

- **Require linear history:** yes
- Only squash-merge or rebase-merge are permitted; merge commits are disabled.

## Merge Queue

Configure the merge queue (GitHub Merge Queue) with the following settings:

- **Merge method:** squash
- **Minimum group size:** 1
- **Maximum group size:** 5
- **Wait timer:** 5 minutes

## Force Push & Deletion Protection

- **Allow force pushes:** no
- **Allow deletions:** no

## Applying These Rules

1. Navigate to **Settings → Branches** in the repository.
2. Click **Add branch protection rule**.
3. Set the pattern to `main`.
4. Enable **Require a pull request before merging** and set **Required approving reviews** to `1`.
5. Enable **Require status checks to pass before merging**, search for each job listed above, and add it.
6. Enable **Require branches to be up to date before merging**.
7. Enable **Require linear history**.
8. Enable **Do not allow bypassing the above settings**.
9. Disable **Allow force pushes** and **Allow deletions**.
10. Save.

> **Note:** Rules cannot be enforced via code — they must be applied through GitHub Settings or the GitHub API/CLI after the repository is configured. This document serves as the canonical reference for the intended configuration.
