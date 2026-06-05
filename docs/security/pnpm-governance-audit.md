# PNPM Governance Audit

## Purpose

The PNPM governance audit verifies whether managed Node.js and PNPM project roots comply with the repository's PNPM Fortress governance policy.

It is intentionally separate from the IOC and malware scan surface.

## Canonical policy

The normative rule set for managed-project discovery lives in:

- `conventions/security/pnpm-governance-managed-project-discovery.md`

This document explains the behavior.
The convention document defines the canonical policy.

## What the governance audit does

- discovers candidate project roots by looking for `package.json` or `pnpm-workspace.yaml`
- applies managed-project discovery rules before a candidate is allowed into governance reporting
- classifies accepted PNPM roots as `pnpm-single-project` or `pnpm-monorepo`
- recursively promotes nested `pnpm-workspace.yaml` domains inside accepted PNPM roots, while still respecting the excluded-directory blacklist such as `node_modules` and `.pnpm`
- validates `pnpm-workspace.yaml`, root `package.json`, lockfile presence, committed `.nvmrc` prohibition, and project-local auth files
- enforces topology-aware package-manager governance: `packageManager` and `devEngines.packageManager` stay on the workspace root, while monorepo leaf packages must not declare `packageManager`, `devEngines.packageManager`, or `engines.pnpm`
- enforces role-aware runtime governance: `engines.runtime` requires `devEngines.runtime`, single-project runtime identity is checked only when a root `devEngines.runtime` contract is actually declared, monorepos do not blanket-match root `nodeVersion` to every leaf runtime surface, and embedded Electron surfaces must not declare host-node runtime contracts
- checks PNPM pinning, build governance, trust policy, lockfile discipline, `saveExact: true`, exact catalog versions, and workspace protocol usage
- reports nested domains as child domains of their containing PNPM root instead of presenting them as unrelated standalone repos
- can run as a standalone CLI that audits only PNPM governance without running IOC, malware, persistence, hosts, or firewall flows first

## Standalone execution

The repository provides a governance-only entrypoint:

```bash
node --import tsx src/cli/scan-pnpm-governance.ts
```

Every governance-only run refreshes `generated/latest-pnpm-governance-scan.json`.

Explicit roots can be supplied either as separate positional path arguments or as a single comma-separated token:

```bash
node --import tsx src/cli/scan-pnpm-governance.ts C:\git
node --import tsx src/cli/scan-pnpm-governance.ts C:\git,C:\Projects
node --import tsx src/cli/scan-pnpm-governance.ts C:\git C:\Projects
```

## Managed-project discovery model

The governance audit is fail-closed.

In machine-wide mode, a candidate project root is reported only when:

1. a governance root sentinel is present,
2. the path is not in a known unmanaged install/runtime zone,
3. the candidate root has an ownership signal such as `.git`, `.hg`, or `.svn`.

This prevents installed software payloads, extension stores, caches, and vendored trees from being reported as managed projects.

Nested PNPM domains are a special case: if an already accepted PNPM root contains deeper `pnpm-workspace.yaml` files, those nested domains are also audited even without their own ownership sentinel. This keeps monorepo-contained PNPM domains visible without falling open to dependency trees or vendored payloads.

## Why this differs from the IOC scan

The IOC scan and the governance audit intentionally cover different surfaces:

- the IOC scan may inspect broader runtime and dependency areas to detect compromise artifacts,
- the governance audit reports only accepted managed roots that belong to the operator's project estate.

That split keeps threat hunting broad while keeping governance reporting precise.
