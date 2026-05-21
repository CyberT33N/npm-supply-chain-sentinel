# npm-supply-chain-sentinel

Cross-platform Node.js scanner and threat-intelligence repository for detecting documented npm supply-chain compromises, malicious install hooks, persistence artifacts, campaign IOCs, and PNPM governance drift.

`README.md` is the workspace-level table of contents for descriptive repository documentation.

The canonical normative rules live in `CONVENTIONS.md` and the leaf slices under `conventions/`.

## Documentation TOC

- `docs/README.md`
  Entry point for the descriptive documentation model.
- `docs/architecture/README.md`
  Architecture overview and repository slice model.
- `docs/operations/README.md`
  Runtime contract, CLI usage, scan execution model, and remediation guidance.
- `docs/security/README.md`
  PNPM governance audit behavior, campaign analysis, and generated blocklist artifacts.

## Convention TOC

- `CONVENTIONS.md`
  Entry point for normative repository conventions.
- `conventions/security/pnpm-governance-managed-project-discovery.md`
  Canonical managed-project discovery and suppression policy for the PNPM governance audit.

## Quick entrypoints

- install dependencies: `pnpm install`
- project scan: `pnpm run scan`
- machine-wide scan: `pnpm run scan:machine-wide`
- full remediation package: `pnpm run scan:machine-wide:full`
