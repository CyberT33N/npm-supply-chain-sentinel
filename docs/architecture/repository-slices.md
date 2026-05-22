# Repository Slices

The repository is intentionally split by responsibility.

## Source Slices

- `src/cli/`
  Delivery entrypoints and executable CLI wiring for the full supply-chain scan and the governance-only scan.
- `src/application/`
  Application orchestration, preflight planning, worker scheduling, filesystem/package scanning, and PNPM governance auditing.
- `src/domain/`
  Policy constants, scan modes, skip rules, governance rules, and finding aggregation primitives.
- `src/infrastructure/`
  Filesystem helpers, process helpers, remediation adapters, and `ripgrep` integration.
- `src/data/`
  Curated campaign intelligence, exact package/version rules, heuristic signatures, and network indicators.
- `src/presentation/`
  Human-readable and serializable reporting surfaces, including the dedicated PNPM governance report model.

## Documentation Slices

- `docs/architecture/`
  Descriptive architecture read model.
- `docs/operations/`
  Usage, execution, and remediation documentation.
- `docs/security/`
  Governance-audit, incident, and blocklist documentation.
- `conventions/`
  Normative architecture and governance rules.

## Normative Reference

The documentation-slice rules are defined in `conventions/architecture/documentation-slices.md`.
