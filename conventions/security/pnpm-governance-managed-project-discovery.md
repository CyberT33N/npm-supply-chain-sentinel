# PNPM Governance Managed-Project Discovery Convention

## Status

Normative.

## Intent

The PNPM governance audit MUST report only managed projects that are intentionally owned by the operator, such as cloned repositories, forks, or explicitly targeted local projects.

Installed software payloads, editor extension stores, runtime caches, vendored trees, and embedded Electron/Node.js bundles MUST NOT be reported as managed governance targets.

## Scope

This convention applies only to the PNPM and Node.js governance audit flow.

It does NOT redefine the IOC and malware scan surface. The IOC scan may still inspect broader filesystem areas, including dependency trees, when that is required for incident-response coverage.

## Managed Project Definition

A directory MAY enter the governance audit only when all of the following are true:

1. It contains a governance root sentinel:
   - `package.json`, or
   - `pnpm-workspace.yaml`
2. It is not suppressed by the unmanaged path registry.
3. It has a valid ownership signal for the current scan mode.

## Ownership Rules

### Machine-wide mode

Machine-wide governance discovery MUST be fail-closed.

A candidate root discovered during machine-wide traversal is managed only when the candidate root itself contains at least one ownership sentinel:

- `.git`
- `.hg`
- `.svn`

If no ownership sentinel is present at the candidate root, the candidate MUST be suppressed from governance reporting.

### Explicit project scope

When the operator runs a project-scoped scan or provides an explicit root, the explicit scan root MAY be audited even if it does not contain an ownership sentinel.

Nested candidates under that explicit root MUST still satisfy their own ownership signal unless they are governed through an accepted monorepo root.

## Unmanaged Path Registry

The governance discovery layer MUST maintain a platform-aware unmanaged path registry.

This registry exists to suppress well-known runtime and installation zones before they appear in governance reporting.

The registry MUST prefer install-zone and runtime-shape semantics over vendor-name heuristics.

The following path classes are normative examples of unmanaged discovery zones:

- installed application roots under Windows `Program Files`
- Windows Store application payloads
- per-user installed application bundles under local program stores
- user editor and IDE extension stores
- user-level agent plugin and tool state
- pnpm runtime stores and caches
- Corepack-managed package-manager payloads
- Cypress runtime caches
- Trunk plugin and tool payloads
- editor-managed runtime caches such as local TypeScript payloads
- embedded Electron application resources such as `resources/app` and `resources/app.asar.unpacked`
- embedded desktop runtime assets such as `desktop-assets` and `trusted-ui`

## Generated and Cache Trees

The discovery walk MUST skip clearly generated or cache-oriented subtree names that are not managed projects, including generated framework and build trees.

Examples include:

- `.angular`
- `.build`
- `.cache`
- `.next`
- `.nuxt`
- `.nx`
- `.parcel-cache`
- `.pnpm`
- `.pnpm-store`
- `.turbo`
- `coverage`
- `dist`
- `build`
- `out`
- `tmp`
- `temp`
- `node_modules`

## Reporting Rules

1. Governance summary output MUST reflect only accepted managed roots.
2. Suppressed unmanaged-path candidates SHOULD be counted for operator visibility.
3. Suppressed missing-ownership candidates SHOULD be counted for operator visibility.
4. Nested `package.json` files that are not independently owned MUST NOT be reported as separate managed projects.
5. Workspace members MUST be represented through their accepted monorepo root instead of being promoted to independent managed roots unless they are independently owned.

## Change Policy

When a new false-positive class is observed, the change MUST be handled in this order:

1. verify whether the candidate lacks ownership and should therefore be suppressed by policy,
2. extend the unmanaged path registry when the path class is a real install/runtime zone,
3. update descriptive documentation in `docs/security/` to reference the new policy behavior.

The repository MUST NOT expand the governance surface by treating every `package.json` as a managed project.
