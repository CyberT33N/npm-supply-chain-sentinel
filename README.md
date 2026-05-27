# npm-supply-chain-sentinel

`npm-supply-chain-sentinel` is a cross-platform Node.js security CLI for two related but independent workflows:

1. a filesystem scanner that hunts for documented npm supply-chain compromise evidence across a repository or an entire host
2. a PNPM governance scanner that audits managed Node.js / PNPM projects against a strict PNPM 11 Fortress policy

The two modules are designed to work in both modes:

- together: the full scan CLI runs filesystem hunting and then appends the PNPM governance audit to the same report
- independently: the filesystem scanner is executable through the full scan CLI, and the governance scanner is executable through its dedicated CLI without running IOC, malware, persistence, hosts, or firewall flows

> This repository is a curated campaign detector and governance auditor. It is not a general-purpose CVE feed mirror or an SBOM platform.

## At a glance

| Module | What it does | Standalone CLI | Included in the full scan |
| --- | --- | --- | --- |
| Filesystem scanner | Hunts exact package/version hits, malicious hooks, payload files, persistence artifacts, and campaign IOCs across project roots or machine-wide filesystem scope. | `npm-supply-chain-sentinel` | Yes |
| PNPM governance scanner | Audits managed Node/PNPM roots for Fortress policy drift, runtime contract drift, dependency governance drift, and auth-local misconfiguration. | `npm-supply-chain-sentinel-pnpm-governance` | Yes |

## Quick start

Requirements:

- `pnpm install`
- `rg` (`ripgrep`) on `PATH` for the filesystem scanner
- network access is optional for governance version resolution; when unavailable, the scanner falls back to the checked-in reference Node and PNPM policy contracts, currently Node `26.2.0` and PNPM `11.2.2`

Run the two workflows from the repository root:

```bash
# Full project scan: filesystem hunting + PNPM governance
pnpm run scan

# Full machine-wide scan
pnpm run scan:machine-wide

# Governance only
pnpm run scan:pnpm-governance

# Governance only for explicit roots
pnpm run scan:pnpm-governance -- C:\git C:\Projects
```

The local package binaries expose the same flows:

```bash
pnpm exec npm-supply-chain-sentinel --help
pnpm exec npm-supply-chain-sentinel-pnpm-governance --help
```

`pnpm run ...` and `pnpm exec ...` use the repository's local `packageManager` pin from `package.json`. If your installed `pnpm` version does not match that pin, those commands can fail before the scanner starts. In that case, either switch to the pinned repo version or use the source entrypoints below.

Source entrypoints:

```bash
node --import tsx src/cli/scan-supply-chain-campaigns.ts --help
node --import tsx src/cli/scan-pnpm-governance.ts --help
```

## How the modules compose

The project has one primary orchestration CLI and one dedicated governance CLI:

- `npm-supply-chain-sentinel` (or `pnpm run scan`) is the end-to-end scanner. It runs filesystem threat hunting, fixed home and registry inspection, optional blocklist/remediation flows, and then the PNPM governance audit on the resolved roots.
- `npm-supply-chain-sentinel-pnpm-governance` (or `pnpm run scan:pnpm-governance`) runs only the governance workflow. It does not run IOC hunting, persistence hunting, hosts auditing, firewall auditing, or remediation.
- Both flows write machine-readable JSON artifacts so they can be used in local developer workflows, CI, or incident-response pipelines.

## Filesystem scanner

The filesystem scanner is a targeted campaign detector, not a blind full-text scrape of every file. It combines exact matches, semantic manifest inspection, targeted `ripgrep` literal searches, fixed-path checks, and platform-specific persistence checks.

What it scans:

- exact compromised package/version matches in `package.json`, lockfiles, and installed package manifests
- suspicious install hooks and manifest needles in `package.json`
- known payload files and renamed loader files in project trees and inside installed packages under `node_modules`
- persistence surfaces in `.claude`, `.vscode`, GitHub Actions workflows, shell RC files, home directories, system temp locations, and the Windows Run registry key
- network indicators used to generate hosts-file and firewall blocklists, plus detection-only endpoints that are intentionally not blindly blocked

Current exact-match campaign coverage is curated around publicly documented incidents from 2026-03-31 through 2026-05-20 and includes the Axios compromise, Bitwarden CLI, SAP CAP / `mbt`, Intercom Node SDK, the TanStack Router/Start wave, and the AntV wave.

<details>
<summary>Exact filesystem hunting surfaces</summary>

The targeted candidate file set includes:

- manifests and lockfiles: `package.json`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `bun.lockb`
- project config and persistence files: `.claude/settings.json`, `.vscode/tasks.json`, `.bashrc`, `.zshrc`, and GitHub workflow files under `.github/workflows/*.yml` and `.github/workflows/*.yaml`
- known payload or loader basenames: `setup.js`, `setup.mjs`, `execution.js`, `router_runtime.js`, `router_init.js`, `bw_setup.js`, `bw1.js`, `6202033.vbs`, `6202033.ps1`, `ld.py`, `transformers.pyz`, `pglog`, `gh-token-monitor.sh`, `gh-token-monitor.service`, `com.user.gh-token-monitor.plist`, `com.apple.act.mond`

The scanner also performs fixed-path and platform checks for:

- home-directory artifacts such as `.claude/execution.js`, `.claude/router_runtime.js`, `.claude/setup.mjs`, `.vscode/setup.mjs`, AI-tooling configs, and Linux/macOS persistence payloads
- absolute system paths such as `/tmp/ld.py`, `/tmp/transformers.pyz`, `/tmp/pglog`, and `/Library/Caches/com.apple.act.mond`
- Windows-specific paths such as `%PROGRAMDATA%\wt`, `%TEMP%\6202033.vbs`, and `%TEMP%\6202033.ps1`
- the Windows Run key value `HKCU\Software\Microsoft\Windows\CurrentVersion\Run -> MicrosoftUpdate`

The current network indicator set includes:

- hosts-blocklist domains: `sfrclak.com`, `filev2.getsession.org`, `seed1.getsession.org`, `seed2.getsession.org`, `seed3.getsession.org`, `api.masscan.cloud`, `git-tanstack.com`, `t.m-kosche.com`, `zero.masscan.cloud`, `audit.checkmarx.cx`
- firewall IP blocklist: `142.11.206.73`
- detection-only domains: `api.github.com`, `registry.npmjs.org`, `github.com`, `metadata.google.internal`
- detection-only IPs: `169.254.169.254`, `169.254.170.2`, `127.0.0.1`

</details>

Operational notes:

- project mode scans the resolved project root and also inspects fixed home and platform persistence surfaces unless `--no-home` is used
- machine-wide mode enumerates accessible local filesystem roots and scans them in parallel worker tasks
- the recycle bin / trash is excluded by default and can be included explicitly with `--include-trash`
- unreadable or OS-protected paths are reported as scan limitations instead of being treated as hard scanner errors
- the full scan writes `generated/latest-scan.json` on every run and can additionally write to a custom path with `--json`
- optional response actions include `--write-blocklists`, `--apply-hosts`, and `--apply-firewall`

## PNPM governance scanner

The PNPM governance scanner is the strict policy engine in this repository. It is fail-closed, focused on managed project roots, and separate from the IOC/malware scan surface.

At a high level, it scans:

- managed project discovery across the supplied roots
- the installed machine `pnpm` runtime
- root `pnpm-workspace.yaml`, `package.json`, `pnpm-lock.yaml`, `.npmrc`, `auth.ini`, and `.gitignore`
- workspace member `package.json` files discovered from `pnpm-workspace.yaml#packages`
- dependency version governance, workspace-link governance, runtime contract alignment, and auth-local boundaries

> In Fortress mode, `pnpm-workspace.yaml` is the primary repository policy surface. `package.json#pnpm` is intentionally forbidden, and a project-local `.npmrc` is intentionally limited to auth and certificate material only.

### Governance-only CLI

```bash
# Current project root
pnpm run scan:pnpm-governance

# Explicit roots
pnpm run scan:pnpm-governance -- C:\git C:\Projects

# Source entrypoint
node --import tsx src/cli/scan-pnpm-governance.ts --help
```

Every governance-only run refreshes `generated/latest-pnpm-governance-scan.json`.

<details>
<summary>Exact managed-root discovery rules</summary>

A candidate root enters governance discovery when the scanner finds `package.json` or `pnpm-workspace.yaml`.

A candidate is accepted into governance reporting when one of the following is true:

- it is an explicit CLI root in project-mode scanning
- it has an ownership signal: `.git`, `.hg`, or `.svn`
- it is a nested PNPM domain with its own `pnpm-workspace.yaml` inside an already accepted PNPM root

Machine-wide governance discovery suppresses unmanaged install/runtime areas such as:

- `Program Files` and `Program Files (x86)`
- `Program Files\WindowsApps`
- per-user application bundles under `AppData\Local\Programs`
- user editor extension stores such as `~/.vscode/extensions`, `~/.cursor/extensions`, `~/.windsurf/extensions`, `~/.trae/extensions`, and `~/.antigravity/extensions`
- user agent-tool directories such as `~/.codex` and `~/.continue`
- pnpm runtime stores and caches, Corepack payload stores, Cypress caches, Trunk caches, and editor-managed TypeScript caches
- embedded Electron app resources such as `.../resources/app` and `.../resources/app.asar.unpacked`
- runtime asset directories such as `desktop-assets` and `trusted-ui`
- macOS `.app/Contents` bundles and Linux `/opt/.../resources/app` bundles

Recursive governance discovery skips these directory names:

- `.git`, `.hg`, `.svn`
- `.angular`, `.build`, `.next`, `.nx`, `.nuxt`, `.turbo`
- `.cache`, `.parcel-cache`, `.pnpm`, `.pnpm-store`, `.npm`, `.yarn`, `.bun`
- `_cacache`, `_npx`
- `node_modules`, `jspm_packages`, `bower_components`
- `coverage`, `dist`, `build`, `out`, `tmp`, `temp`

In machine-wide mode, `$Recycle.Bin` is skipped unless `--include-trash` is set.

</details>

### Exact governance surfaces

The scanner evaluates the following surfaces exactly.

#### Machine and root files

| Surface | Rule scanned |
| --- | --- |
| Machine `pnpm` runtime | `pnpm` must be installed and is compared against the required Fortress PNPM version. A mismatch is a warning; a missing runtime is also a warning. |
| `pnpm-workspace.yaml` | Must exist and parse as YAML for PNPM-governed projects. |
| `package.json` | Must exist and parse as JSON at the root. |
| `pnpm-lock.yaml` | Must exist for deterministic installs. |
| `.npmrc` | Optional, but if present it must be gitignored and may contain only allowed auth/certificate keys. |
| `auth.ini` | Optional, but if present it must be gitignored. |
| `.gitignore` | Warned if missing, because auth-local files must stay ignored. |
| Workspace member `package.json` files | Discovered from `pnpm-workspace.yaml#packages` and audited for dependency governance. |
| Workspace member `.npmrc` / `auth.ini` | Invalid if present inside workspace packages. |

#### `pnpm-workspace.yaml` shared Fortress policy

| Property | Rule scanned |
| --- | --- |
| `minimumReleaseAge` | Must be numeric and `>= 10080` minutes. |
| `minimumReleaseAgeIgnoreMissingTime` | Must be `false`. |
| `minimumReleaseAgeStrict` | Must be `true`. |
| `trustPolicy` | Must be `no-downgrade`. |
| `blockExoticSubdeps` | Must be `true`. |
| `strictDepBuilds` | Must be `true`. |
| `dangerouslyAllowAllBuilds` | Must be `false`. |
| `strictSsl` | Must be `true`. |
| `nodeVersion` | Must be an exact semver string. |
| `engineStrict` | Must be `true`. |
| `pmOnFail` | Must be `error`. |
| `runtimeOnFail` | Must be `error`. |
| `lockfile` | Must be `true`. |
| `preferFrozenLockfile` | Must be `true`. |
| `lockfileIncludeTarballUrl` | Must be `true`. |
| `resolutionMode` | Must be `time-based`. |
| `registrySupportsTimeField` | Must be `false`. |
| `registries.default` | Must be an HTTPS URL. The preferred design is a reviewed internal Nexus registry; otherwise the official `https://registry.npmjs.org/` registry is accepted. |
| `nodeLinker` | Must be `isolated`. |
| `enableGlobalVirtualStore` | Must be `false`. |
| `hoist` | Must be `false`. |
| `shamefullyHoist` | Must be `false`. |
| `virtualStoreDir` | Must be `.pnpm`. |
| `virtualStoreDirMaxLength` | Must be numeric and `<= 60`. |
| `verifyStoreIntegrity` | Must be `true`. |
| `strictStorePkgContentCheck` | Must be `true`. |
| `autoInstallPeers` | Must be `false`. |
| `strictPeerDependencies` | Must be `true`. |
| `ignoreCompatibilityDb` | Must be `true`. |
| `updateNotifier` | Must be `false`. |
| `saveExact` | Must be `true`. |
| `savePrefix` | Must be the empty string. |
| `catalogMode` | Must be `strict`. |
| `cleanupUnusedCatalogs` | Must be `true`. |
| `enablePrePostScripts` | Must be `false`. |
| `verifyDepsBeforeRun` | Must be `error`. |

#### `pnpm-workspace.yaml` array, object, and exception surfaces

| Property | Rule scanned |
| --- | --- |
| `minimumReleaseAgeExclude` | Must exist as `[]`. |
| `trustPolicyExclude` | Must exist as `[]`. If populated, it is rendered as a yellow exception surface but still fails governance. |
| `hoistPattern` | Must exist as `[]`. |
| `publicHoistPattern` | Must exist as `[]`. |
| `peerDependencyRules.ignoreMissing` | Must exist as `[]`. |
| `peerDependencyRules.allowAny` | Must exist as `[]`. |
| `peerDependencyRules.allowedVersions` | Must exist as `{}`. |
| `overrides` | Must exist as `{}`. If populated, it is rendered as a yellow exception surface but still fails governance. |
| `packageExtensions` | Must exist as `{}`. If populated, it is rendered as a yellow exception surface but still fails governance. |
| `allowedDeprecatedVersions` | Must exist as `{}`. |
| `allowBuilds` | Must exist as an object map, and every value must be boolean. |
| `catalog` | Must exist as an object map. Every catalog entry must be an exact semver string such as `1.2.3`; ranges such as `^1.2.3` or `~1.2.3` fail. |
| `catalogs` | Optional. If present, it must be an object of named catalog maps, and every named-catalog entry must also be an exact semver string. |
| `trustPolicyIgnoreAfter` | Must be unset. |

#### Monorepo-only `pnpm-workspace.yaml` surfaces

These rules are scanned when a root is classified as a PNPM monorepo.

| Property | Rule scanned |
| --- | --- |
| `packages` | Must be a non-empty array. |
| `packageConfigs` | Must be present as an array. |
| `includeWorkspaceRoot` | Must be `false`. |
| `sharedWorkspaceLockfile` | Must be `true`. |
| `disallowWorkspaceCycles` | Must be `true`. |
| `failIfNoMatch` | Must be `true`. |
| `linkWorkspacePackages` | Must be `false`. |
| `preferWorkspacePackages` | Must be `false`. |
| `saveWorkspaceProtocol` | Must be `true`. |
| `injectWorkspacePackages` | Must be `false`. |
| `dedupeInjectedDeps` | Must be `true`. |
| `hoistWorkspacePackages` | Must be `false`. |
| `resolvePeersFromWorkspaceRoot` | Must be `true`. |

#### Single-project forbidden workspace surfaces

These same monorepo-only surfaces must be unset in a PNPM single-project repository:

- `packages`
- `includeWorkspaceRoot`
- `sharedWorkspaceLockfile`
- `disallowWorkspaceCycles`
- `failIfNoMatch`
- `linkWorkspacePackages`
- `preferWorkspacePackages`
- `saveWorkspaceProtocol`
- `injectWorkspacePackages`
- `dedupeInjectedDeps`
- `hoistWorkspacePackages`
- `resolvePeersFromWorkspaceRoot`
- `packageConfigs`

#### Root `package.json` governance surfaces

| Property | Rule scanned |
| --- | --- |
| `packageManager` | Must be `pnpm@<required-version>` and must pin an exact semver. The required version is live-resolved from the official `pnpm` metadata subject to the `minimumReleaseAge` gate; if live resolution fails, the scanner falls back to the checked-in reference contract. |
| `engines.node` | Must be unset. |
| `devEngines.runtime.name` | Must be `node`. |
| `devEngines.runtime.version` | Must be an exact semver string. |
| `devEngines.runtime.onFail` | Must be `error`. |
| `devEngines.packageManager.name` | Must be `pnpm`. |
| `devEngines.packageManager.version` | Must be the same exact required PNPM version as `packageManager`. |
| `devEngines.packageManager.onFail` | Must be `error`. |
| `pnpm` | Must be unset in `package.json`; PNPM 11 policy must live in `pnpm-workspace.yaml`, not `package.json#pnpm`. |
| `name` | Warned when missing at a monorepo root. |

#### Cross-file and runtime drift policies

| Policy | Rule scanned |
| --- | --- |
| Runtime identity | `package.json#devEngines.runtime.version` must equal `pnpm-workspace.yaml#nodeVersion`. |
| Node LTS floor | The aligned runtime contract must be `>=` the current Node LTS floor resolved from the official Node release index. |
| Node latest guidance | If the aligned runtime meets LTS but is below the current Node latest release, the audit emits a warning. If it matches latest, it passes. If it is newer than the resolved latest, the audit emits a warning to reconfirm upstream state. |
| Lockfile discipline | `pnpm-lock.yaml` must exist. |
| Non-PNPM Node roots | Managed Node projects that do not show PNPM signals are reported as warnings, not Fortress passes. |

#### Dependency governance across root and workspace member manifests

| Surface | Rule scanned |
| --- | --- |
| `dependencies`, `devDependencies`, `optionalDependencies`, `peerDependencies` | If a dependency name matches a discovered local workspace package, the specifier must use the `workspace:` protocol. |
| `dependencies`, `devDependencies` | Non-workspace dependencies must be governed through `catalog:` references instead of hardcoded version strings. |
| Workspace member `package.json` | Must parse correctly and is audited with the same `workspace:` and `catalog:` rules. |

#### Project-local auth file governance

Root-level `.npmrc` is treated as an auth-local file, not a repository policy file.

Allowed project-local `.npmrc` keys are only:

- global certificate/auth surfaces: `ca`, `ca[]`, `cafile`, `cert`, `key`
- registry-scoped auth or certificate surfaces ending with: `_authToken`, `cafile`, `ca`, `cert`, `certfile`, `key`, `keyfile`

The scanner also enforces these auth-local policies exactly:

- `.npmrc` must be gitignored if present
- `auth.ini` must be gitignored if present
- `tokenHelper` is forbidden in a project-local `.npmrc`, including registry-scoped `tokenHelper`, because a repo-local helper path can execute arbitrary local binaries
- repository policy settings placed in `.npmrc` are failed and mapped to their intended governance surface:
  - repository policy belongs in `pnpm-workspace.yaml`
  - runtime identity belongs in `package.json#devEngines.runtime.version` and `pnpm-workspace.yaml#nodeVersion`
  - machine-local infrastructure settings belong in global PNPM `config.yaml`
- `auth.ini` is only checked for gitignore governance; its properties are not audited
- workspace member `.npmrc` or `auth.ini` files are invalid and must not exist

## CLI reference

Common full-scan commands:

```bash
# Project mode
pnpm run scan

# Machine-wide mode
pnpm run scan:machine-wide

# Machine-wide with hosts and firewall remediation
pnpm run scan:machine-wide:full

# Custom project roots and JSON export
pnpm run scan -- --root ..\repo-a --root ..\repo-b --json .\generated\custom-scan.json

# Write blocklist files without mutating the local machine
pnpm run scan:blocklists
```

Common governance-only commands:

```bash
# Current root
pnpm run scan:pnpm-governance

# Explicit roots as separate arguments
pnpm run scan:pnpm-governance -- C:\git C:\Projects

# Explicit roots as one comma-separated token
pnpm run scan:pnpm-governance -- C:\git,C:\Projects

# Machine-wide governance discovery
pnpm run scan:pnpm-governance -- --machine-wide
```

Useful flags:

- full scan: `--root`, `--machine-wide`, `--workers`, `--no-home`, `--write-blocklists`, `--apply-hosts`, `--apply-firewall`, `--json`, `--fast-preflight`, `--deep-preflight`, `--heartbeat-sec`, `--include-trash`, `--quiet`, `--help`
- governance only: `--root`, `--roots`, `--machine-wide`, `--include-trash`, `--json`, `--help`

## Reports and exit codes

Reports:

- full scan always refreshes `generated/latest-scan.json`
- governance-only scan always refreshes `generated/latest-pnpm-governance-scan.json`
- both CLIs can also write an additional JSON artifact via `--json`

Exit behavior:

- the full scan exits with `1` when it finds exact compromise hits, heuristic hits, artifact/persistence hits, or PNPM governance failures
- the governance-only scan exits with `1` when one or more audited projects fail governance
- warnings alone do not fail the governance-only exit code

## Further reading

- `docs/operations/cli-usage.md`
- `docs/security/pnpm-governance-audit.md`
- `docs/security/supply-chain-campaigns-2026.md`
- `docs/security/blocklists/README.md`
- `docs/architecture/solution-overview.md`
- `docs/architecture/repository-slices.md`
