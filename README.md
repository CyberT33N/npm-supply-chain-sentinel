# npm-supply-chain-sentinel

Cross-platform Node.js scanner and threat-intelligence repository for detecting documented npm supply-chain compromises, malicious install hooks, persistence artifacts, and campaign IOCs across individual projects or entire hosts.

## Runtime dependencies

`npm-supply-chain-sentinel` requires the following runtime dependencies:

- Node.js `>=24.16.0`
- `pnpm` `11.1.3`
- `ripgrep` (`rg`) on `PATH`

`ripgrep` is a required runtime dependency for the scanner and must be installed before running the CLI.

The repository itself is governed as a PNPM 11 Fortress single-project setup:

- project policy lives in `pnpm-workspace.yaml`,
- toolchain pinning lives in the root `package.json`,
- project-local `.npmrc` / `auth.ini` are optional auth-only files and must stay gitignored.

Typical installation commands:

```bash
# macOS (Homebrew)
brew install ripgrep

# Windows (Winget)
winget install BurntSushi.ripgrep.MSVC

# Ubuntu / Debian
sudo apt-get install ripgrep
```

Upstream installation reference: <https://github.com/burntsushi/ripgrep#installation>

## What it does

`npm-supply-chain-sentinel` helps security teams and developers investigate major documented npm and Node.js supply-chain incidents such as:

- the `axios` compromise with `plain-crypto-js`,
- the `Shai-Hulud` / `Mini Shai-Hulud` campaign family,
- related repackaging, persistence, and CI/CD token-theft patterns.

The project combines:

- a curated IOC and campaign dataset,
- a cross-platform filesystem and package scanner,
- a PNPM 11 Fortress governance audit for managed project roots,
- project-mode and machine-wide scan modes,
- worker-thread-based parallel traversal,
- a required `ripgrep`-backed runtime environment,
- blocklist generation for hosts and firewall workflows,
- incident-response documentation.

## Architecture

This repository is intentionally split by responsibility:

- `src/cli`
  The delivery layer. This is the executable scanner entrypoint and orchestration boundary.
- `src/application`
  The application layer. This contains CLI orchestration, preflight planning, worker scheduling, the filesystem/package scan flow, and PNPM governance auditing.
- `src/domain`
  The policy and findings layer. This contains scan modes, skip rules, PNPM Fortress policy constants, reporting symbols, and finding aggregation primitives derived from the curated dataset.
- `src/infrastructure`
  The infrastructure adapter layer. This contains filesystem helpers, process helpers, native remediation adapters, and the `ripgrep` runtime integration.
- `src/data`
  The curated threat-intelligence and detection-policy layer. This is the canonical source of campaign metadata, exact package-version rules, IOC lists, and heuristic signatures.
- `src/presentation`
  The reporting layer. This renders human-readable summaries and serializable result payloads.
- `docs/security`
  The read-model and operational documentation layer. This contains the detailed campaign report and generated blocklist artifacts.

### Why this layout

From a Domain-Driven Design perspective, the bounded context is **Supply-Chain Threat Detection and Response**.

That means:

- the domain core is the detection knowledge, not the CLI shell itself,
- the CLI should remain an adapter over a canonical policy dataset,
- documentation and blocklists should remain separate read models rather than being mixed into the executable core.

From a 12-Factor perspective, this tool is modeled as a stateless CLI process:

- configuration is explicit via CLI flags,
- scan output is written to explicit file paths,
- no hidden runtime state is required between invocations,
- generated artifacts are externalized rather than embedded into code.

Administrative mutation is intentionally isolated to explicit remediation operations such as `--apply-hosts` and `--apply-firewall`. The main scan path does not require elevated privileges; only the operating-system-specific hosts/firewall mutation step may need administrator/root execution.

## Repository structure

```text
src/
  cli/
    scan-supply-chain-campaigns.mjs
  application/
    cli.mjs
    pnpm-governance.mjs
    preflight.mjs
    scan-worker.mjs
    scanner.mjs
  domain/
    findings.mjs
    pnpm-governance.mjs
    policy.mjs
  data/
    supply-chain-campaigns-2026.mjs
  infrastructure/
    fs-utils.mjs
    process-utils.mjs
    remediation.mjs
    ripgrep.mjs
  presentation/
    reporting.mjs
docs/
  security/
    supply-chain-campaigns-2026.md
    blocklists/
      supply-chain-2026.hosts
      supply-chain-2026-firewall.txt
.gitignore
package.json
pnpm-lock.yaml
pnpm-workspace.yaml
```

## Usage

Install the pinned package-manager/runtime contract first:

```bash
pnpm install
```

### Direct Node.js execution

Project scan (default):

```bash
node src/cli/scan-supply-chain-campaigns.mjs
```

Machine-wide scan:

```bash
node src/cli/scan-supply-chain-campaigns.mjs --machine-wide
```

Machine-wide scan with explicit worker count:

```bash
node src/cli/scan-supply-chain-campaigns.mjs --machine-wide --workers 8
```

Machine-wide scan with the default deep preflight inventory:

```bash
node src/cli/scan-supply-chain-campaigns.mjs --machine-wide
```

Machine-wide scan with a 5-second heartbeat:

```bash
node src/cli/scan-supply-chain-campaigns.mjs --machine-wide --heartbeat-sec 5
```

Machine-wide scan with explicit recycle-bin coverage:

```bash
node src/cli/scan-supply-chain-campaigns.mjs --machine-wide --include-trash
```

Write blocklists:

```bash
node src/cli/scan-supply-chain-campaigns.mjs --write-blocklists ./docs/security/blocklists
```

Apply the managed hosts section:

```bash
node src/cli/scan-supply-chain-campaigns.mjs --apply-hosts
```

Apply outbound firewall blocks for the documented IOC IPs:

```bash
node src/cli/scan-supply-chain-campaigns.mjs --apply-firewall
```

Complete machine-wide scan plus hosts/firewall remediation:

```bash
node src/cli/scan-supply-chain-campaigns.mjs --machine-wide --apply-hosts --apply-firewall
```

Equivalent pnpm script (uses the default deep preflight):

```bash
pnpm run scan:machine-wide:full
```

Equivalent pnpm script with a 5-second heartbeat:

```bash
pnpm run scan:machine-wide:full:heartbeat-5s
```

Machine-wide scans exclude the OS trash / recycle bin by default. Add `--include-trash` only when you explicitly want that extra forensic scope.

## Operator quick start

### Unprivileged scan only

Use these commands when you only want detection and reporting. No hosts-file or firewall mutation is requested.

```bash
# project scope
node src/cli/scan-supply-chain-campaigns.mjs

# full machine scope
node src/cli/scan-supply-chain-campaigns.mjs --machine-wide
```

### Full remediation package

Use the full remediation package when you want all of the following in one run:

- machine-wide filesystem scan
- live hosts-file audit
- managed hosts-file update
- outbound firewall rule application

Direct CLI command:

```bash
node src/cli/scan-supply-chain-campaigns.mjs --machine-wide --apply-hosts --apply-firewall
```

Equivalent pnpm script:

```bash
pnpm run scan:machine-wide:full
```

Deep preflight is enabled by default. If you want a lighter startup and less pre-scan work:

```bash
node src/cli/scan-supply-chain-campaigns.mjs --machine-wide --fast-preflight --apply-hosts --apply-firewall
```

If you want to include the OS trash / recycle bin in a machine-wide scan:

```bash
node src/cli/scan-supply-chain-campaigns.mjs --machine-wide --include-trash --apply-hosts --apply-firewall
```

Heartbeat logs are enabled by default. If you want a shorter heartbeat interval:

```bash
node src/cli/scan-supply-chain-campaigns.mjs --machine-wide --heartbeat-sec 5 --apply-hosts --apply-firewall
```

### Windows

For a normal detection-only scan, a regular terminal is sufficient.

For `--apply-hosts`, `--apply-firewall`, or the full remediation package, open **PowerShell as Administrator** and then run:

```powershell
pnpm run scan:machine-wide:full
```

Or, without npm:

```powershell
node .\src\cli\scan-supply-chain-campaigns.mjs --machine-wide --apply-hosts --apply-firewall
```

Windows firewall remediation uses PowerShell and `New-NetFirewallRule`.

### Linux

For a normal detection-only scan, a regular shell is sufficient.

For `--apply-hosts`, `--apply-firewall`, or the full remediation package, run the command elevated:

```bash
sudo node ./src/cli/scan-supply-chain-campaigns.mjs --machine-wide --apply-hosts --apply-firewall
```

Linux firewall remediation currently targets `ufw` when it is available.

### macOS

For a normal detection-only scan, a regular shell is sufficient.

For `--apply-hosts`, `--apply-firewall`, or the full remediation package, run the command elevated:

```bash
sudo node ./src/cli/scan-supply-chain-campaigns.mjs --machine-wide --apply-hosts --apply-firewall
```

macOS firewall remediation currently targets `pfctl`.

### pnpm scripts

The repository exposes ready-to-run pnpm scripts:

- `pnpm run scan`
- `pnpm run scan:project`
- `pnpm run scan:project:verbose`
- `pnpm run scan:machine-wide`
- `pnpm run scan:machine-wide:verbose`
- `pnpm run scan:no-home`
- `pnpm run scan:blocklists`
- `pnpm run scan:json`
- `pnpm run scan:apply-firewall`
- `pnpm run scan:machine-wide:full`
- `pnpm run scan:machine-wide:full:heartbeat-5s`
- `pnpm run scan:machine-wide:fast-preflight`
- `pnpm run scan:quiet`
- `pnpm run scan:help`

For custom flags such as `--root`, `--workers`, `--hosts-path`, or a custom JSON output path, forward arguments after `--`:

```bash
pnpm run scan -- --root ../repo-a --workers 8 --json ./docs/security/custom-scan.json
```

You can also forward explicit recycle-bin scan flags this way:

```bash
pnpm run scan:machine-wide -- --include-trash
pnpm run scan:machine-wide:full -- --include-recycle-bin
```

## Hosts and firewall remediation

The scanner now audits the live hosts file on Linux, macOS, and Windows and reports whether every managed block entry is already present.

- If all required entries are present, the CLI prints a green success indicator.
- If entries are missing, the CLI prints the missing lines explicitly.
- `--apply-hosts` appends or refreshes the managed hosts section without overwriting unrelated entries.

For raw IOC IP addresses, the hosts file is not sufficient. Use `--apply-firewall` to request operating-system-specific outbound blocking:

- Windows: PowerShell / `New-NetFirewallRule`
- Linux: `ufw` if available
- macOS: `pfctl`

These remediation operations may require administrator/root privileges.

For the full machine-wide remediation package, run the CLI elevated:

- Windows: run PowerShell or Terminal as Administrator
- Linux/macOS: run the command with `sudo` if hosts/firewall changes are required

### When admin/root privileges are required

Administrator/root privileges are **not** required for the normal scan path itself.

Administrator/root privileges are required only for mutation operations such as:

- `--apply-hosts`
- `--apply-firewall`
- any command that includes both of the above

If you start a non-elevated process with remediation flags, the scan can still complete, but the hosts-file or firewall mutation step may fail because the operating system denies the write operation.

## Preflight modes

The scanner defaults to **deep preflight**.

- default deep preflight
  Metadata-only inventory preflight. This walks the planned task subtrees before the actual scan, computes a better workload model, and can split very large areas into more execution tasks.
- `--fast-preflight`
  Explicitly disables the default deep preflight and falls back to the lighter task-based startup path.

Use the default deep mode when machine-wide scans are large and you want better visibility into:

- planned directories
- planned files
- planned candidate files
- planned `node_modules` roots
- the heaviest remaining tasks
- preflight-driven task splitting for very large areas

Example:

```bash
node src/cli/scan-supply-chain-campaigns.mjs --machine-wide
```

## Recycle bin scanning

The scanner excludes the OS trash / recycle bin by default.

This is intentional:

- the default machine-wide mode is optimized for active project and host coverage,
- the recycle bin is primarily forensic scope rather than active supply-chain scope,
- automatically emptying the recycle bin would destroy the very evidence an explicit forensic scan might want to inspect.
- even when explicitly enabled, recycle-bin scans skip the expensive recursive installed-package crawl under `node_modules` and keep the lighter project-file / payload-oriented coverage.

If you explicitly want recycle-bin coverage, pass one of these flags:

- `--include-trash`
- `--include-recycle-bin`

Example:

```bash
node src/cli/scan-supply-chain-campaigns.mjs --machine-wide --include-trash
```

## Heartbeat logs

The scanner emits periodic heartbeat logs by default while long phases are still running.

- Default interval: `10` seconds
- Override interval with `--heartbeat-sec <seconds>`
- Disable with `--no-heartbeat`
- Disable detailed process and progress output with `--quiet`

Example:

```bash
node src/cli/scan-supply-chain-campaigns.mjs --machine-wide --heartbeat-sec 5
```

The heartbeat is especially useful when a few heavy areas such as `C:\\Users`, `C:\\Projects`, `C:\\git`, or, when explicitly enabled, `$Recycle.Bin` dominate the remaining work.

Example:

```bash
node src/cli/scan-supply-chain-campaigns.mjs --machine-wide --preflight deep --verbose
```

## Scan modes

### Default mode

The default behavior is intentionally project-scoped:

- the scanner derives the project root from the repository that contains the CLI file,
- it scans only that project recursively,
- it also checks the documented fixed home-/machine-level artifact paths unless `--no-home` is used.

### Machine-wide mode

When `--machine-wide` is set:

- the scanner switches from project scope to host scope,
- all accessible local filesystem roots become scan roots,
- top-level subtrees are distributed across worker threads,
- the OS trash / recycle bin is excluded by default unless `--include-trash` is set,
- `node_modules`, suspicious payload files, persistence artifacts, and IOC-bearing files are searched across the full host scope.

`--machine-wide` and `--root` are intentionally mutually exclusive.

## PNPM governance audit

In addition to IOC- and persistence-detection, the scanner now performs a dedicated PNPM 11 Fortress governance audit on managed project roots.

The governance pass:

- discovers managed project roots recursively,
- excludes package-manager-managed areas such as `node_modules`, `.pnpm`, `.pnpm-store`, `.npm`, `.yarn`, `.bun`, `_cacache`, `_npx`, `jspm_packages`, and `bower_components`,
- classifies PNPM roots as `pnpm-single-project` or `pnpm-monorepo`,
- validates `pnpm-workspace.yaml`, the root `package.json`, and project-local `.npmrc` / `auth.ini`,
- checks for PNPM 11 pinning, Node.js LTS floor alignment, lockfile presence, build-script governance, trust policy, and workspace protocol usage,
- reports every discovered managed project with its path, status, and missing or invalid Fortress requirements.

Important scope rule:

- the governance audit is intentionally root-focused and does **not** treat package-manager-managed directories as user-controlled projects,
- the malware/IOC scan still inspects installed dependencies where appropriate,
- the governance audit and the IOC scan therefore cover different architectural surfaces on purpose.

## Documentation

- Detailed campaign analysis: `docs/security/supply-chain-campaigns-2026.md`
- Curated detection data: `src/data/supply-chain-campaigns-2026.mjs`
- Generated blocklists: `docs/security/blocklists/`
