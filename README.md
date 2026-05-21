# npm-supply-chain-sentinel

Cross-platform Node.js scanner and threat-intelligence repository for detecting documented npm supply-chain compromises, malicious install hooks, persistence artifacts, and campaign IOCs across individual projects or entire hosts.

## Runtime dependencies

`npm-supply-chain-sentinel` requires the following runtime dependencies:

- Node.js `>=20`
- `ripgrep` (`rg`) on `PATH`

`ripgrep` is a required runtime dependency for the scanner and must be installed before running the CLI.

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
- project-mode and machine-wide scan modes,
- worker-thread-based parallel traversal,
- a required `ripgrep`-backed runtime environment,
- blocklist generation for hosts and firewall workflows,
- incident-response documentation.

## Architecture

This repository is intentionally split by responsibility:

- `src/cli`
  The delivery layer. This is the executable scanner entrypoint and orchestration boundary.
- `src/data`
  The curated threat-intelligence and detection-policy layer. This is the canonical source of campaign metadata, exact package-version rules, IOC lists, and heuristic signatures.
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
  data/
    supply-chain-campaigns-2026.mjs
docs/
  security/
    supply-chain-campaigns-2026.md
    blocklists/
      supply-chain-2026.hosts
      supply-chain-2026-firewall.txt
```

## Usage

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

Equivalent npm script (uses the default deep preflight):

```bash
npm run scan:machine-wide:full
```

Equivalent npm script with a 5-second heartbeat:

```bash
npm run scan:machine-wide:full:heartbeat-5s
```

Interactive machine-wide runs can offer to empty the native OS trash / recycle bin before preflight when items are detected there.

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

Equivalent npm script:

```bash
npm run scan:machine-wide:full
```

Deep preflight is enabled by default. If you want a lighter startup and less pre-scan work:

```bash
node src/cli/scan-supply-chain-campaigns.mjs --machine-wide --fast-preflight --apply-hosts --apply-firewall
```

If you want to empty the native OS trash / recycle bin before preflight without an interactive prompt:

```bash
node src/cli/scan-supply-chain-campaigns.mjs --machine-wide --empty-trash --apply-hosts --apply-firewall
```

Heartbeat logs are enabled by default. If you want a shorter heartbeat interval:

```bash
node src/cli/scan-supply-chain-campaigns.mjs --machine-wide --heartbeat-sec 5 --apply-hosts --apply-firewall
```

### Windows

For a normal detection-only scan, a regular terminal is sufficient.

For `--apply-hosts`, `--apply-firewall`, or the full remediation package, open **PowerShell as Administrator** and then run:

```powershell
npm run scan:machine-wide:full
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

### npm scripts

The repository exposes ready-to-run npm scripts:

- `npm run scan`
- `npm run scan:project`
- `npm run scan:project:verbose`
- `npm run scan:machine-wide`
- `npm run scan:machine-wide:verbose`
- `npm run scan:no-home`
- `npm run scan:blocklists`
- `npm run scan:json`
- `npm run scan:apply-firewall`
- `npm run scan:machine-wide:full`
- `npm run scan:machine-wide:full:heartbeat-5s`
- `npm run scan:machine-wide:fast-preflight`
- `npm run scan:quiet`
- `npm run scan:help`

For custom flags such as `--root`, `--workers`, `--hosts-path`, or a custom JSON output path, forward arguments after `--`:

```bash
npm run scan -- --root ../repo-a --workers 8 --json ./docs/security/custom-scan.json
```

You can also forward trash-handling flags this way:

```bash
npm run scan:machine-wide:full -- --empty-trash
npm run scan:machine-wide:full -- --no-trash-prompt
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

## Trash / recycle bin handling

Before interactive machine-wide scans, the CLI can inspect the native OS trash / recycle bin and offer to empty it before preflight starts.

- Windows: `Clear-RecycleBin -Force`
- macOS: `osascript -e 'tell application "Finder" to empty the trash'`
- Ubuntu/Linux: `gio trash --empty` when available, with `gvfs-trash --empty` as a distro-provided fallback when present
- No `rm -rf` fallback is used

Behavior:

- Interactive machine-wide runs may show a yes/no prompt when trash items are detected.
- `--empty-trash` skips the prompt and attempts native cleanup immediately before preflight.
- `--no-trash-prompt` suppresses the interactive prompt.
- If no supported native command is available on Linux, the scan continues without trash cleanup.

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

The heartbeat is especially useful when a few heavy areas such as `C:\\Users`, `C:\\Projects`, `C:\\git`, or `$Recycle.Bin` dominate the remaining work.

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
- `node_modules`, suspicious payload files, persistence artifacts, and IOC-bearing files are searched across the full host scope.

`--machine-wide` and `--root` are intentionally mutually exclusive.

## Documentation

- Detailed campaign analysis: `docs/security/supply-chain-campaigns-2026.md`
- Curated detection data: `src/data/supply-chain-campaigns-2026.mjs`
- Generated blocklists: `docs/security/blocklists/`
