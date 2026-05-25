# Remediation

## Hosts-file audit and update

The scanner audits the live hosts file on Linux, macOS, and Windows and reports whether every managed block entry is already present.

- If all required entries are present, the CLI prints a success indicator.
- If entries are missing, the CLI prints the missing lines explicitly.
- `--apply-hosts` appends or refreshes the managed hosts section without overwriting unrelated entries.

## Firewall rule application

For raw IOC IP addresses, the hosts file is not sufficient. Use `--apply-firewall` to request operating-system-specific outbound blocking.

- Windows: PowerShell and `New-NetFirewallRule`
- Linux: `ufw` when available
- macOS: `pfctl`

## Privilege model

Administrator or root privileges are not required for the normal scan path itself.

Administrator or root privileges are required only for mutation operations such as:

- `--apply-hosts`
- `--apply-firewall`
- any command that combines those flags

## Operator guidance

### Windows

For detection-only scans, a normal terminal is sufficient.

For remediation, open PowerShell as Administrator and run:

```powershell
pnpm run scan:machine-wide:full
```

### Linux

For remediation, run the command elevated:

```bash
sudo node --import tsx ./src/cli/scan-supply-chain-campaigns.ts --machine-wide --apply-hosts --apply-firewall
```

### macOS

For remediation, run the command elevated:

```bash
sudo node --import tsx ./src/cli/scan-supply-chain-campaigns.ts --machine-wide --apply-hosts --apply-firewall
```
