# CLI Usage

## Direct Node.js execution

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

Write blocklists:

```bash
node src/cli/scan-supply-chain-campaigns.mjs --write-blocklists ./docs/security/blocklists
```

Apply the managed hosts section:

```bash
node src/cli/scan-supply-chain-campaigns.mjs --apply-hosts
```

Apply outbound firewall rules:

```bash
node src/cli/scan-supply-chain-campaigns.mjs --apply-firewall
```

Standalone PNPM governance scan (current project scope only):

```bash
node src/cli/scan-pnpm-governance.mjs
```

Standalone PNPM governance scan for one or more explicit roots:

```bash
node src/cli/scan-pnpm-governance.mjs C:\git
node src/cli/scan-pnpm-governance.mjs C:\git,C:\Projects
node src/cli/scan-pnpm-governance.mjs C:\git C:\Projects
```

Complete machine-wide scan plus remediation:

```bash
node src/cli/scan-supply-chain-campaigns.mjs --machine-wide --apply-hosts --apply-firewall
```

## pnpm scripts

- `pnpm run scan`
- `pnpm run scan:project`
- `pnpm run scan:project:verbose`
- `pnpm run scan:machine-wide`
- `pnpm run scan:machine-wide:verbose`
- `pnpm run scan:no-home`
- `pnpm run scan:blocklists`
- `pnpm run scan:json`
- `pnpm run scan:apply-hosts`
- `pnpm run scan:apply-firewall`
- `pnpm run scan:machine-wide:full`
- `pnpm run scan:machine-wide:full:heartbeat-5s`
- `pnpm run scan:machine-wide:fast-preflight`
- `pnpm run scan:pnpm-governance`
- `pnpm run scan:pnpm-governance:help`
- `pnpm run scan:quiet`
- `pnpm run scan:help`

## Forwarding custom flags

```bash
pnpm run scan -- --root ../repo-a --workers 8 --json ./docs/security/custom-scan.json
```

You can also forward recycle-bin flags:

```bash
pnpm run scan:machine-wide -- --include-trash
pnpm run scan:machine-wide:full -- --include-recycle-bin
```

You can forward explicit governance roots either as separate positional arguments or as a single comma-separated value:

```bash
pnpm run scan:pnpm-governance -- C:\git
pnpm run scan:pnpm-governance -- C:\git,C:\Projects
pnpm run scan:pnpm-governance -- C:\git C:\Projects
```
