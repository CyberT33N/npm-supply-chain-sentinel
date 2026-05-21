# Scan Execution Model

## Scan modes

### Default mode

The default behavior is intentionally project-scoped:

- the scanner derives the project root from the repository that contains the CLI file,
- it scans only that project recursively,
- it can still inspect documented fixed home and machine artifact paths unless `--no-home` is used.

### Machine-wide mode

When `--machine-wide` is set:

- the scanner switches from project scope to host scope,
- all accessible local filesystem roots become scan roots,
- top-level subtrees are distributed across worker threads,
- the OS trash or recycle bin is excluded by default unless `--include-trash` is set,
- IOC and persistence inspection may still reach broader runtime surfaces than the governance audit.

`--machine-wide` and `--root` are intentionally mutually exclusive.

## Preflight modes

The scanner defaults to deep preflight.

- default deep preflight
  Metadata-only inventory preflight that computes a better workload model and can split very large areas into more execution tasks.
- `--fast-preflight`
  Disables the default deep preflight and falls back to the lighter task-based startup path.

Use deep preflight when machine-wide scans are large and you want visibility into:

- planned directories
- planned files
- planned candidate files
- planned `node_modules` roots
- the heaviest remaining tasks
- preflight-driven task splitting for very large areas

## Recycle bin scanning

The scanner excludes the OS trash or recycle bin by default.

This keeps the default machine-wide mode focused on active project and host coverage rather than explicit forensic trash recovery.

If you want recycle-bin coverage, pass one of these flags:

- `--include-trash`
- `--include-recycle-bin`

## Heartbeat logs

The scanner emits periodic heartbeat logs by default while long phases are still running.

- default interval: `10` seconds
- override interval with `--heartbeat-sec <seconds>`
- disable with `--no-heartbeat`
- disable detailed progress output with `--quiet`

Heartbeat output is especially useful when large roots such as user-home or project drives dominate the remaining work.
