#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const cliEntrypoint = fileURLToPath(
  new URL('../src/cli/scan-pnpm-governance.ts', import.meta.url),
);

const result = spawnSync(
  process.execPath,
  ['--import', 'tsx', cliEntrypoint, ...process.argv.slice(2)],
  {
    env: process.env,
    stdio: 'inherit',
    windowsHide: true,
  },
);

if (result.error) {
  throw result.error;
}

process.exit(result.status ?? 1);
