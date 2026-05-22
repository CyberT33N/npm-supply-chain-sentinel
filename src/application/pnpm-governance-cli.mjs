import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { SCAN_MODE_MACHINE, SCAN_MODE_PROJECT } from '../domain/policy.mjs';
import { detectProjectRoot, normalizeForDisplay, toAbsolutePath } from '../infrastructure/fs-utils.mjs';
import {
  LATEST_PNPM_GOVERNANCE_REPORT_BASENAME,
  resolveGeneratedReportPath,
  writeJsonArtifacts,
} from '../infrastructure/report-artifacts.mjs';
import { renderPnpmGovernanceAudit, toSerializablePnpmGovernanceResult } from '../presentation/pnpm-governance-reporting.mjs';
import { enumerateMachineRoots } from './scanner.mjs';
import { auditPnpmGovernance, inspectPnpmRuntime } from './pnpm-governance.mjs';

const SCRIPT_FILE_PATH = fileURLToPath(import.meta.url);
const SCRIPT_DIR = path.dirname(SCRIPT_FILE_PATH);
const DEFAULT_PROJECT_ROOT = detectProjectRoot(SCRIPT_DIR);

export async function main() {
  let args;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (error) {
    console.error(`Argument error: ${error.message}`);
    console.error('Use --help for usage.');
    process.exitCode = 2;
    return;
  }

  if (args.help) {
    printHelp();
    return;
  }

  args.roots = resolveRoots(args);
  const pnpmRuntime = inspectPnpmRuntime();
  const governanceAudit = auditPnpmGovernance(args.roots, args, pnpmRuntime);

  renderStandaloneGovernanceSummary(args, governanceAudit);

  const latestReportPath = resolveGeneratedReportPath(LATEST_PNPM_GOVERNANCE_REPORT_BASENAME);
  const exportReportPath = args.jsonPath === null
    ? null
    : args.jsonPath === '-'
      ? '-'
      : toAbsolutePath(args.jsonPath);
  try {
    writeJsonArtifacts({
      latestPath: latestReportPath,
      exportPath: exportReportPath,
      payload: toSerializablePnpmGovernanceResult(governanceAudit, args),
    });
  } catch (error) {
    console.error(`Could not write JSON report: ${error.message}`);
    process.exitCode = 2;
    return;
  }

  process.exitCode = governanceAudit?.summary?.failCount > 0 ? 1 : 0;
}

function printHelp() {
  console.log(`PNPM governance scanner

Usage:
  node src/cli/scan-pnpm-governance.mjs [options] [path[,path...]] ...

Options:
  --root <path>              Add an explicit governance root. Repeatable.
  --roots <path[,path...]>   Add one or more explicit roots as a comma-separated list.
  --machine-wide             Audit all accessible local filesystem roots on this host.
  --host-wide                Alias for --machine-wide.
  --include-trash            Include the OS trash/recycle bin during machine-wide discovery.
  --include-recycle-bin      Alias for --include-trash.
  --json <path|->            Additionally write the governance JSON result to a file or stdout ("-").
  --help                     Show this help.

Notes:
  - Positional paths are accepted. Each positional token may be a single path or a comma-separated list.
  - Default scope: the project root that contains this CLI.
  - The latest governance JSON report is always written to ./generated/latest-pnpm-governance-scan.json.
  - This command runs only the PNPM governance audit. It does not run IOC, malware,
    persistence, hosts, firewall, or remediation flows.
  - --machine-wide cannot be combined with explicit paths.

Examples:
  node src/cli/scan-pnpm-governance.mjs
  node src/cli/scan-pnpm-governance.mjs C:\\git
  node src/cli/scan-pnpm-governance.mjs C:\\git,C:\\Projects
  node src/cli/scan-pnpm-governance.mjs C:\\git C:\\Projects
  node src/cli/scan-pnpm-governance.mjs --root C:\\git --roots C:\\Projects,D:\\repos
`);
}

function parseArgs(argv) {
  const args = {
    roots: [],
    mode: SCAN_MODE_PROJECT,
    includeTrash: false,
    jsonPath: null,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];

    if (token === '--root' || token === '--roots') {
      const value = argv[index + 1];
      if (!value) {
        throw new Error(`${token} requires a path or comma-separated paths`);
      }
      appendCliRoots(args.roots, value, token);
      index += 1;
      continue;
    }

    if (token === '--machine-wide' || token === '--host-wide') {
      args.mode = SCAN_MODE_MACHINE;
      continue;
    }

    if (token === '--include-trash' || token === '--include-recycle-bin') {
      args.includeTrash = true;
      continue;
    }

    if (token === '--json') {
      const value = argv[index + 1];
      if (!value) {
        throw new Error('--json requires a path or "-"');
      }
      args.jsonPath = value;
      index += 1;
      continue;
    }

    if (token === '--help' || token === '-h') {
      args.help = true;
      continue;
    }

    if (token.startsWith('-')) {
      throw new Error(`Unknown argument: ${token}`);
    }

    appendCliRoots(args.roots, token, 'path');
  }

  if (args.mode === SCAN_MODE_MACHINE && args.roots.length > 0) {
    throw new Error('--machine-wide cannot be combined with explicit paths');
  }

  return args;
}

function appendCliRoots(target, rawValue, optionName) {
  if (typeof rawValue !== 'string' || rawValue.trim().length === 0) {
    throw new Error(`${optionName} requires at least one path`);
  }

  const parts = rawValue
    .split(',')
    .map((part) => part.trim());

  if (parts.some((part) => part.length === 0)) {
    throw new Error(`${optionName} contains an empty path segment`);
  }

  target.push(...parts);
}

function resolveRoots(args) {
  const rawRoots = args.mode === SCAN_MODE_MACHINE
    ? enumerateMachineRoots()
    : args.roots.length > 0
      ? args.roots.map(toAbsolutePath)
      : [DEFAULT_PROJECT_ROOT];

  return [...new Set(rawRoots.map((rootPath) => path.resolve(rootPath)))];
}

function renderStandaloneGovernanceSummary(args, governanceAudit) {
  console.log('');
  console.log('=== PNPM governance scan summary ===');
  console.log(`Mode: ${args.mode}`);
  console.log(`Roots scanned: ${args.roots.length}`);
  if (args.mode === SCAN_MODE_MACHINE || args.includeTrash) {
    console.log(`Recycle bin scan: ${args.includeTrash ? 'included (explicit)' : 'excluded (default)'}`);
  }
  console.log('Resolved roots:');
  for (const rootPath of args.roots) {
    console.log(`- ${normalizeForDisplay(rootPath)}`);
  }
  console.log('');
  renderPnpmGovernanceAudit(governanceAudit);
}

