import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { addFinding, createFindingsContainer, summarizeFindings } from '../domain/findings.mjs';
import {
  DEFAULT_WORKER_COUNT,
  SCAN_MODE_MACHINE,
  SCAN_MODE_PROJECT,
} from '../domain/policy.mjs';
import { detectProjectRoot, normalizeForDisplay, toAbsolutePath } from '../infrastructure/fs-utils.mjs';
import {
  applyFirewallRules,
  applyHostsFile,
  auditHostsFile,
  defaultHostsPath,
  writeBlocklists,
} from '../infrastructure/remediation.mjs';
import { ensureRipgrepInstalled } from '../infrastructure/ripgrep.mjs';
import {
  LATEST_FULL_SCAN_REPORT_BASENAME,
  resolveGeneratedReportPath,
  writeJsonArtifacts,
} from '../infrastructure/report-artifacts.mjs';
import { renderSummary, toSerializableResult } from '../presentation/reporting.mjs';
import {
  buildScanTasks,
  enumerateMachineRoots,
  inspectFixedHomePaths,
  inspectHomeContentRules,
  inspectWindowsRegistry,
  runWorkerPool,
} from './scanner.mjs';
import { auditPnpmGovernance, inspectPnpmRuntime } from './pnpm-governance.mjs';
import {
  PREFLIGHT_MODE_DEEP,
  PREFLIGHT_MODE_FAST,
  buildPreflightPlan,
  formatTaskPlanSummary,
} from './preflight.mjs';

const SCRIPT_FILE_PATH = fileURLToPath(import.meta.url);
const SCRIPT_DIR = path.dirname(SCRIPT_FILE_PATH);
const DEFAULT_PROJECT_ROOT = detectProjectRoot(SCRIPT_DIR);

export async function main() {
  const stageLogger = createStageLogger();
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

  let ripgrepVersion;
  try {
    ripgrepVersion = ensureRipgrepInstalled();
  } catch (error) {
    console.error(`Dependency error: ${error.message}`);
    process.exitCode = 2;
    return;
  }
  const pnpmRuntime = inspectPnpmRuntime();

  const findings = createFindingsContainer();
  logStageIfVerbose(stageLogger, args, 'preflight-started', 'Resolving scan scope and runtime dependencies');
  const normalizedRoots = [
    ...new Set(
      (
        args.mode === SCAN_MODE_MACHINE
          ? enumerateMachineRoots()
          : args.roots.length > 0
            ? args.roots.map(toAbsolutePath)
            : [DEFAULT_PROJECT_ROOT]
      ).map((rootPath) => path.resolve(rootPath)),
    ),
  ];
  args.roots = normalizedRoots;

  const tasks = buildScanTasks(normalizedRoots, args.mode, findings, { includeTrash: args.includeTrash });
  const preflightPlan = await buildPreflightPlan(
    tasks,
    { mode: args.preflight, heartbeatMs: args.heartbeatMs },
    (event) => logPreflightIfVerbose(stageLogger, args, event),
  );
  const executionTasks = preflightPlan.executionTasks ?? tasks;
  logStageIfVerbose(
    stageLogger,
    args,
    'preflight-complete',
    buildPreflightCompleteDetail(normalizedRoots.length, tasks.length, executionTasks.length, args, preflightPlan),
  );
  logHeaviestPreflightTasksIfVerbose(stageLogger, args, preflightPlan);
  logStageIfVerbose(stageLogger, args, 'scan-started', 'Starting parallel subtree scan');
  const { scanStats, workersUsed } = await runWorkerPool(executionTasks, findings, args, preflightPlan);
  logStageIfVerbose(
    stageLogger,
    args,
    'scan-complete',
    `Parallel subtree scan finished with workers=${workersUsed} dirs=${scanStats.directoriesVisited} candidate_files=${scanStats.candidateFilesVisited} node_modules_dirs=${scanStats.nodeModulesDirsVisited}`,
  );

  if (args.includeHome) {
    logStageIfVerbose(stageLogger, args, 'home-audit-started', 'Inspecting fixed home and machine persistence paths');
    inspectFixedHomePaths(findings);
    inspectHomeContentRules(findings);
    logStageIfVerbose(stageLogger, args, 'home-audit-complete', 'Finished inspecting fixed home and machine persistence paths');
  }

  logStageIfVerbose(stageLogger, args, 'registry-audit-started', 'Inspecting platform-specific registry/runtime persistence');
  inspectWindowsRegistry(findings);
  logStageIfVerbose(stageLogger, args, 'registry-audit-complete', 'Finished inspecting platform-specific registry/runtime persistence');

  logStageIfVerbose(stageLogger, args, 'pnpm-governance-started', 'Auditing managed project roots for PNPM 11 Fortress governance');
  const governanceAudit = auditPnpmGovernance(normalizedRoots, args, pnpmRuntime);
  logStageIfVerbose(
    stageLogger,
    args,
    'pnpm-governance-complete',
    `Managed projects=${governanceAudit.summary.projectCount} pnpm_projects=${governanceAudit.summary.pnpmProjectCount} passed=${governanceAudit.summary.passCount} failed=${governanceAudit.summary.failCount} warnings=${governanceAudit.summary.warningCount}`,
  );

  let blocklistPaths = null;
  if (args.writeBlocklistsDir) {
    logStageIfVerbose(stageLogger, args, 'blocklist-write-started', `Writing blocklists to ${args.writeBlocklistsDir}`);
    try {
      blocklistPaths = writeBlocklists(toAbsolutePath(args.writeBlocklistsDir));
      logStageIfVerbose(stageLogger, args, 'blocklist-write-complete', `Blocklists written to ${normalizeForDisplay(blocklistPaths.hostsPath)} and ${normalizeForDisplay(blocklistPaths.firewallPath)}`);
    } catch (error) {
      addFinding(findings.errors, {
        type: 'blocklist-write-error',
        path: normalizeForDisplay(args.writeBlocklistsDir),
        message: `Could not write blocklists to ${args.writeBlocklistsDir}: ${error.message}`,
      });
    }
  }

  const hostsPath = args.hostsPath ? toAbsolutePath(args.hostsPath) : defaultHostsPath();
  if (args.applyHosts) {
    logStageIfVerbose(stageLogger, args, 'hosts-apply-started', `Applying managed hosts entries to ${normalizeForDisplay(hostsPath)}`);
    try {
      applyHostsFile(hostsPath);
      console.log(`Applied managed hosts blocklist section to ${normalizeForDisplay(hostsPath)}`);
      logStageIfVerbose(stageLogger, args, 'hosts-apply-complete', `Managed hosts entries applied to ${normalizeForDisplay(hostsPath)}`);
    } catch (error) {
      addFinding(findings.errors, {
        type: 'hosts-apply-error',
        path: normalizeForDisplay(hostsPath),
        message: `Could not apply hosts blocklist to ${normalizeForDisplay(hostsPath)}: ${error.message}`,
      });
    }
  }

  logStageIfVerbose(stageLogger, args, 'hosts-audit-started', `Auditing hosts file ${normalizeForDisplay(hostsPath)}`);
  const hostsAudit = auditHostsFile(hostsPath);
  logStageIfVerbose(
    stageLogger,
    args,
    'hosts-audit-complete',
    hostsAudit.readable
      ? `Hosts audit finished: present=${hostsAudit.presentEntries.length} missing=${hostsAudit.missingEntries.length}`
      : `Hosts audit failed: ${hostsAudit.error}`,
  );
  let firewallAudit = null;
  if (args.applyFirewall) {
    logStageIfVerbose(stageLogger, args, 'firewall-apply-started', 'Applying outbound firewall IOC rules');
    firewallAudit = applyFirewallRules();
    if (firewallAudit?.error && !firewallAudit.requiresElevation) {
      addFinding(findings.errors, {
        type: 'firewall-apply-error',
        path: firewallAudit.provider ?? process.platform,
        message: firewallAudit.error,
      });
    }
    logStageIfVerbose(
      stageLogger,
      args,
      'firewall-apply-complete',
      firewallAudit?.error
        ? `Firewall remediation completed with warning/error: ${firewallAudit.error}`
        : `Firewall remediation completed: provider=${firewallAudit?.provider ?? 'unknown'}`,
    );
  }

  logStageIfVerbose(stageLogger, args, 'summary-started', 'Rendering final summary and optional JSON payload');
  renderSummary(findings, args, blocklistPaths, scanStats, workersUsed, hostsAudit, firewallAudit, preflightPlan, ripgrepVersion, governanceAudit);

  const payload = toSerializableResult(
    findings,
    args,
    blocklistPaths,
    scanStats,
    workersUsed,
    hostsAudit,
    firewallAudit,
    preflightPlan,
    ripgrepVersion,
    governanceAudit,
  );
  const latestReportPath = resolveGeneratedReportPath(LATEST_FULL_SCAN_REPORT_BASENAME);
  const exportReportPath = args.jsonPath === null
    ? null
    : args.jsonPath === '-'
      ? '-'
      : toAbsolutePath(args.jsonPath);
  try {
    writeJsonArtifacts({
      latestPath: latestReportPath,
      exportPath: exportReportPath,
      payload,
    });
  } catch (error) {
    console.error(`Could not write JSON report: ${error.message}`);
    process.exitCode = 2;
    return;
  }

  const summary = summarizeFindings(findings);
  const governanceFailures = governanceAudit?.summary?.failCount ?? 0;
  process.exitCode =
    summary.exactCount > 0 || summary.heuristicCount > 0 || summary.artifactCount > 0 || governanceFailures > 0
      ? 1
      : 0;
  logStageIfVerbose(
    stageLogger,
    args,
    'summary-complete',
    `Process finished with exact=${summary.exactCount} heuristic=${summary.heuristicCount} artifact=${summary.artifactCount} limitations=${summary.limitationCount} errors=${summary.errorCount}`,
  );
}

function printHelp() {
  console.log(`Supply-chain scanner (Axios + Shai-Hulud / Mini Shai-Hulud)

Usage:
  node src/cli/scan-supply-chain-campaigns.mjs [options]

Options:
  --root <path>              Override or add project roots. Repeatable.
  --machine-wide             Scan all accessible local filesystem roots on this host.
  --host-wide                Alias for --machine-wide.
  --workers <count>          Worker-thread count for parallel subtree scanning.
  --no-home                  Skip fixed machine/user paths under the current home directory.
  --json <path|->            Additionally write the full JSON result to a file or stdout ("-").
  --write-blocklists <dir>   Write hosts + firewall blocklist files into a directory.
  --apply-hosts              Apply a managed blocklist section to the local hosts file.
  --apply-firewall           Apply outbound firewall block rules for the documented IOC IPs.
  --hosts-path <path>        Override the hosts file path used by --apply-hosts.
  --include-trash            Include the OS trash/recycle bin in scans when encountered.
  --include-recycle-bin      Alias for --include-trash.
  --fast-preflight           Disable the default deep preflight and use the lighter task-based mode.
  --deep-preflight           Explicitly enable deep preflight (default).
  --heartbeat-sec <seconds>  Emit periodic heartbeat logs while long phases are running.
  --no-heartbeat             Disable periodic heartbeat logs.
  --quiet                    Disable detailed progress and process logs.
  --verbose                  Alias to re-enable detailed logs.
  --help                     Show this help.

Notes:
  - Default scan scope: the project root that contains this script + fixed machine paths.
  - --machine-wide scans all accessible local filesystem roots instead of only the project.
  - Worker threads shard subtrees, while each rg process runs with --threads 1 to avoid
    over-parallelizing the host.
  - Scans exclude the OS trash / recycle bin by default. Use --include-trash
    (or --include-recycle-bin) only when you explicitly want that additional forensic scope.
  - Deep preflight is enabled by default. Use --fast-preflight to disable the metadata-only
    inventory pass and fall back to the lighter task-based mode.
  - Heartbeats are enabled by default. Use --no-heartbeat to disable them. Default interval:
    10 seconds. Override with --heartbeat-sec.
  - The latest full scan JSON report is always written to ./generated/latest-scan.json.
  - ripgrep (rg) must be installed and available on PATH.
  - Managed project roots are also audited for PNPM 11 Fortress governance outside package-manager-managed areas such as node_modules, .pnpm, .pnpm-store, .yarn, .bun, jspm_packages, and bower_components.
  - Exact package/version hits are high confidence.
  - Heuristic hits look for the documented loader/payload/persistence patterns from the
    Axios incident and the Shai-Hulud / Mini-Shai-Hulud campaign family.
  - The hosts file can block domains, not raw IPs. IPs are written to a separate
    firewall-oriented blocklist file.
  - --apply-hosts and --apply-firewall may require administrator/root privileges.
`);
}

function parseArgs(argv) {
  const args = {
    roots: [],
    mode: SCAN_MODE_PROJECT,
    workers: DEFAULT_WORKER_COUNT,
    includeHome: true,
    jsonPath: null,
    writeBlocklistsDir: null,
    applyHosts: false,
    applyFirewall: false,
    hostsPath: null,
    includeTrash: false,
    preflight: PREFLIGHT_MODE_DEEP,
    heartbeatMs: 10_000,
    verbose: true,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];

    if (token === '--root') {
      const value = argv[index + 1];
      if (!value) {
        throw new Error('--root requires a path');
      }
      args.roots.push(value);
      index += 1;
      continue;
    }

    if (token === '--machine-wide' || token === '--host-wide') {
      args.mode = SCAN_MODE_MACHINE;
      continue;
    }

    if (token === '--workers') {
      const value = argv[index + 1];
      if (!value) {
        throw new Error('--workers requires a positive integer');
      }
      const parsed = Number.parseInt(value, 10);
      if (!Number.isInteger(parsed) || parsed < 1) {
        throw new Error('--workers requires a positive integer');
      }
      args.workers = parsed;
      index += 1;
      continue;
    }

    if (token === '--no-home') {
      args.includeHome = false;
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

    if (token === '--write-blocklists') {
      const value = argv[index + 1];
      if (!value) {
        throw new Error('--write-blocklists requires a directory path');
      }
      args.writeBlocklistsDir = value;
      index += 1;
      continue;
    }

    if (token === '--apply-hosts') {
      args.applyHosts = true;
      continue;
    }

    if (token === '--apply-firewall') {
      args.applyFirewall = true;
      continue;
    }

    if (token === '--hosts-path') {
      const value = argv[index + 1];
      if (!value) {
        throw new Error('--hosts-path requires a path');
      }
      args.hostsPath = value;
      index += 1;
      continue;
    }

    if (token === '--fast-preflight') {
      args.preflight = PREFLIGHT_MODE_FAST;
      continue;
    }

    if (token === '--deep-preflight') {
      args.preflight = PREFLIGHT_MODE_DEEP;
      continue;
    }

    if (token === '--preflight') {
      const value = argv[index + 1];
      if (!value || ![PREFLIGHT_MODE_FAST, PREFLIGHT_MODE_DEEP].includes(value)) {
        throw new Error('--preflight requires "fast" or "deep"');
      }
      args.preflight = value;
      index += 1;
      continue;
    }

    if (token === '--heartbeat-sec') {
      const value = argv[index + 1];
      const parsed = Number.parseInt(value ?? '', 10);
      if (!Number.isInteger(parsed) || parsed < 1) {
        throw new Error('--heartbeat-sec requires a positive integer');
      }
      args.heartbeatMs = parsed * 1_000;
      index += 1;
      continue;
    }

    if (token === '--no-heartbeat') {
      args.heartbeatMs = 0;
      continue;
    }

    if (token === '--include-trash' || token === '--include-recycle-bin') {
      args.includeTrash = true;
      continue;
    }

    if (token === '--quiet') {
      args.verbose = false;
      continue;
    }

    if (token === '--verbose') {
      args.verbose = true;
      continue;
    }

    if (token === '--help' || token === '-h') {
      args.help = true;
      continue;
    }

    throw new Error(`Unknown argument: ${token}`);
  }

  if (args.mode === SCAN_MODE_MACHINE && args.roots.length > 0) {
    throw new Error('--machine-wide cannot be combined with --root');
  }
  return args;
}

function createStageLogger() {
  return {
    index: 0,
    startedAt: Date.now(),
  };
}

function logStageIfVerbose(stageLogger, args, stageName, detail) {
  if (!args.verbose) {
    return;
  }
  stageLogger.index += 1;
  console.log(
    `[process][${String(stageLogger.index).padStart(2, '0')}][+${formatStageDuration(Date.now() - stageLogger.startedAt)}] ${stageName}: ${detail}`,
  );
}

function formatStageDuration(durationMs) {
  const safeDurationMs = Math.max(0, durationMs);
  const totalSeconds = Math.floor(safeDurationMs / 1000);
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  const milliseconds = safeDurationMs % 1000;
  return `${[hours, minutes, seconds].map((value) => String(value).padStart(2, '0')).join(':')}.${String(milliseconds).padStart(3, '0')}`;
}

function logPreflightIfVerbose(stageLogger, args, event) {
  if (!args.verbose || args.preflight !== PREFLIGHT_MODE_DEEP) {
    return;
  }
  if (event.phase === 'deep-preflight-started') {
    console.log(
      `[preflight][+${formatStageDuration(Date.now() - stageLogger.startedAt)}] started deep inventory total_tasks=${event.totalTasks}`,
    );
    return;
  }
  if (event.phase === 'deep-preflight-task-complete') {
    const percent = event.totalTasks === 0
      ? 100
      : Math.floor((event.completedTasks / event.totalTasks) * 100);
    console.log(
      `[preflight][${event.completedTasks}/${event.totalTasks} ${String(percent).padStart(3, ' ')}%][+${formatStageDuration(Date.now() - stageLogger.startedAt)}] ${formatTaskPlanSummary(event.taskPlan)}`,
    );
    return;
  }
  if (event.phase === 'deep-preflight-heartbeat') {
    const currentTask = event.currentTask;
    console.log(
      `[preflight][heartbeat][${event.completedTasks}/${event.totalTasks} completed][+${formatStageDuration(event.elapsedMs)}] task=${currentTask.taskId} path=${normalizeForDisplay(currentTask.rootPath)} running=${formatStageDuration(currentTask.elapsedMs)} dirs=${currentTask.directoriesVisited} files=${currentTask.filesVisited} candidate_files=${currentTask.candidateFilesDiscovered} node_modules_roots=${currentTask.nodeModulesRootsDiscovered}`,
    );
  }
}

function buildPreflightCompleteDetail(rootCount, taskCount, executionTaskCount, args, preflightPlan) {
  if (preflightPlan.mode === PREFLIGHT_MODE_DEEP) {
    return `Resolved roots=${rootCount} source_tasks=${taskCount} execution_tasks=${executionTaskCount} requested_workers=${args.workers} preflight=${preflightPlan.mode} total_dirs=${preflightPlan.totals.directoriesVisited} total_files=${preflightPlan.totals.filesVisited} candidate_files=${preflightPlan.totals.candidateFilesDiscovered} node_modules_roots=${preflightPlan.totals.nodeModulesRootsDiscovered} split_tasks=${preflightPlan.splitSummary?.splitTaskCount ?? 0}`;
  }
  return `Resolved roots=${rootCount} source_tasks=${taskCount} execution_tasks=${executionTaskCount} requested_workers=${args.workers} preflight=${preflightPlan.mode}`;
}

function logHeaviestPreflightTasksIfVerbose(stageLogger, args, preflightPlan) {
  if (!args.verbose || preflightPlan.mode !== PREFLIGHT_MODE_DEEP) {
    return;
  }
  for (const taskPlan of preflightPlan.heaviestTasks) {
    console.log(
      `[preflight][top][+${formatStageDuration(Date.now() - stageLogger.startedAt)}] ${formatTaskPlanSummary(taskPlan)}`,
    );
  }
}
