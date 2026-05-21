import process from 'node:process';

import { stripInternalKeys, summarizeFindings } from '../domain/findings.mjs';
import {
  ANSI_COLORS,
  STATUS_ERROR_SYMBOL,
  STATUS_OK_SYMBOL,
  STATUS_WARN_SYMBOL,
  buildManagedHostsEntries,
  dataset,
} from '../domain/policy.mjs';
import { normalizeForDisplay } from '../infrastructure/fs-utils.mjs';

export function colorize(text, colorName) {
  if (!process.stdout.isTTY) {
    return text;
  }
  const color = ANSI_COLORS[colorName];
  if (!color) {
    return text;
  }
  return `${color}${text}${ANSI_COLORS.reset}`;
}

export function renderSummary(findings, options, blocklistPaths, scanStats, workersUsed, hostsAudit, firewallAudit, preflightPlan, ripgrepVersion, trashStatus) {
  const { exactCount, heuristicCount, artifactCount, errorCount } = summarizeFindings(findings);

  console.log('');
  console.log('=== Supply-chain scan summary ===');
  console.log(`Mode: ${options.mode}`);
  console.log(`Roots scanned: ${options.roots.length}`);
  console.log(`Worker threads: ${workersUsed}`);
  console.log(`Preflight mode: ${preflightPlan?.mode ?? 'fast'}`);
  console.log(`Progress model: ${preflightPlan?.progressModel ?? 'tasks'}`);
  if (preflightPlan?.splitSummary) {
    console.log(`Execution tasks: ${preflightPlan.splitSummary.executionTasks} (from ${preflightPlan.splitSummary.sourceTasks} source tasks, split heavy tasks=${preflightPlan.splitSummary.splitTaskCount})`);
  }
  console.log(`ripgrep runtime: ${ripgrepVersion}`);
  console.log(`Exact package/version hits: ${exactCount}`);
  console.log(`Heuristic package/manifest hits: ${heuristicCount}`);
  console.log(`Artifact/persistence hits: ${artifactCount}`);
  console.log(`Scanner errors: ${errorCount}`);
  console.log(`Directories visited: ${scanStats.directoriesVisited}`);
  console.log(`Candidate files inspected: ${scanStats.candidateFilesVisited}`);
  console.log(`node_modules directories inspected: ${scanStats.nodeModulesDirsVisited}`);
  console.log(
    `Traversal access issues: EACCES=${scanStats.traversalErrors.EACCES}, EPERM=${scanStats.traversalErrors.EPERM}, ENOENT=${scanStats.traversalErrors.ENOENT}, OTHER=${scanStats.traversalErrors.OTHER}`,
  );
  console.log('');

  if (preflightPlan?.mode === 'deep') {
    console.log('Deep preflight inventory:');
    console.log(`- Planned directories: ${preflightPlan.totals.directoriesVisited}`);
    console.log(`- Planned files: ${preflightPlan.totals.filesVisited}`);
    console.log(`- Planned candidate files: ${preflightPlan.totals.candidateFilesDiscovered}`);
    console.log(`- Planned node_modules roots: ${preflightPlan.totals.nodeModulesRootsDiscovered}`);
    console.log(`- Planned workload units: ${preflightPlan.totals.workUnits}`);
    console.log('');

    if (preflightPlan.heaviestTasks.length > 0) {
      console.log('Heaviest planned tasks:');
      for (const taskPlan of preflightPlan.heaviestTasks) {
        console.log(
          `- ${normalizeForDisplay(taskPlan.rootPath)} (work=${taskPlan.workUnits}, dirs=${taskPlan.inventory.directoriesVisited}, files=${taskPlan.inventory.filesVisited}, candidateFiles=${taskPlan.inventory.candidateFilesDiscovered}, nodeModulesRoots=${taskPlan.inventory.nodeModulesRootsDiscovered})`,
        );
      }
      console.log('');
    }
  }

  renderTrashStatus(trashStatus);

  if (exactCount > 0) {
    console.log('High-confidence exact hits:');
    for (const finding of findings.exactHits) {
      console.log(`- ${finding.message}`);
    }
    console.log('');
  }

  if (heuristicCount > 0) {
    console.log('Heuristic hits:');
    for (const finding of findings.heuristicHits) {
      console.log(`- ${finding.message}`);
    }
    console.log('');
  }

  if (artifactCount > 0) {
    console.log('Artifact / persistence hits:');
    for (const finding of findings.artifactHits) {
      console.log(`- ${finding.message}`);
    }
    console.log('');
  }

  if (errorCount > 0) {
    console.log('Scanner errors:');
    for (const finding of findings.errors) {
      console.log(`- ${finding.message}`);
    }
    console.log('');
  }

  console.log('Required hosts-file entries:');
  for (const entry of buildManagedHostsEntries()) {
    console.log(`- ${entry.line}`);
  }
  console.log('');
  renderHostsAudit(hostsAudit);

  console.log('Recommended firewall/IP blocks:');
  for (const ip of dataset.networkIndicators.firewallIpBlocklist) {
    console.log(`- ${ip}`);
  }
  console.log('');
  renderFirewallAudit(firewallAudit);

  console.log('Detection-only domains (do not blindly hosts-block globally):');
  for (const domain of dataset.networkIndicators.detectionOnlyDomains) {
    console.log(`- ${domain}`);
  }
  console.log('');

  for (const caveat of dataset.blocklistCaveats) {
    console.log(`Caveat: ${caveat}`);
  }
  console.log('');

  if (blocklistPaths && options.verbose) {
    console.log(`Blocklist files written: ${normalizeForDisplay(blocklistPaths.hostsPath)}`);
    console.log(`Firewall file written: ${normalizeForDisplay(blocklistPaths.firewallPath)}`);
    console.log('');
  }
}

export function toSerializableResult(findings, options, blocklistPaths, scanStats, workersUsed, hostsAudit, firewallAudit, preflightPlan, ripgrepVersion, trashStatus) {
  const summary = summarizeFindings(findings);
  return {
    scanner: 'CyberT33N-supply-chain-2026',
    generatedAt: new Date().toISOString(),
    mode: options.mode,
    platform: {
      os: process.platform,
      arch: process.arch,
      node: process.version,
    },
    runtimeDependencies: {
      ripgrep: ripgrepVersion,
    },
    roots: options.roots.map((rootPath) => normalizeForDisplay(rootPath)),
    workers: workersUsed,
    preflight: preflightPlan
      ? {
          mode: preflightPlan.mode,
          progressModel: preflightPlan.progressModel,
          totals: preflightPlan.totals,
          splitSummary: preflightPlan.splitSummary,
          heaviestTasks: preflightPlan.heaviestTasks.map((taskPlan) => ({
            taskId: taskPlan.taskId,
            rootPath: normalizeForDisplay(taskPlan.rootPath),
            workUnits: taskPlan.workUnits,
            inventory: taskPlan.inventory,
          })),
        }
      : null,
    includeHome: options.includeHome,
    summary,
    scanStats,
    conclusions: dataset.executiveConclusions,
    findings: {
      exactHits: stripInternalKeys(findings.exactHits),
      heuristicHits: stripInternalKeys(findings.heuristicHits),
      artifactHits: stripInternalKeys(findings.artifactHits),
      errors: stripInternalKeys(findings.errors),
    },
    blocklists: {
      hostsDomains: dataset.networkIndicators.hostsBlocklistDomains,
      firewallIps: dataset.networkIndicators.firewallIpBlocklist,
      detectionOnlyDomains: dataset.networkIndicators.detectionOnlyDomains,
      detectionOnlyIps: dataset.networkIndicators.detectionOnlyIps,
      writtenFiles: blocklistPaths
        ? {
            hostsPath: normalizeForDisplay(blocklistPaths.hostsPath),
            firewallPath: normalizeForDisplay(blocklistPaths.firewallPath),
          }
        : null,
    },
    remediation: {
      trashStatus: trashStatus
        ? {
            before: serializeTrashAudit(trashStatus.before),
            promptOffered: trashStatus.promptOffered,
            userChoice: trashStatus.userChoice,
            action: serializeTrashAction(trashStatus.action),
            after: serializeTrashAudit(trashStatus.after),
          }
        : null,
      hostsAudit: hostsAudit
        ? {
            path: normalizeForDisplay(hostsAudit.path),
            readable: hostsAudit.readable,
            presentEntries: hostsAudit.presentEntries.map((entry) => entry.line),
            missingEntries: hostsAudit.missingEntries.map((entry) => entry.line),
            error: hostsAudit.error,
          }
        : null,
      firewallAudit,
    },
  };
}

function renderTrashStatus(trashStatus) {
  if (!trashStatus?.before) {
    return;
  }

  console.log('Trash / recycle bin status:');
  console.log(`- Provider: ${trashStatus.before.provider}`);
  console.log(`- Native empty command available: ${trashStatus.before.available ? 'yes' : 'no'}`);
  if (trashStatus.before.command) {
    console.log(`- Native empty command: ${trashStatus.before.command}`);
  }
  if (trashStatus.before.path) {
    console.log(`- Inspected path: ${normalizeForDisplay(trashStatus.before.path)}`);
  }
  if (trashStatus.before.error) {
    console.log(`- Audit error: ${trashStatus.before.error}`);
  } else if (trashStatus.before.hasItems == null) {
    console.log('- Items detected before scan: unknown');
  } else {
    const itemCount = Number.isInteger(trashStatus.before.itemCount) ? trashStatus.before.itemCount : 'unknown';
    console.log(`- Items detected before scan: ${itemCount}`);
  }

  if (trashStatus.promptOffered) {
    console.log(`- Interactive prompt shown: yes (${trashStatus.userChoice})`);
  } else if (trashStatus.userChoice !== 'not-asked') {
    console.log(`- Trash handling mode: ${trashStatus.userChoice}`);
  }

  if (trashStatus.action) {
    const color = trashStatus.action.succeeded ? 'green' : 'yellow';
    const symbol = trashStatus.action.succeeded ? STATUS_OK_SYMBOL : STATUS_WARN_SYMBOL;
    const message = trashStatus.action.succeeded
      ? 'Native trash/recycle bin cleanup completed.'
      : `Native trash/recycle bin cleanup did not complete: ${trashStatus.action.error}`;
    console.log(`${colorize(symbol, color)} ${colorize(message, color)}`);
    for (const warning of trashStatus.action.warnings ?? []) {
      console.log(`  ${colorize(STATUS_WARN_SYMBOL, 'yellow')} ${warning}`);
    }
  }

  if (trashStatus.after) {
    if (trashStatus.after.error) {
      console.log(`- Items detected after cleanup: unknown (${trashStatus.after.error})`);
    } else if (trashStatus.after.hasItems == null) {
      console.log('- Items detected after cleanup: unknown');
    } else {
      const itemCount = Number.isInteger(trashStatus.after.itemCount) ? trashStatus.after.itemCount : 'unknown';
      console.log(`- Items detected after cleanup: ${itemCount}`);
    }
  }

  console.log('');
}

function serializeTrashAudit(trashAudit) {
  if (!trashAudit) {
    return null;
  }
  return {
    provider: trashAudit.provider,
    supported: trashAudit.supported,
    available: trashAudit.available,
    hasItems: trashAudit.hasItems,
    itemCount: trashAudit.itemCount,
    command: trashAudit.command,
    path: trashAudit.path ? normalizeForDisplay(trashAudit.path) : null,
    warnings: trashAudit.warnings ?? [],
    error: trashAudit.error,
  };
}

function serializeTrashAction(trashAction) {
  if (!trashAction) {
    return null;
  }
  return {
    provider: trashAction.provider,
    supported: trashAction.supported,
    available: trashAction.available,
    attempted: trashAction.attempted,
    succeeded: trashAction.succeeded,
    command: trashAction.command,
    warnings: trashAction.warnings ?? [],
    error: trashAction.error,
  };
}

function renderHostsAudit(hostsAudit) {
  console.log(`Hosts file audit: ${normalizeForDisplay(hostsAudit.path)}`);
  if (!hostsAudit.readable) {
    console.log(
      `${colorize(STATUS_ERROR_SYMBOL, 'red')} ${colorize(`Could not read hosts file: ${hostsAudit.error}`, 'red')}`,
    );
    console.log('');
    return;
  }

  if (hostsAudit.missingEntries.length === 0) {
    console.log(
      `${colorize(STATUS_OK_SYMBOL, 'green')} ${colorize(`All managed hosts entries are already present (${hostsAudit.presentEntries.length}/${hostsAudit.requiredEntries.length}).`, 'green')}`,
    );
    console.log('');
    return;
  }

  console.log(
    `${colorize(STATUS_WARN_SYMBOL, 'yellow')} ${colorize(`${hostsAudit.missingEntries.length} managed hosts entries are missing.`, 'yellow')}`,
  );
  if (hostsAudit.presentEntries.length > 0) {
    console.log(
      `  ${colorize(STATUS_OK_SYMBOL, 'green')} Present entries: ${hostsAudit.presentEntries.length}/${hostsAudit.requiredEntries.length}`,
    );
  }
  for (const entry of hostsAudit.missingEntries) {
    console.log(`  ${colorize(STATUS_WARN_SYMBOL, 'yellow')} Missing: ${entry.line}`);
  }
  console.log('');
}

function renderFirewallAudit(firewallAudit) {
  if (!firewallAudit) {
    return;
  }

  console.log(`Firewall enforcement status: ${firewallAudit.provider}`);
  if (!firewallAudit.available) {
    console.log(
      `${colorize(STATUS_WARN_SYMBOL, 'yellow')} ${colorize(firewallAudit.error ?? 'Firewall tooling is unavailable.', 'yellow')}`,
    );
    console.log('');
    return;
  }
  if (firewallAudit.error) {
    const color = firewallAudit.requiresElevation ? 'yellow' : 'red';
    const symbol = firewallAudit.requiresElevation ? STATUS_WARN_SYMBOL : STATUS_ERROR_SYMBOL;
    console.log(`${colorize(symbol, color)} ${colorize(firewallAudit.error, color)}`);
  }
  if (firewallAudit.active === false) {
    console.log(`${colorize(STATUS_WARN_SYMBOL, 'yellow')} ${colorize('Firewall is not currently active.', 'yellow')}`);
  }

  for (const warning of firewallAudit.warnings) {
    console.log(`${colorize(STATUS_WARN_SYMBOL, 'yellow')} ${colorize(warning, 'yellow')}`);
  }

  for (const ruleResult of firewallAudit.ruleResults) {
    if (ruleResult.status === 'present' || ruleResult.status === 'applied') {
      const verb = ruleResult.status === 'present' ? 'Present' : 'Applied';
      console.log(`  ${colorize(STATUS_OK_SYMBOL, 'green')} ${colorize(`${verb}: ${ruleResult.target}`, 'green')}`);
      continue;
    }
    if (ruleResult.status === 'missing') {
      console.log(`  ${colorize(STATUS_WARN_SYMBOL, 'yellow')} ${colorize(`Missing: ${ruleResult.target}`, 'yellow')}`);
      continue;
    }
    console.log(`  ${colorize(STATUS_ERROR_SYMBOL, 'red')} ${colorize(`Failed: ${ruleResult.target} (${ruleResult.detail})`, 'red')}`);
  }
  console.log('');
}
