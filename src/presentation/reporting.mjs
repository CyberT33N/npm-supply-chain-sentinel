import path from 'node:path';
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

export function renderSummary(findings, options, blocklistPaths, scanStats, workersUsed, hostsAudit, firewallAudit, preflightPlan, ripgrepVersion, governanceAudit) {
  const { exactCount, heuristicCount, artifactCount, limitationCount, errorCount } = summarizeFindings(findings);

  console.log('');
  console.log('=== Supply-chain scan summary ===');
  console.log(`Mode: ${options.mode}`);
  console.log(`Roots scanned: ${options.roots.length}`);
  console.log(`Worker threads: ${workersUsed}`);
  if (options.mode === 'machine-wide' || options.includeTrash) {
    console.log(`Recycle bin scan: ${options.includeTrash ? 'included (explicit)' : 'excluded (default)'}`);
  }
  console.log(`Preflight mode: ${preflightPlan?.mode ?? 'fast'}`);
  console.log(`Progress model: ${preflightPlan?.progressModel ?? 'tasks'}`);
  if (preflightPlan?.splitSummary) {
    console.log(`Execution tasks: ${preflightPlan.splitSummary.executionTasks} (from ${preflightPlan.splitSummary.sourceTasks} source tasks, split heavy tasks=${preflightPlan.splitSummary.splitTaskCount})`);
  }
  console.log(`ripgrep runtime: ${ripgrepVersion}`);
  console.log(`Exact package/version hits: ${exactCount}`);
  console.log(`Heuristic package/manifest hits: ${heuristicCount}`);
  console.log(`Artifact/persistence hits: ${artifactCount}`);
  console.log(`Expected scan limitations: ${limitationCount}`);
  console.log(`Scanner errors: ${errorCount}`);
  console.log(`Directories visited: ${scanStats.directoriesVisited}`);
  console.log(`Candidate files inspected: ${scanStats.candidateFilesVisited}`);
  console.log(`node_modules directories inspected: ${scanStats.nodeModulesDirsVisited}`);
  console.log(
    `Filesystem access limitations: EACCES=${scanStats.traversalErrors.EACCES}, EPERM=${scanStats.traversalErrors.EPERM}, ENOENT=${scanStats.traversalErrors.ENOENT}, OTHER=${scanStats.traversalErrors.OTHER}`,
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

  if (limitationCount > 0) {
    renderScanLimitations(findings.limitations);
  }

  if (errorCount > 0) {
    console.log('Scanner errors:');
    for (const finding of findings.errors) {
      console.log(`- ${finding.message}`);
    }
    console.log('');
  }

  renderPnpmGovernanceAudit(governanceAudit);

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

export function toSerializableResult(findings, options, blocklistPaths, scanStats, workersUsed, hostsAudit, firewallAudit, preflightPlan, ripgrepVersion, governanceAudit) {
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
      pnpm: governanceAudit?.pnpmRuntime?.version ?? null,
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
    includeTrash: options.includeTrash,
    summary,
    scanStats,
    conclusions: dataset.executiveConclusions,
    findings: {
      exactHits: stripInternalKeys(findings.exactHits),
      heuristicHits: stripInternalKeys(findings.heuristicHits),
      artifactHits: stripInternalKeys(findings.artifactHits),
      limitations: stripInternalKeys(findings.limitations),
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
    governance: governanceAudit
      ? {
          nodeLtsFloor: governanceAudit.nodeLtsFloor,
          recommendedProperties: governanceAudit.recommendedProperties,
          pnpmRuntime: governanceAudit.pnpmRuntime,
          discovery: governanceAudit.discovery ?? null,
          summary: governanceAudit.summary,
          projects: governanceAudit.projects.map((project) => ({
            rootPath: normalizeForDisplay(project.rootPath),
            status: project.status,
            classification: project.classification,
            files: {
              packageJson: project.files.packageJson ? normalizeForDisplay(project.files.packageJson) : null,
              pnpmWorkspace: project.files.pnpmWorkspace ? normalizeForDisplay(project.files.pnpmWorkspace) : null,
              pnpmLockfile: project.files.pnpmLockfile ? normalizeForDisplay(project.files.pnpmLockfile) : null,
              npmrc: project.files.npmrc ? normalizeForDisplay(project.files.npmrc) : null,
              authIni: project.files.authIni ? normalizeForDisplay(project.files.authIni) : null,
              gitignore: project.files.gitignore ? normalizeForDisplay(project.files.gitignore) : null,
            },
            summary: project.summary,
            workspaceMembers: project.workspaceMembers.map((member) => ({
              rootPath: normalizeForDisplay(member.rootPath),
              packageName: member.packageJson?.value?.name ?? null,
            })),
            checks: project.checks,
          })),
        }
      : null,
  };
}

function renderPnpmGovernanceAudit(governanceAudit) {
  if (!governanceAudit) {
    return;
  }

  console.log('PNPM governance audit:');
  if (governanceAudit.discovery) {
    console.log(`- Discovery candidates: ${governanceAudit.discovery.candidateRootCount}`);
    console.log(`- Accepted managed roots: ${governanceAudit.discovery.acceptedRootCount}`);
    console.log(`- Suppressed unmanaged-path candidates: ${governanceAudit.discovery.suppressedUnmanagedPathCount}`);
    console.log(`- Suppressed missing-ownership candidates: ${governanceAudit.discovery.suppressedMissingOwnershipCount}`);
  }
  console.log(`- Managed projects discovered: ${governanceAudit.summary.projectCount}`);
  console.log(`- PNPM projects: ${governanceAudit.summary.pnpmProjectCount}`);
  console.log(`- Single-project PNPM repos: ${governanceAudit.summary.pnpmSingleProjectCount}`);
  console.log(`- Monorepos: ${governanceAudit.summary.pnpmMonorepoCount}`);
  console.log(`- Node projects without PNPM governance: ${governanceAudit.summary.nonPnpmNodeProjectCount}`);
  console.log(`- Fortress passes: ${governanceAudit.summary.passCount}`);
  console.log(`- Fortress failures: ${governanceAudit.summary.failCount}`);
  console.log(`- Governance warnings: ${governanceAudit.summary.warningCount}`);
  console.log('');

  if (governanceAudit.pnpmRuntime.warning) {
    console.log(
      `${colorize(STATUS_WARN_SYMBOL, 'yellow')} ${colorize(governanceAudit.pnpmRuntime.warning, 'yellow')}`,
    );
    if (!governanceAudit.pnpmRuntime.available) {
      console.log('  Recommended PNPM Fortress properties:');
      for (const property of governanceAudit.recommendedProperties) {
        console.log(`  - ${property}`);
      }
    }
    console.log('');
  }

  if (governanceAudit.projects.length === 0) {
    console.log('No managed Node/PNPM project roots were discovered under the scanned roots.');
    console.log('');
    return;
  }

  console.log('Managed project reports:');
  for (const project of governanceAudit.projects) {
    const { symbol, colorName, label } = statusPresentation(project.status);
    console.log(
      `${colorize(symbol, colorName)} ${colorize(`${project.displayPath} [${project.classification.kind}]`, colorName)}`,
    );
    if (project.status === 'passed') {
      const memberSuffix = project.workspaceMembers.length > 0
        ? ` workspace_members=${project.workspaceMembers.length}`
        : '';
      console.log(
        `  ${colorize('Fortress governance check passed.', 'green')} checks_ok=${project.summary.okCount}${memberSuffix}`,
      );
      continue;
    }

    console.log(
      `  Status: ${label} ok=${project.summary.okCount} warnings=${project.summary.warningCount} missing=${project.summary.missingCount} invalid=${project.summary.invalidCount}`,
    );
    for (const check of project.checks.filter((check) => check.status !== 'ok')) {
      const prefix = check.status === 'warning'
        ? colorize(STATUS_WARN_SYMBOL, 'yellow')
        : colorize(STATUS_ERROR_SYMBOL, 'red');
      const expectation = check.expected ? ` | expected=${check.expected}` : '';
      const actual = check.actual ? ` | actual=${check.actual}` : '';
      console.log(`  ${prefix} ${check.property}: ${check.message}${expectation}${actual}`);
    }
  }
  console.log('');
}

function statusPresentation(status) {
  if (status === 'passed') {
    return {
      symbol: STATUS_OK_SYMBOL,
      colorName: 'green',
      label: 'passed',
    };
  }
  if (status === 'failed') {
    return {
      symbol: STATUS_ERROR_SYMBOL,
      colorName: 'red',
      label: 'failed',
    };
  }
  return {
    symbol: STATUS_WARN_SYMBOL,
    colorName: 'yellow',
    label: 'warning',
  };
}

function renderScanLimitations(limitations) {
  console.log('Excluded / unreadable technical areas (not treated as scanner errors):');

  const directFindings = [];
  const groupedFindings = new Map();

  for (const finding of limitations) {
    if (!finding?.path || !['unreadable-directory', 'unreadable-file'].includes(finding.type)) {
      directFindings.push(finding);
      continue;
    }

    const parentPath = normalizeForDisplay(path.dirname(finding.path));
    const key = `${finding.type}:${parentPath}`;
    const existing = groupedFindings.get(key) ?? {
      type: finding.type,
      parentPath,
      count: 0,
    };
    existing.count += 1;
    groupedFindings.set(key, existing);
  }

  for (const finding of directFindings) {
    console.log(`- ${finding.message}`);
  }

  for (const group of [...groupedFindings.values()].sort((left, right) => {
    if (right.count !== left.count) {
      return right.count - left.count;
    }
    return left.parentPath.localeCompare(right.parentPath);
  })) {
    const noun = group.type === 'unreadable-file'
      ? group.count === 1 ? 'unreadable file' : 'unreadable files'
      : group.count === 1 ? 'unreadable directory' : 'unreadable directories';
    console.log(`- ${group.count} ${noun} under ${group.parentPath}: access was denied by the operating system (system-managed or permission-restricted area).`);
  }

  console.log('');
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
