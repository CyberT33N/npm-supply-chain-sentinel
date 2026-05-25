import process from 'node:process';

import {
  ANSI_COLORS,
  STATUS_ERROR_SYMBOL,
  STATUS_OK_SYMBOL,
  STATUS_WARN_SYMBOL,
} from '../domain/policy';
import { normalizeForDisplay } from '../infrastructure/fs-utils';

export function renderPnpmGovernanceAudit(governanceAudit) {
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
  console.log(`- Standalone single-project PNPM roots: ${governanceAudit.summary.standalonePnpmSingleProjectCount}`);
  console.log(`- Monorepo roots: ${governanceAudit.summary.rootPnpmMonorepoCount}`);
  console.log(`- Nested PNPM domains: ${governanceAudit.summary.nestedPnpmDomainCount}`);
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
      `${colorize(symbol, colorName)} ${colorize(formatProjectHeading(project), colorName)}`,
    );
    if (project.status === 'passed') {
      const memberSuffix = project.workspaceMembers.length > 0
        ? ` workspace_members=${project.workspaceMembers.length}`
        : '';
      const governanceHighlights = summarizePassHighlights(project);
      const highlightSuffix = governanceHighlights.length > 0
        ? ` ${governanceHighlights.join(' ')}`
        : '';
      console.log(
        `  ${colorize('Fortress governance check passed.', 'green')} checks_ok=${project.summary.okCount}${memberSuffix}${highlightSuffix}`,
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

export function serializeGovernanceAudit(governanceAudit) {
  if (!governanceAudit) {
    return null;
  }

  return {
    nodeLtsFloor: governanceAudit.nodeLtsFloor,
    recommendedProperties: governanceAudit.recommendedProperties,
    pnpmRuntime: governanceAudit.pnpmRuntime,
    discovery: governanceAudit.discovery ?? null,
    summary: governanceAudit.summary,
    projects: governanceAudit.projects.map((project) => ({
      rootPath: normalizeForDisplay(project.rootPath),
      displayPath: project.displayPath,
      status: project.status,
      classification: project.classification,
      topology: serializeProjectTopology(project.topology),
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
  };
}

export function toSerializablePnpmGovernanceResult(governanceAudit, options = {}) {
  return {
    scanner: 'pnpm-governance-audit',
    generatedAt: new Date().toISOString(),
    mode: options.mode ?? 'project',
    platform: {
      os: process.platform,
      arch: process.arch,
      node: process.version,
    },
    runtimeDependencies: {
      pnpm: governanceAudit?.pnpmRuntime?.version ?? null,
    },
    roots: (options.roots ?? []).map((rootPath) => normalizeForDisplay(rootPath)),
    includeTrash: Boolean(options.includeTrash),
    governance: serializeGovernanceAudit(governanceAudit),
  };
}

function colorize(text, colorName) {
  if (!process.stdout.isTTY) {
    return text;
  }
  const color = ANSI_COLORS[colorName];
  if (!color) {
    return text;
  }
  return `${color}${text}${ANSI_COLORS.reset}`;
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

function summarizePassHighlights(project) {
  const highlights = [];
  if (hasOkCheck(project, 'saveExact')) {
    highlights.push('save_exact=true');
  }
  if (hasOkCheck(project, 'catalog exact versions')) {
    highlights.push('catalog_versions=explicit');
  }
  return highlights;
}

function hasOkCheck(project, property) {
  return project.checks.some((check) => check.status === 'ok' && check.property === property);
}

function formatProjectHeading(project) {
  const lineageDisplayPaths = project.topology?.lineageDisplayPaths ?? [project.displayPath];
  const pathLabel = lineageDisplayPaths.join(' -> ');
  const kindLabel = project.topology?.role === 'nested-domain'
    ? `${project.classification.kind} domain`
    : project.classification.kind;
  return `${pathLabel} [${kindLabel}]`;
}

function serializeProjectTopology(topology) {
  if (!topology) {
    return null;
  }
  return {
    role: topology.role,
    parentRootPath: topology.parentRootPath ? normalizeForDisplay(topology.parentRootPath) : null,
    parentDisplayPath: topology.parentDisplayPath ?? null,
    lineageRootPaths: (topology.lineageRootPaths ?? []).map((rootPath) => normalizeForDisplay(rootPath)),
    lineageDisplayPaths: topology.lineageDisplayPaths ?? [],
  };
}
