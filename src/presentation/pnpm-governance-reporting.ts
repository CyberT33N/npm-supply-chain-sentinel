import process from 'node:process';

import type {
  GovernanceAudit,
  GovernanceCheck,
  GovernanceProjectReport,
  GovernanceProjectTopology,
} from '../application/pnpm-governance';
import {
  ANSI_COLORS,
  STATUS_ERROR_SYMBOL,
  STATUS_OK_SYMBOL,
  STATUS_WARN_SYMBOL,
} from '../domain/policy';
import { normalizeForDisplay } from '../infrastructure/fs-utils';

interface StandaloneGovernanceOptions {
  mode?: string;
  roots?: string[];
  includeTrash?: boolean;
}

type CatalogDependencySection = 'dependencies' | 'devDependencies';

type RenderableGovernanceCheck = Pick<
  GovernanceCheck,
  'actual' | 'expected' | 'file' | 'message' | 'presentationTone' | 'property'
>;

function getPackageName(value: unknown): string | null {
  if (typeof value !== 'object' || value === null || !('name' in value)) {
    return null;
  }
  const packageName = value['name'];
  return typeof packageName === 'string' ? packageName : null;
}

export function renderPnpmGovernanceAudit(governanceAudit: GovernanceAudit | null | undefined): void {
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
    const okChecks = project.checks.filter((check) => check.status === 'ok');
    const failedChecks = project.checks.filter((check) => check.status !== 'ok');
    renderCheckSection('Successful checks:', okChecks, 'green', STATUS_OK_SYMBOL);
    console.log('');
    renderCheckSection('Failed checks:', failedChecks, 'red', STATUS_ERROR_SYMBOL);
  }
  console.log('');
}

export function serializeGovernanceAudit(governanceAudit: GovernanceAudit | null | undefined) {
  if (!governanceAudit) {
    return null;
  }

  return {
    nodeRuntimeContract: governanceAudit.nodeRuntimeContract,
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
        packageName: getPackageName(member.packageJson.value),
      })),
      checks: project.checks,
    })),
  };
}

export function toSerializablePnpmGovernanceResult(
  governanceAudit: GovernanceAudit | null | undefined,
  options: StandaloneGovernanceOptions = {},
) {
  const roots = Array.isArray(options.roots) ? options.roots : [];
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
    roots: roots.map((rootPath) => normalizeForDisplay(rootPath)),
    includeTrash: Boolean(options.includeTrash),
    governance: serializeGovernanceAudit(governanceAudit),
  };
}

function colorize(text: string, colorName: keyof typeof ANSI_COLORS): string {
  if (!process.stdout.isTTY) {
    return text;
  }
  const color = ANSI_COLORS[colorName];
  if (!color) {
    return text;
  }
  return `${color}${text}${ANSI_COLORS.reset}`;
}

function statusPresentation(status: GovernanceProjectReport['status']): {
  symbol: string;
  colorName: keyof typeof ANSI_COLORS;
  label: GovernanceProjectReport['status'];
} {
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

function sortChecks<T extends Pick<GovernanceCheck, 'file' | 'message' | 'property'>>(
  checks: readonly T[],
): T[] {
  return [...checks].sort((left, right) => {
    const propertyComparison = left.property.localeCompare(right.property);
    if (propertyComparison !== 0) {
      return propertyComparison;
    }
    const fileComparison = left.file.localeCompare(right.file);
    if (fileComparison !== 0) {
      return fileComparison;
    }
    return left.message.localeCompare(right.message);
  });
}

function renderCheckSection(
  title: string,
  checks: readonly GovernanceCheck[],
  colorName: 'green' | 'red',
  symbol: string,
): void {
  console.log(`  ${colorize(title, colorName)}`);
  for (const check of sortChecks(collapseChecksForDisplay(checks))) {
    const presentation = checkPresentation(check, colorName, symbol);
    const expectation = check.expected ? ` | expected=${check.expected}` : '';
    const actual = check.actual ? ` | actual=${check.actual}` : '';
    const details = `${check.property}: ${check.message}${expectation}${actual}`;
    console.log(
      `    ${colorize(presentation.symbol, presentation.colorName)} ${colorize(details, presentation.colorName)}`,
    );
  }
}

function checkPresentation(
  check: Pick<GovernanceCheck, 'presentationTone'>,
  fallbackColorName: 'green' | 'red',
  fallbackSymbol: string,
): {
  colorName: keyof typeof ANSI_COLORS;
  symbol: string;
} {
  if (check.presentationTone === 'warning') {
    return {
      colorName: 'yellow',
      symbol: STATUS_WARN_SYMBOL,
    };
  }
  return {
    colorName: fallbackColorName,
    symbol: fallbackSymbol,
  };
}

function collapseChecksForDisplay(
  checks: readonly GovernanceCheck[],
): RenderableGovernanceCheck[] {
  const retainedChecks: RenderableGovernanceCheck[] = [];
  const aggregatedCatalogChecks = new Map<CatalogDependencySection, Set<string>>();

  for (const check of checks) {
    const catalogResolution = parseCatalogResolutionCheck(check);
    if (!catalogResolution) {
      retainedChecks.push(check);
      continue;
    }

    const packageNames = aggregatedCatalogChecks.get(catalogResolution.section) ?? new Set<string>();
    packageNames.add(catalogResolution.dependencyName);
    aggregatedCatalogChecks.set(catalogResolution.section, packageNames);
  }

  for (const section of ['dependencies', 'devDependencies'] as const) {
    const packageNames = aggregatedCatalogChecks.get(section);
    if (!packageNames || packageNames.size === 0) {
      continue;
    }
    retainedChecks.push(buildAggregatedCatalogCheck(section, packageNames));
  }

  return retainedChecks;
}

function parseCatalogResolutionCheck(
  check: GovernanceCheck,
): { dependencyName: string; section: CatalogDependencySection } | null {
  if (check.expected !== 'catalog: reference') {
    return null;
  }
  if (typeof check.actual !== 'string' || !check.actual.startsWith('catalog:')) {
    return null;
  }

  const match = /^(dependencies|devDependencies)\.(.+)$/u.exec(check.property);
  if (!match) {
    return null;
  }

  const [, section, dependencyName] = match;
  if (
    (section !== 'dependencies' && section !== 'devDependencies')
    || typeof dependencyName !== 'string'
    || dependencyName.length === 0
  ) {
    return null;
  }

  return {
    dependencyName,
    section,
  };
}

function buildAggregatedCatalogCheck(
  section: CatalogDependencySection,
  packageNames: ReadonlySet<string>,
): RenderableGovernanceCheck {
  const sortedPackageNames = [...packageNames].sort((left, right) => left.localeCompare(right));
  const verb = sortedPackageNames.length === 1 ? 'delegates' : 'delegate';

  return {
    file: section,
    property: section,
    presentationTone: 'default',
    expected: null,
    actual: null,
    message: `${sortedPackageNames.join(', ')} ${verb} version governance to the shared PNPM catalog via catalog: specifiers.`,
  };
}

function summarizePassHighlights(project: GovernanceProjectReport): string[] {
  const highlights: string[] = [];
  if (hasOkCheck(project, 'saveExact')) {
    highlights.push('save_exact=true');
  }
  if (hasAnyCatalogExactVersionCheck(project)) {
    highlights.push('catalog_versions=exact');
  }
  return highlights;
}

function hasOkCheck(project: GovernanceProjectReport, property: string): boolean {
  return project.checks.some((check) => check.status === 'ok' && check.property === property);
}

function hasAnyCatalogExactVersionCheck(project: GovernanceProjectReport): boolean {
  return project.checks.some((check) =>
    check.status === 'ok'
    && (
      check.property === 'catalog exact versions'
      || (check.property.startsWith('catalogs.') && check.property.endsWith(' exact versions'))
    ),
  );
}

function formatProjectHeading(project: GovernanceProjectReport): string {
  const lineageDisplayPaths = project.topology?.lineageDisplayPaths ?? [project.displayPath];
  const pathLabel = lineageDisplayPaths.join(' -> ');
  const kindLabel = project.topology?.role === 'nested-domain'
    ? `${project.classification.kind} domain`
    : project.classification.kind;
  return `${pathLabel} [${kindLabel}]`;
}

function serializeProjectTopology(topology: GovernanceProjectTopology | null | undefined) {
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
