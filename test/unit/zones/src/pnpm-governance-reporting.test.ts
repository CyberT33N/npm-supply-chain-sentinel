import process from 'node:process';

import { describe, expect, it } from 'vitest';

import { auditPnpmGovernance } from '../../../../src/application/pnpm-governance';
import {
  ANSI_COLORS,
  STATUS_ERROR_SYMBOL,
  STATUS_OK_SYMBOL,
  STATUS_WARN_SYMBOL,
} from '../../../../src/domain/policy';
import {
  renderPnpmGovernanceAudit,
  serializeGovernanceAudit,
  toSerializablePnpmGovernanceResult,
} from '../../../../src/presentation/pnpm-governance-reporting';
import {
  BASE_WORKSPACE_TEXT,
  PNPM_RUNTIME,
  buildMonorepoWorkspaceText,
  captureConsoleOutput,
  createFixtureProject,
  createPackageJson,
} from '@test/shared/utils/pnpm-governance-fixtures';

function withStdoutTty<T>(value: boolean, action: () => T): T {
  const isTTYDescriptor = Object.getOwnPropertyDescriptor(process.stdout, 'isTTY');
  Object.defineProperty(process.stdout, 'isTTY', {
    configurable: true,
    value,
    writable: true,
  });

  try {
    return action();
  } finally {
    if (isTTYDescriptor) {
      Object.defineProperty(process.stdout, 'isTTY', isTTYDescriptor);
    } else {
      Reflect.deleteProperty(process.stdout, 'isTTY');
    }
  }
}

describe('renderPnpmGovernanceAudit', () => {
  it('renders successful checks before failed checks with headings, spacing, and alphabetical sorting', async () => {
    const rootPath = await createFixtureProject({
      workspaceText: BASE_WORKSPACE_TEXT.replace(/^saveExact: true\r?\n/mu, ''),
    });

    const audit = auditPnpmGovernance([rootPath], {}, PNPM_RUNTIME);
    const [project] = audit.projects;
    if (!project) {
      throw new Error('Expected an audited project to be present.');
    }

    const output = captureConsoleOutput(() => {
      renderPnpmGovernanceAudit(audit);
    });
    const lines = output.split('\n');
    const successfulHeadingIndex = lines.indexOf('  Successful checks:');
    const failedHeadingIndex = lines.indexOf('  Failed checks:');

    expect(successfulHeadingIndex).toBeGreaterThan(-1);
    expect(failedHeadingIndex).toBeGreaterThan(successfulHeadingIndex);
    expect(lines[failedHeadingIndex - 1]).toBe('');

    const successfulLines = lines
      .slice(successfulHeadingIndex + 1, failedHeadingIndex - 1)
      .filter((line) => line.length > 0);
    const failedLines = lines.slice(failedHeadingIndex + 1).filter((line) => line.length > 0);

    const successfulProperties = project.checks
      .filter((check) => check.status === 'ok')
      .map((check) => check.property)
      .toSorted((left, right) => left.localeCompare(right));
    const failedProperties = project.checks
      .filter((check) => check.status !== 'ok')
      .map((check) => check.property)
      .toSorted((left, right) => left.localeCompare(right));
    const renderedSuccessfulProperties = successfulLines.map((line) => {
      const match = /^\s+✓ ([^:]+):/u.exec(line);
      return match?.[1] ?? null;
    });
    const renderedFailedProperties = failedLines.map((line) => {
      const match = /^\s+✗ ([^:]+):/u.exec(line);
      return match?.[1] ?? null;
    });

    expect(successfulLines.length).toBeLessThan(successfulProperties.length);
    expect(failedLines.length).toBe(failedProperties.length);
    expect(successfulLines.every((line) => line.startsWith(`    ${STATUS_OK_SYMBOL} `))).toBe(true);
    expect(failedLines.every((line) => line.startsWith(`    ${STATUS_ERROR_SYMBOL} `))).toBe(true);
    expect(renderedSuccessfulProperties).toEqual(
      [...renderedSuccessfulProperties].toSorted((left, right) =>
        String(left).localeCompare(String(right)),
      ),
    );
    expect(renderedFailedProperties).toEqual(failedProperties);
    expect(output.match(/^\s+✓ dependencies:/gmu) ?? []).toHaveLength(1);
    expect(output.match(/^\s+✓ devDependencies:/gmu) ?? []).toHaveLength(1);
    expect(output).toMatch(/^\s+✓ dependencies: .*minimatch.*$/mu);
    expect(output).toMatch(/^\s+✓ devDependencies: .*vitest.*$/mu);
    expect(output).toContain(
      'delegate version governance to the shared PNPM catalog via catalog: specifiers.',
    );
    expect(output).not.toContain('dependencies.minimatch: minimatch was scanned and resolves through the shared catalog.');
    expect(output).not.toContain('was scanned');
    expect(output).toContain(
      'devEngines.runtime.version = nodeVersion: devEngines.runtime.version and pnpm-workspace.yaml#nodeVersion are aligned on 26.2.0. | expected=same exact semver in package.json and pnpm-workspace.yaml | actual=26.2.0',
    );
    expect(output).toContain(
      'engines.node: engines.node is intentionally unset to avoid a third root-level Node.js version authority and version drift. | expected=unset | actual=unset',
    );
  });

  it('colors successful sections green and failed sections red on TTY output', async () => {
    const rootPath = await createFixtureProject({
      workspaceText: BASE_WORKSPACE_TEXT.replace(/^saveExact: true\r?\n/mu, ''),
    });

    const audit = auditPnpmGovernance([rootPath], {}, PNPM_RUNTIME);
    const output = withStdoutTty(true, () => captureConsoleOutput(() => {
      renderPnpmGovernanceAudit(audit);
    }));

    expect(output).toContain(`  ${ANSI_COLORS.green}Successful checks:${ANSI_COLORS.reset}`);
    expect(output).toContain(`  ${ANSI_COLORS.red}Failed checks:${ANSI_COLORS.reset}`);
    expect(output).toContain(
      `    ${ANSI_COLORS.green}${STATUS_OK_SYMBOL}${ANSI_COLORS.reset} ${ANSI_COLORS.green}registries.default:`,
    );
    expect(output).toContain(
      `    ${ANSI_COLORS.red}${STATUS_ERROR_SYMBOL}${ANSI_COLORS.reset} ${ANSI_COLORS.red}saveExact:`,
    );
  });

  it('renders monorepo workspace packages as nested package reports and keeps catalog checks aggregated per package', async () => {
    const rootPath = await createFixtureProject({
      workspaceText: buildMonorepoWorkspaceText(
        BASE_WORKSPACE_TEXT.replace(/^saveExact: true\r?\n/mu, ''),
      ),
      workspaceMembers: [
        {
          relativePath: 'packages/fixture-a',
          packageJson: createPackageJson({
            name: '@fixture/fixture-a',
            devDependencies: {
              'ts-node': 'catalog:',
              tsx: 'catalog:',
            },
          }),
        },
        {
          relativePath: 'packages/fixture-b',
          packageJson: createPackageJson({
            name: '@fixture/fixture-b',
            devDependencies: {
              'ts-node': 'catalog:',
              tsx: 'catalog:',
            },
          }),
        },
        {
          relativePath: 'packages/fixture-c',
          packageJson: createPackageJson({
            name: '@fixture/fixture-c',
            devDependencies: {
              'ts-node': 'catalog:',
              tsx: 'catalog:',
            },
          }),
        },
      ],
    });

    const audit = auditPnpmGovernance([rootPath], {}, PNPM_RUNTIME);
    const output = captureConsoleOutput(() => {
      renderPnpmGovernanceAudit(audit);
    });

    expect(output).toContain('- Workspace packages discovered: 3');
    expect(output).toContain('[pnpm-monorepo root]');
    expect(output).toContain('workspace_packages=3');
    expect(output).toContain('Workspace packages:');
    expect(output).toMatch(/packages[\\/]+fixture-a \[workspace-package\]/u);
    expect(output).toMatch(/packages[\\/]+fixture-b \[workspace-package\]/u);
    expect(output).toMatch(/packages[\\/]+fixture-c \[workspace-package\]/u);
    const workspaceDividers = output.match(/^\s{4}-{20,}$/gmu) ?? [];
    expect(workspaceDividers).toHaveLength(2);
    const memberDevDependencyLines = output.match(/^\s+✓ devDependencies: .*ts-node.*tsx.*$/gmu) ?? [];
    expect(memberDevDependencyLines).toHaveLength(3);
    expect(output).not.toMatch(/^\s+✓ devDependencies\.ts-node:/gmu);
    expect(output).not.toMatch(/^\s+✓ devDependencies\.tsx:/gmu);
  });

  it('renders failing fortress exception surfaces in yellow while the audit remains in the failed red area', async () => {
    const rootPath = await createFixtureProject({
      workspaceText: BASE_WORKSPACE_TEXT.replace(
        /^trustPolicyExclude: \[\]$/mu,
        'trustPolicyExclude:\n  - legacy-mirror',
      ),
    });

    const audit = auditPnpmGovernance([rootPath], {}, PNPM_RUNTIME);
    const [project] = audit.projects;
    if (!project) {
      throw new Error('Expected an audited project to be present.');
    }

    expect(project.status).toBe('failed');

    const output = withStdoutTty(true, () => captureConsoleOutput(() => {
      renderPnpmGovernanceAudit(audit);
    }));

    expect(output).toContain(`  ${ANSI_COLORS.red}Failed checks:${ANSI_COLORS.reset}`);
    expect(output).toContain(
      `    ${ANSI_COLORS.yellow}${STATUS_WARN_SYMBOL}${ANSI_COLORS.reset} ${ANSI_COLORS.yellow}trustPolicyExclude:`,
    );
  });

  it('reports named catalog sections with exact versions in the successful green area', async () => {
    const rootPath = await createFixtureProject({
      workspaceText: BASE_WORKSPACE_TEXT.replace(
        /^catalogMode: strict$/mu,
        'catalogs:\n  ui:\n    react: 19.2.0\n    vite: 8.0.13\ncatalogMode: strict',
      ),
    });

    const audit = auditPnpmGovernance([rootPath], {}, PNPM_RUNTIME);
    const output = captureConsoleOutput(() => {
      renderPnpmGovernanceAudit(audit);
    });

    expect(output).toContain(
      'Fortress governance check passed.',
    );
    expect(output).toContain(
      'catalog_versions=exact',
    );
  });

  it('serializes workspace packages as first-class nested JSON structures', async () => {
    const rootPath = await createFixtureProject({
      workspaceText: buildMonorepoWorkspaceText(
        BASE_WORKSPACE_TEXT.replace(/^saveExact: true\r?\n/mu, ''),
      ),
      workspaceMembers: [
        {
          relativePath: 'packages/fixture-a',
          packageJson: createPackageJson({
            name: '@fixture/fixture-a',
            devDependencies: {
              'ts-node': 'catalog:',
              tsx: 'catalog:',
            },
          }),
        },
        {
          relativePath: 'packages/fixture-b',
          packageJson: createPackageJson({
            name: '@fixture/fixture-b',
            devDependencies: {
              'ts-node': 'catalog:',
              tsx: 'catalog:',
            },
          }),
        },
      ],
    });

    const audit = auditPnpmGovernance([rootPath], {}, PNPM_RUNTIME);
    const serialized = serializeGovernanceAudit(audit);
    const payload = toSerializablePnpmGovernanceResult(audit, {
      mode: 'project',
      roots: [rootPath],
    });
    const project = serialized?.projects[0];

    expect(serialized?.summary.workspacePackageCount).toBe(2);
    expect(payload.governance?.summary.workspacePackageCount).toBe(2);
    expect(project?.summary.workspacePackageCount).toBe(2);
    expect(project?.rootChecks.some((check) => check.property === 'saveExact')).toBe(true);
    expect(project?.workspacePackages).toHaveLength(2);
    expect(project?.workspacePackages[0]?.displayPath).toMatch(/packages[\\/]+fixture-a|packages[\\/]+fixture-b/u);
    expect(project?.workspacePackages.every((workspacePackage) => workspacePackage.status === 'passed')).toBe(true);
    expect(project?.workspacePackages[0]?.checks.some((check) => check.property === 'devDependencies.ts-node')).toBe(true);
    expect(project?.workspacePackages[0]?.checks.some((check) => check.property === 'saveExact')).toBe(false);
  });
});
