import process from 'node:process';

import { describe, expect, it } from 'vitest';

import { auditPnpmGovernance } from '../../../../src/application/pnpm-governance';
import {
  ANSI_COLORS,
  STATUS_ERROR_SYMBOL,
  STATUS_OK_SYMBOL,
} from '../../../../src/domain/policy';
import { renderPnpmGovernanceAudit } from '../../../../src/presentation/pnpm-governance-reporting';
import {
  BASE_WORKSPACE_TEXT,
  PNPM_RUNTIME,
  captureConsoleOutput,
  createFixtureProject,
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

    expect(successfulLines.length).toBe(successfulProperties.length);
    expect(failedLines.length).toBe(failedProperties.length);
    expect(successfulLines.every((line) => line.startsWith(`    ${STATUS_OK_SYMBOL} `))).toBe(true);
    expect(failedLines.every((line) => line.startsWith(`    ${STATUS_ERROR_SYMBOL} `))).toBe(true);
    expect(renderedSuccessfulProperties).toEqual(successfulProperties);
    expect(renderedFailedProperties).toEqual(failedProperties);
    expect(output).toContain(
      'dependencies.minimatch: minimatch was scanned and resolves through the shared catalog. | expected=catalog: reference | actual=catalog:',
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

    expect(output).toContain('  Successful checks:');
    expect(output).toContain(
      'catalogs.ui exact versions: catalogs.ui entries are present and pinned to explicit exact semver versions only. | expected=exact semver only | actual=2 exact entries',
    );
  });
});
