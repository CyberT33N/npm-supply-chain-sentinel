import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { auditPnpmGovernance } from '../../../../../src/application/pnpm-governance';
import {
  BASE_WORKSPACE_TEXT,
  PNPM_RUNTIME,
  buildMonorepoWorkspaceText,
  createFixtureProject,
  createPackageJson,
  getCheck,
  runAudit,
} from '@test/shared/utils/pnpm-governance-fixtures';

describe('auditPnpmGovernance', () => {
  it('accepts saveExact and exact catalog versions for a single-project repository', async () => {
    const rootPath = await createFixtureProject({
      workspaceText: BASE_WORKSPACE_TEXT,
    });

    const project = runAudit(rootPath);

    expect(project.classification.kind).toBe('pnpm-single-project');
    expect(getCheck(project, 'saveExact')?.status).toBe('ok');
    expect(getCheck(project, 'catalog exact versions')?.status).toBe('ok');
  });

  it('flags a missing saveExact policy for a single-project repository', async () => {
    const rootPath = await createFixtureProject({
      workspaceText: BASE_WORKSPACE_TEXT.replace(/^saveExact: true\r?\n/mu, ''),
    });

    const project = runAudit(rootPath);

    expect(project.classification.kind).toBe('pnpm-single-project');
    expect(getCheck(project, 'saveExact')?.status).toBe('missing');
  });

  it('accepts saveExact as a required root policy for monorepos', async () => {
    const rootPath = await createFixtureProject({
      workspaceText: buildMonorepoWorkspaceText(BASE_WORKSPACE_TEXT),
      workspaceMembers: [
        {
          relativePath: path.join('packages', 'fixture-app'),
          packageJson: {
            name: '@fixture/fixture-app',
            version: '1.0.0',
            private: true,
            type: 'module',
          },
        },
      ],
    });

    const project = runAudit(rootPath);

    expect(project.classification.kind).toBe('pnpm-monorepo');
    expect(getCheck(project, 'saveExact')?.status).toBe('ok');
  });

  it('audits nested pnpm workspace domains and links them to their parent monorepo', async () => {
    const rootPath = await createFixtureProject({
      workspaceText: buildMonorepoWorkspaceText(BASE_WORKSPACE_TEXT, {
        workspacePatterns: ['domains/*'],
      }),
      workspaceMembers: [
        {
          relativePath: path.join('domains', 'billing-domain'),
          packageJson: createPackageJson({
            name: '@fixture/billing-domain',
            engines: {
              node: '>=26.2.0',
            },
            devEngines: {
              runtime: {
                name: 'node',
                version: '>=26.2.0',
                onFail: 'error',
              },
              packageManager: {
                name: 'pnpm',
                version: '11.2.2',
                onFail: 'error',
              },
            },
          }),
          workspaceText: BASE_WORKSPACE_TEXT.replace(
            /^nodeVersion: .+$/mu,
            'nodeVersion: 26.2.0',
          ),
          lockfileText: 'lockfileVersion: "9.0"\n',
        },
      ],
    });

    const audit = auditPnpmGovernance([rootPath], {}, PNPM_RUNTIME);

    expect(audit.summary.projectCount).toBe(2);
    expect(audit.summary.rootPnpmMonorepoCount).toBe(1);
    expect(audit.summary.standalonePnpmSingleProjectCount).toBe(0);
    expect(audit.summary.nestedPnpmDomainCount).toBe(1);

    const rootProject = audit.projects.find((project) => project.rootPath === rootPath);
    const nestedDomain = audit.projects.find(
      (project) => project.rootPath === path.join(rootPath, 'domains', 'billing-domain'),
    );

    if (!rootProject || !nestedDomain) {
      throw new Error('Expected both the root monorepo and nested domain audit results.');
    }

    expect(nestedDomain.classification.kind).toBe('pnpm-single-project');
    expect(nestedDomain.topology?.role).toBe('nested-domain');
    expect(nestedDomain.topology?.parentRootPath).toBe(rootProject.rootPath);
    expect(nestedDomain.topology?.lineageRootPaths).toEqual([
      rootProject.rootPath,
      nestedDomain.rootPath,
    ]);
  });

  it('keeps ordinary workspace packages without their own workspace file out of nested-domain scanning', async () => {
    const rootPath = await createFixtureProject({
      workspaceText: buildMonorepoWorkspaceText(BASE_WORKSPACE_TEXT, {
        workspacePatterns: ['domains/*'],
      }),
      workspaceMembers: [
        {
          relativePath: path.join('domains', 'shared-lib'),
          packageJson: createPackageJson({
            name: '@fixture/shared-lib',
          }),
        },
      ],
    });

    const audit = auditPnpmGovernance([rootPath], {}, PNPM_RUNTIME);

    expect(audit.summary.projectCount).toBe(1);
    expect(audit.summary.nestedPnpmDomainCount).toBe(0);
    expect(audit.projects.map((project) => project.rootPath)).toEqual([rootPath]);
  });

  it('rejects catalog entries that use non-exact version ranges', async () => {
    const rootPath = await createFixtureProject({
      workspaceText: BASE_WORKSPACE_TEXT.replace(
        /^catalog:\r?\n/mu,
        'catalog:\n  range-only-fixture: ^1.2.3\n',
      ),
    });

    const project = runAudit(rootPath);
    const rangeCheck = getCheck(project, 'catalog.range-only-fixture');

    expect(rangeCheck?.status).toBe('invalid');
    expect(rangeCheck?.message ?? '').toMatch(/explicit exact versions/i);
    expect(getCheck(project, 'catalog exact versions')).toBeUndefined();
  });
});
