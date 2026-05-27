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
    expect(getCheck(project, 'dependencies.minimatch')?.status).toBe('ok');
    expect(getCheck(project, 'dependencies.minimatch')?.actual).toBe('catalog:');
    expect(getCheck(project, 'dependencies.minimatch')?.message ?? '').toMatch(/delegates version governance/i);
    expect(getCheck(project, 'dependencies.minimatch')?.message ?? '').not.toMatch(/scanned/i);
    expect(getCheck(project, 'devDependencies.vitest')?.status).toBe('ok');
    expect(getCheck(project, 'devDependencies.vitest')?.actual).toBe('catalog:');
    expect(getCheck(project, 'devDependencies.vitest')?.message ?? '').toMatch(/delegates version governance/i);
    expect(getCheck(project, 'devDependencies.vitest')?.message ?? '').not.toMatch(/scanned/i);
  });

  it('rejects hardcoded dependency versions that are not migrated to the catalog', async () => {
    const rootPath = await createFixtureProject({
      packageJson: createPackageJson({
        dependencies: {
          minimatch: '10.2.5',
        },
      }),
      workspaceText: BASE_WORKSPACE_TEXT,
    });

    const project = runAudit(rootPath);
    const dependencyCheck = getCheck(project, 'dependencies.minimatch');

    expect(dependencyCheck?.status).toBe('invalid');
    expect(dependencyCheck?.actual).toBe('10.2.5');
    expect(dependencyCheck?.message ?? '').toMatch(/catalog/i);
    expect(dependencyCheck?.message ?? '').toMatch(/exact approved version/i);
  });

  it('rejects hardcoded devDependency versions that are not migrated to the catalog', async () => {
    const rootPath = await createFixtureProject({
      packageJson: createPackageJson({
        devDependencies: {
          vitest: '4.1.6',
        },
      }),
      workspaceText: BASE_WORKSPACE_TEXT,
    });

    const project = runAudit(rootPath);
    const dependencyCheck = getCheck(project, 'devDependencies.vitest');

    expect(dependencyCheck?.status).toBe('invalid');
    expect(dependencyCheck?.actual).toBe('4.1.6');
    expect(dependencyCheck?.message ?? '').toMatch(/catalog/i);
    expect(dependencyCheck?.message ?? '').toMatch(/exact approved version/i);
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
          }),
          workspaceText: BASE_WORKSPACE_TEXT,
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
    expect(rangeCheck?.message ?? '').toMatch(/explicit exact semver version only/i);
    expect(rangeCheck?.message ?? '').toMatch(/supply-chain/i);
    expect(getCheck(project, 'catalog exact versions')).toBeUndefined();
  });

  it('accepts named catalog sections when all entries use exact versions', async () => {
    const rootPath = await createFixtureProject({
      workspaceText: BASE_WORKSPACE_TEXT.replace(
        /^catalogMode: strict$/mu,
        'catalogs:\n  ui:\n    react: 19.2.0\n    vite: 8.0.13\ncatalogMode: strict',
      ),
    });

    const project = runAudit(rootPath);
    const exactVersionsCheck = getCheck(project, 'catalogs.ui exact versions');

    expect(exactVersionsCheck?.status).toBe('ok');
    expect(exactVersionsCheck?.actual).toBe('2 exact entries');
    expect(exactVersionsCheck?.message ?? '').toMatch(/pinned to explicit exact semver versions only/i);
  });

  it('rejects named catalog sections that use ranges instead of exact versions', async () => {
    const rootPath = await createFixtureProject({
      workspaceText: BASE_WORKSPACE_TEXT.replace(
        /^catalogMode: strict$/mu,
        'catalogs:\n  ui:\n    react: ^19.2.0\ncatalogMode: strict',
      ),
    });

    const project = runAudit(rootPath);
    const rangeCheck = getCheck(project, 'catalogs.ui.react');

    expect(rangeCheck?.status).toBe('invalid');
    expect(rangeCheck?.actual).toBe('^19.2.0');
    expect(rangeCheck?.message ?? '').toMatch(/supply-chain/i);
    expect(rangeCheck?.message ?? '').toMatch(/\^ or ~/i);
    expect(getCheck(project, 'catalogs.ui exact versions')).toBeUndefined();
  });

  it('audits workspace member package dependencies against the shared catalog', async () => {
    const rootPath = await createFixtureProject({
      workspaceText: buildMonorepoWorkspaceText(BASE_WORKSPACE_TEXT),
      workspaceMembers: [
        {
          relativePath: path.join('packages', 'fixture-app'),
          packageJson: createPackageJson({
            name: '@fixture/fixture-app',
            dependencies: {
              minimatch: '10.2.5',
            },
          }),
        },
      ],
    });

    const project = runAudit(rootPath);
    const memberCheck = project.checks.find((check) =>
      check.property === 'dependencies.minimatch'
      && check.file.endsWith(path.join('packages', 'fixture-app', 'package.json')),
    );

    expect(memberCheck?.status).toBe('invalid');
    expect(memberCheck?.actual).toBe('10.2.5');
    expect(memberCheck?.message ?? '').toMatch(/catalog/i);
  });

  it('keeps an empty project-local .npmrc as a gitignored auth-local surface', async () => {
    const rootPath = await createFixtureProject({
      npmrcText: '',
    });

    const project = runAudit(rootPath);

    expect(getCheck(project, '.npmrc gitignore')?.status).toBe('ok');
    expect(getCheck(project, '.npmrc')?.status).toBe('ok');
    expect(getCheck(project, '.npmrc')?.message ?? '').toMatch(/does not contain active config keys/i);
  });

  it('reports repo-policy settings in .npmrc as migrations to pnpm-workspace.yaml', async () => {
    const rootPath = await createFixtureProject({
      npmrcText: [
        'save-exact=true',
        'strict-ssl=true',
        'registry=https://registry.corp.example/npm/',
        '',
      ].join('\n'),
    });

    const project = runAudit(rootPath);

    expect(getCheck(project, 'save-exact')?.status).toBe('invalid');
    expect(getCheck(project, 'save-exact')?.message ?? '').toContain('pnpm-workspace.yaml#saveExact');
    expect(getCheck(project, 'strict-ssl')?.status).toBe('invalid');
    expect(getCheck(project, 'strict-ssl')?.message ?? '').toContain('pnpm-workspace.yaml#strictSsl');
    expect(getCheck(project, 'registry')?.status).toBe('invalid');
    expect(getCheck(project, 'registry')?.message ?? '').toContain('pnpm-workspace.yaml#registries.default');
  });

  it('reports legacy runtime settings in .npmrc as migrations to the package and workspace contracts', async () => {
    const rootPath = await createFixtureProject({
      npmrcText: 'use-node-version=26.2.0\n',
    });

    const project = runAudit(rootPath);
    const runtimeCheck = getCheck(project, 'use-node-version');

    expect(runtimeCheck?.status).toBe('invalid');
    expect(runtimeCheck?.message ?? '').toContain('package.json#devEngines.runtime.version');
    expect(runtimeCheck?.message ?? '').toContain('pnpm-workspace.yaml#nodeVersion');
  });

  it('limits auth.ini auditing to gitignore governance', async () => {
    const rootPath = await createFixtureProject({
      authIniText: '//registry.corp.example/:_authToken=${NPM_TOKEN}\n',
    });

    const project = runAudit(rootPath);
    const authIniPropertyCheck = project.checks.find((check) =>
      check.file === 'auth.ini'
      && check.property === '//registry.corp.example/:_authToken'
    );

    expect(getCheck(project, 'auth.ini gitignore')?.status).toBe('ok');
    expect(authIniPropertyCheck).toBeUndefined();
  });
});
