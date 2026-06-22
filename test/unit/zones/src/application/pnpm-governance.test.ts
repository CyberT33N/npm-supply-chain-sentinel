import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { auditPnpmGovernance } from '../../../../../src/application/pnpm-governance';
import {
  BASE_WORKSPACE_TEXT,
  PNPM_RUNTIME,
  buildMonorepoWorkspaceText,
  createGovernanceToolchainPolicy,
  createFixtureProject,
  createPackageJson,
  createPnpmRuntime,
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
    expect(rootProject.checks.find((check) =>
      check.file === path.join(rootPath, 'domains', 'billing-domain', 'package.json')
      && check.property === 'packageManager'
    )).toBeUndefined();
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

  it('accepts exact trustPolicyExclude entries while surfacing the response-order checklist as a warning', async () => {
    const rootPath = await createFixtureProject({
      workspaceText: BASE_WORKSPACE_TEXT.replace(
        /^trustPolicyExclude: \[\]$/mu,
        'trustPolicyExclude:\n  - "chokidar@4.0.3"',
      ),
    });

    const project = runAudit(rootPath);
    const exactVersionsCheck = getCheck(project, 'trustPolicyExclude exact versions');
    const responseOrderWarning = getCheck(project, 'trustPolicyExclude response order');

    expect(project.status).toBe('failed');
    expect(project.summary.warningCount).toBeGreaterThan(0);
    expect(getCheck(project, 'trustPolicyExclude')?.status).toBe('invalid');
    expect(exactVersionsCheck?.status).toBe('ok');
    expect(exactVersionsCheck?.actual).toBe('1 exact exception');
    expect(exactVersionsCheck?.message ?? '').toMatch(/one exact package version each/i);
    expect(responseOrderWarning?.status).toBe('warning');
    expect(responseOrderWarning?.message ?? '').toMatch(/ERR_PNPM_TRUST_DOWNGRADE/i);
    expect(responseOrderWarning?.expected).toMatch(/patch-only/i);
    expect(responseOrderWarning?.message ?? '').toMatch(/same major\/minor line/i);
    expect(responseOrderWarning?.message ?? '').toMatch(/consumer contract/i);
    expect(responseOrderWarning?.message ?? '').toMatch(/trustPolicyExclude is not architecturally correct/i);
    expect(responseOrderWarning?.message ?? '').toMatch(/remove the exception/i);
  });

  it('rejects trustPolicyExclude entries that drift to latest instead of one exact reviewed version', async () => {
    const rootPath = await createFixtureProject({
      workspaceText: BASE_WORKSPACE_TEXT.replace(
        /^trustPolicyExclude: \[\]$/mu,
        'trustPolicyExclude:\n  - "foo@latest"',
      ),
    });

    const project = runAudit(rootPath);
    const selectorCheck = project.checks.find((check) => check.property === 'trustPolicyExclude[0]');

    expect(selectorCheck?.status).toBe('invalid');
    expect(selectorCheck?.actual).toBe('foo@latest');
    expect(selectorCheck?.message ?? '').toMatch(/exact package version/i);
    expect(selectorCheck?.message ?? '').toMatch(/latest/i);
    expect(getCheck(project, 'trustPolicyExclude exact versions')).toBeUndefined();
  });

  it('accepts overrides only when every target stays pinned to an exact semver version', async () => {
    const rootPath = await createFixtureProject({
      workspaceText: BASE_WORKSPACE_TEXT.replace(
        /^overrides: \{\}$/mu,
        'overrides:\n  "react-dom@18.2.0>react": "18.1.0"',
      ),
    });

    const project = runAudit(rootPath);
    const exactVersionsCheck = getCheck(project, 'overrides exact versions');

    expect(project.status).toBe('failed');
    expect(getCheck(project, 'overrides')?.status).toBe('invalid');
    expect(exactVersionsCheck?.status).toBe('ok');
    expect(exactVersionsCheck?.actual).toBe('1 exact override target');
    expect(exactVersionsCheck?.message ?? '').toMatch(/explicit exact semver versions only/i);
  });

  it('rejects overrides that target open semver ranges instead of one exact reviewed version', async () => {
    const rootPath = await createFixtureProject({
      workspaceText: BASE_WORKSPACE_TEXT.replace(
        /^overrides: \{\}$/mu,
        'overrides:\n  "react-dom@18.2.0>react": "^18.1.0"',
      ),
    });

    const project = runAudit(rootPath);
    const rangeCheck = project.checks.find((check) => check.property === 'overrides.react-dom@18.2.0>react');

    expect(rangeCheck?.status).toBe('invalid');
    expect(rangeCheck?.actual).toBe('^18.1.0');
    expect(rangeCheck?.message ?? '').toMatch(/exact semver version only/i);
    expect(rangeCheck?.message ?? '').toMatch(/open ranges/i);
    expect(getCheck(project, 'overrides exact versions')).toBeUndefined();
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
    expect(runtimeCheck?.message ?? '').toContain('package.json#devEngines.runtime');
    expect(runtimeCheck?.message ?? '').toContain('package.json#engines.runtime');
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

  it('requires the dynamically resolved pnpm latest version on both package-manager contracts', async () => {
    const rootPath = await createFixtureProject();
    const toolchainPolicy = createGovernanceToolchainPolicy({
      pnpm: {
        requiredVersion: '12.1.0',
        requiredMajor: 12,
        latestVersion: '12.1.0',
        minimumReleaseAgeMinutes: 10080,
        latestPublishedAt: '2026-05-12T08:00:00.000Z',
        requiredPublishedAt: '2026-05-12T08:00:00.000Z',
        releaseAgeCutoff: '2026-05-20T09:34:35.333Z',
        latestDeferredByMinimumReleaseAge: false,
        checkedAt: '2026-05-27T09:00:00.000Z',
        source: 'https://registry.npmjs.org/pnpm',
        liveResolved: true,
      },
    });

    const project = runAudit(rootPath, {
      pnpmRuntime: createPnpmRuntime({
        version: '12.1.0',
        major: 12,
        requiredVersion: '12.1.0',
        requiredMajor: 12,
        matchesRequiredVersion: true,
        matchesRequiredMajor: true,
        warning: null,
      }),
      toolchainPolicy,
    });

    expect(getCheck(project, 'packageManager')?.status).toBe('invalid');
    expect(getCheck(project, 'packageManager')?.expected).toBe('pnpm@12.1.0');
    expect(getCheck(project, 'devEngines.packageManager.version')?.status).toBe('invalid');
    expect(getCheck(project, 'devEngines.packageManager.version')?.expected).toBe('12.1.0');
    expect(project.status).toBe('failed');
  });

  it('keeps the newest mature pnpm version as the required contract while latest is still blocked by minimumReleaseAge', async () => {
    const rootPath = await createFixtureProject({
      packageJson: createPackageJson({
        packageManager: 'pnpm@11.5.2',
        devEngines: {
          packageManager: {
            name: 'pnpm',
            version: '11.5.2',
            onFail: 'error',
          },
        },
      }),
    });
    const pnpmPolicy = createGovernanceToolchainPolicy({
      pnpm: {
        requiredVersion: '11.5.0',
        requiredMajor: 11,
        latestVersion: '11.5.2',
        minimumReleaseAgeMinutes: 10080,
        latestPublishedAt: '2026-05-24T08:43:45.834Z',
        requiredPublishedAt: '2026-05-19T08:43:45.834Z',
        releaseAgeCutoff: '2026-05-20T09:34:35.333Z',
        latestDeferredByMinimumReleaseAge: true,
        checkedAt: '2026-05-27T09:34:35.333Z',
        source: 'https://registry.npmjs.org/pnpm',
        liveResolved: true,
      },
    });

    const project = runAudit(rootPath, {
      pnpmRuntime: createPnpmRuntime({
        version: '11.5.0',
        major: 11,
        requiredVersion: '11.5.0',
        requiredMajor: 11,
        matchesRequiredVersion: true,
        matchesRequiredMajor: true,
        warning: null,
      }),
      toolchainPolicy: pnpmPolicy,
    });

    expect(getCheck(project, 'packageManager')?.status).toBe('invalid');
    expect(getCheck(project, 'packageManager')?.message ?? '').toContain('official latest PNPM release 11.5.2');
    expect(getCheck(project, 'packageManager')?.message ?? '').toContain('minimumReleaseAge cutoff 2026-05-20T09:34:35.333Z');
    expect(getCheck(project, 'devEngines.packageManager.version')?.status).toBe('invalid');
    expect(getCheck(project, 'devEngines.packageManager.version')?.message ?? '').toContain('official latest PNPM release 11.5.2');
    expect(project.status).toBe('failed');
  });

  it('fails when the aligned node runtime contract falls below the current Node LTS floor', async () => {
    const rootPath = await createFixtureProject();
    const project = runAudit(rootPath, {
      toolchainPolicy: createGovernanceToolchainPolicy({
        node: {
          minimumLtsVersion: '26.3.0',
          minimumLtsMajor: 26,
          latestVersion: '27.0.1',
          latestMajor: 27,
          checkedAt: '2026-05-27T09:00:00.000Z',
          source: 'https://nodejs.org/dist/index.json',
          ltsCodename: 'Krypton',
          liveResolved: true,
        },
      }),
    });

    expect(getCheck(project, 'runtime contract >= current Node LTS')?.status).toBe('invalid');
    expect(getCheck(project, 'runtime contract >= current Node LTS')?.expected).toBe('26.3.0');
    expect(getCheck(project, 'runtime contract = current Node latest')).toBeUndefined();
    expect(project.status).toBe('failed');
  });

  it('creates a non-failing warning when the aligned node runtime contract meets LTS but not latest', async () => {
    const rootPath = await createFixtureProject();
    const project = runAudit(rootPath, {
      toolchainPolicy: createGovernanceToolchainPolicy({
        node: {
          minimumLtsVersion: '26.0.0',
          minimumLtsMajor: 26,
          latestVersion: '26.3.0',
          latestMajor: 26,
          checkedAt: '2026-05-27T09:00:00.000Z',
          source: 'https://nodejs.org/dist/index.json',
          ltsCodename: 'Krypton',
          liveResolved: true,
        },
      }),
    });

    expect(getCheck(project, 'runtime contract >= current Node LTS')?.status).toBe('ok');
    expect(getCheck(project, 'runtime contract = current Node latest')?.status).toBe('warning');
    expect(getCheck(project, 'runtime contract = current Node latest')?.message ?? '').toContain('26.3.0');
    expect(project.status).toBe('warning');
    expect(project.summary.warningCount).toBeGreaterThan(0);
    expect(project.summary.invalidCount).toBe(0);
    expect(project.summary.missingCount).toBe(0);
  });

  it('passes when the aligned node runtime contract already matches the current latest release', async () => {
    const rootPath = await createFixtureProject();
    const project = runAudit(rootPath, {
      toolchainPolicy: createGovernanceToolchainPolicy({
        node: {
          minimumLtsVersion: '26.0.0',
          minimumLtsMajor: 26,
          latestVersion: '26.2.0',
          latestMajor: 26,
          checkedAt: '2026-05-27T09:00:00.000Z',
          source: 'https://nodejs.org/dist/index.json',
          ltsCodename: 'Krypton',
          liveResolved: true,
        },
      }),
    });

    expect(getCheck(project, 'runtime contract >= current Node LTS')?.status).toBe('ok');
    expect(getCheck(project, 'runtime contract = current Node latest')?.status).toBe('ok');
    expect(project.status).toBe('passed');
  });
});
