import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { auditPnpmGovernance } from './src/application/pnpm-governance.mjs';
import { renderPnpmGovernanceAudit } from './src/presentation/pnpm-governance-reporting.mjs';

const REPO_ROOT = path.dirname(fileURLToPath(import.meta.url));
const BASE_PACKAGE_JSON = JSON.parse(readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf8'));
const BASE_WORKSPACE_TEXT = readFileSync(path.join(REPO_ROOT, 'pnpm-workspace.yaml'), 'utf8');
const PNPM_RUNTIME = Object.freeze({
  available: true,
  version: '11.2.2',
  major: 11,
  requiredMajor: 11,
  matchesRequiredMajor: true,
  warning: null,
});

test('single-project accepts saveExact and exact catalog versions', async (t) => {
  const rootPath = await createFixtureProject(t, {
    workspaceText: BASE_WORKSPACE_TEXT,
  });

  const project = runAudit(rootPath);
  assert.equal(project.classification.kind, 'pnpm-single-project');
  assert.equal(getCheck(project, 'saveExact')?.status, 'ok');
  assert.equal(getCheck(project, 'catalog exact versions')?.status, 'ok');
});

test('single-project flags missing saveExact', async (t) => {
  const rootPath = await createFixtureProject(t, {
    workspaceText: BASE_WORKSPACE_TEXT.replace(/^saveExact: true\r?\n/mu, ''),
  });

  const project = runAudit(rootPath);
  assert.equal(project.classification.kind, 'pnpm-single-project');
  assert.equal(getCheck(project, 'saveExact')?.status, 'missing');
});

test('monorepo accepts saveExact as a required root policy', async (t) => {
  const rootPath = await createFixtureProject(t, {
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
  assert.equal(project.classification.kind, 'pnpm-monorepo');
  assert.equal(getCheck(project, 'saveExact')?.status, 'ok');
});

test('nested pnpm workspace domains inside a monorepo are audited and linked to their parent', async (t) => {
  const rootPath = await createFixtureProject(t, {
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
        workspaceText: BASE_WORKSPACE_TEXT.replace(/^nodeVersion: .+$/mu, 'nodeVersion: 26.2.0'),
        lockfileText: 'lockfileVersion: "9.0"\n',
      },
    ],
  });

  const audit = auditPnpmGovernance([rootPath], {}, PNPM_RUNTIME);
  assert.equal(audit.summary.projectCount, 2);
  assert.equal(audit.summary.rootPnpmMonorepoCount, 1);
  assert.equal(audit.summary.standalonePnpmSingleProjectCount, 0);
  assert.equal(audit.summary.nestedPnpmDomainCount, 1);

  const rootProject = audit.projects.find((project) => project.rootPath === rootPath);
  const nestedDomain = audit.projects.find((project) =>
    project.rootPath === path.join(rootPath, 'domains', 'billing-domain'),
  );

  assert.ok(rootProject);
  assert.ok(nestedDomain);
  assert.equal(nestedDomain.classification.kind, 'pnpm-single-project');
  assert.equal(nestedDomain.topology?.role, 'nested-domain');
  assert.equal(nestedDomain.topology?.parentRootPath, rootProject.rootPath);
  assert.deepEqual(nestedDomain.topology?.lineageRootPaths, [
    rootProject.rootPath,
    nestedDomain.rootPath,
  ]);
});

test('ordinary workspace packages without their own pnpm-workspace file stay out of nested-domain scanning', async (t) => {
  const rootPath = await createFixtureProject(t, {
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
  assert.equal(audit.summary.projectCount, 1);
  assert.equal(audit.summary.nestedPnpmDomainCount, 0);
  assert.deepEqual(audit.projects.map((project) => project.rootPath), [rootPath]);
});

test('catalog entries reject non-exact version ranges', async (t) => {
  const rootPath = await createFixtureProject(t, {
    workspaceText: BASE_WORKSPACE_TEXT.replace(
      /^catalog:\r?\n/mu,
      'catalog:\n  range-only-fixture: ^1.2.3\n',
    ),
  });

  const project = runAudit(rootPath);
  const rangeCheck = getCheck(project, 'catalog.range-only-fixture');
  assert.equal(rangeCheck?.status, 'invalid');
  assert.match(rangeCheck?.message ?? '', /explicit exact versions/i);
  assert.equal(getCheck(project, 'catalog exact versions'), undefined);
});

test('report renders nested domains with an arrow back to the containing monorepo', { concurrency: false }, async (t) => {
  const rootPath = await createFixtureProject(t, {
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
  const rootProject = audit.projects.find((project) => project.rootPath === rootPath);
  const nestedDomain = audit.projects.find((project) =>
    project.rootPath === path.join(rootPath, 'domains', 'billing-domain'),
  );

  const output = captureConsoleOutput(() => {
    renderPnpmGovernanceAudit(audit);
  });

  assert.ok(rootProject);
  assert.ok(nestedDomain);
  assert.match(
    output,
    new RegExp(escapeRegExp(`${rootProject.displayPath} -> ${nestedDomain.displayPath} [pnpm-single-project domain]`), 'u'),
  );
});

function runAudit(rootPath) {
  const audit = auditPnpmGovernance([rootPath], {}, PNPM_RUNTIME);
  assert.equal(audit.projects.length, 1);
  return audit.projects[0];
}

function getCheck(project, property) {
  return project.checks.find((check) => check.property === property);
}

async function createFixtureProject(t, options = {}) {
  const fixtureRoot = await mkdtemp(path.join(os.tmpdir(), 'pnpm-governance-'));
  t.after(async () => {
    await rm(fixtureRoot, { recursive: true, force: true });
  });

  const packageJson = options.packageJson ?? BASE_PACKAGE_JSON;
  await writeFile(path.join(fixtureRoot, 'package.json'), JSON.stringify(packageJson, null, 2));
  await writeFile(path.join(fixtureRoot, 'pnpm-workspace.yaml'), options.workspaceText ?? BASE_WORKSPACE_TEXT);
  await writeFile(path.join(fixtureRoot, 'pnpm-lock.yaml'), 'lockfileVersion: "9.0"\n');
  await writeFile(path.join(fixtureRoot, '.gitignore'), '.npmrc\nauth.ini\n');

  for (const member of options.workspaceMembers ?? []) {
    const memberRoot = path.join(fixtureRoot, member.relativePath);
    await mkdir(memberRoot, { recursive: true });
    await writeFile(
      path.join(memberRoot, 'package.json'),
      JSON.stringify(member.packageJson, null, 2),
    );
    if (member.workspaceText) {
      await writeFile(path.join(memberRoot, 'pnpm-workspace.yaml'), member.workspaceText);
    }
    if (member.lockfileText) {
      await writeFile(path.join(memberRoot, 'pnpm-lock.yaml'), member.lockfileText);
    }
    if (member.gitignoreText) {
      await writeFile(path.join(memberRoot, '.gitignore'), member.gitignoreText);
    }
  }

  return fixtureRoot;
}

function buildMonorepoWorkspaceText(baseWorkspaceText, options = {}) {
  const workspacePatterns = options.workspacePatterns ?? ['packages/*'];
  return [
    'packages:',
    ...workspacePatterns.map((pattern) => `  - "${pattern}"`),
    'includeWorkspaceRoot: false',
    'sharedWorkspaceLockfile: true',
    'disallowWorkspaceCycles: true',
    'failIfNoMatch: true',
    'linkWorkspacePackages: false',
    'preferWorkspacePackages: false',
    'saveWorkspaceProtocol: true',
    'savePrefix: ""',
    'injectWorkspacePackages: false',
    'dedupeInjectedDeps: true',
    'hoistWorkspacePackages: false',
    'resolvePeersFromWorkspaceRoot: true',
    'packageConfigs: []',
    '',
    baseWorkspaceText.trim(),
    '',
  ].join('\n');
}

function createPackageJson(overrides = {}) {
  return {
    ...BASE_PACKAGE_JSON,
    ...overrides,
    engines: {
      ...BASE_PACKAGE_JSON.engines,
      ...(overrides.engines ?? {}),
    },
    devEngines: {
      ...BASE_PACKAGE_JSON.devEngines,
      ...(overrides.devEngines ?? {}),
      runtime: {
        ...BASE_PACKAGE_JSON.devEngines.runtime,
        ...(overrides.devEngines?.runtime ?? {}),
      },
      packageManager: {
        ...BASE_PACKAGE_JSON.devEngines.packageManager,
        ...(overrides.devEngines?.packageManager ?? {}),
      },
    },
    scripts: {
      ...BASE_PACKAGE_JSON.scripts,
      ...(overrides.scripts ?? {}),
    },
    dependencies: {
      ...BASE_PACKAGE_JSON.dependencies,
      ...(overrides.dependencies ?? {}),
    },
  };
}

function captureConsoleOutput(action) {
  const originalConsoleLog = console.log;
  const lines = [];
  console.log = (...args) => {
    lines.push(args.join(' '));
  };
  try {
    action();
  } finally {
    console.log = originalConsoleLog;
  }
  return lines.join('\n');
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
}
