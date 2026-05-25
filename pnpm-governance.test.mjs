import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { auditPnpmGovernance } from './src/application/pnpm-governance.mjs';

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
  }

  return fixtureRoot;
}

function buildMonorepoWorkspaceText(baseWorkspaceText) {
  return [
    'packages:',
    '  - "packages/*"',
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
