import { readFileSync } from 'node:fs';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { onTestFinished, vi } from 'vitest';

import {
  auditPnpmGovernance,
  type GovernanceCheck,
  type GovernanceProjectReport,
  type PnpmRuntimeInfo,
} from '../../../src/application/pnpm-governance';
import {
  createReferenceGovernanceToolchainPolicy,
  type GovernanceNodePolicy,
  type GovernancePnpmPolicy,
  type GovernanceToolchainPolicy,
} from '../../../src/domain/pnpm-governance';

type JsonObject = Record<string, unknown>;

export interface FixtureWorkspaceMember {
  relativePath: string;
  packageJson: JsonObject;
  workspaceText?: string;
  lockfileText?: string;
  gitignoreText?: string;
}

export interface FixtureProjectOptions {
  packageJson?: JsonObject;
  workspaceText?: string;
  workspaceMembers?: readonly FixtureWorkspaceMember[];
  gitignoreText?: string;
  npmrcText?: string;
  authIniText?: string;
}

function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function toJsonObject(value: unknown): JsonObject {
  return isJsonObject(value) ? value : {};
}

function parseJsonObject(text: string, fileLabel: string): JsonObject {
  const parsed: unknown = JSON.parse(text);
  if (!isJsonObject(parsed)) {
    throw new TypeError(`${fileLabel} must contain a JSON object.`);
  }
  return parsed;
}

function mergeJsonObjects(baseValue: unknown, overrideValue: unknown): JsonObject {
  return {
    ...toJsonObject(baseValue),
    ...toJsonObject(overrideValue),
  };
}

const BASE_PACKAGE_JSON = parseJsonObject(
  readFileSync(new URL('../../../package.json', import.meta.url), 'utf8'),
  'package.json',
);

export const BASE_WORKSPACE_TEXT = readFileSync(
  new URL('../../../pnpm-workspace.yaml', import.meta.url),
  'utf8',
);

export const PNPM_RUNTIME: PnpmRuntimeInfo = Object.freeze({
  available: true,
  version: '11.2.2',
  major: 11,
  requiredMajor: 11,
  requiredVersion: '11.2.2',
  matchesRequiredMajor: true,
  matchesRequiredVersion: true,
  warning: null,
});

export const GOVERNANCE_TOOLCHAIN_POLICY: GovernanceToolchainPolicy = Object.freeze(
  createReferenceGovernanceToolchainPolicy(),
);

export function createGovernanceToolchainPolicy(
  overrides: {
    pnpm?: Partial<GovernancePnpmPolicy>;
    node?: Partial<GovernanceNodePolicy>;
    warnings?: string[];
  } = {},
): GovernanceToolchainPolicy {
  const referencePolicy = createReferenceGovernanceToolchainPolicy();
  return {
    pnpm: {
      ...referencePolicy.pnpm,
      ...(overrides.pnpm ?? {}),
    },
    node: {
      ...referencePolicy.node,
      ...(overrides.node ?? {}),
    },
    warnings: [...(overrides.warnings ?? referencePolicy.warnings)],
  };
}

export function createPnpmRuntime(overrides: Partial<PnpmRuntimeInfo> = {}): PnpmRuntimeInfo {
  return {
    ...PNPM_RUNTIME,
    ...overrides,
  };
}

export async function createFixtureProject(
  options: FixtureProjectOptions = {},
): Promise<string> {
  const fixtureRoot = await mkdtemp(path.join(os.tmpdir(), 'pnpm-governance-'));

  onTestFinished(async () => {
    await rm(fixtureRoot, { recursive: true, force: true });
  });

  await writeFile(
    path.join(fixtureRoot, 'package.json'),
    JSON.stringify(options.packageJson ?? BASE_PACKAGE_JSON, null, 2),
  );
  await writeFile(
    path.join(fixtureRoot, 'pnpm-workspace.yaml'),
    options.workspaceText ?? BASE_WORKSPACE_TEXT,
  );
  await writeFile(path.join(fixtureRoot, 'pnpm-lock.yaml'), 'lockfileVersion: "9.0"\n');
  await writeFile(
    path.join(fixtureRoot, '.gitignore'),
    options.gitignoreText ?? '.npmrc\nauth.ini\n',
  );
  if (options.npmrcText !== undefined) {
    await writeFile(path.join(fixtureRoot, '.npmrc'), options.npmrcText);
  }
  if (options.authIniText !== undefined) {
    await writeFile(path.join(fixtureRoot, 'auth.ini'), options.authIniText);
  }

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

export function buildMonorepoWorkspaceText(
  baseWorkspaceText = BASE_WORKSPACE_TEXT,
  options: { workspacePatterns?: readonly string[] } = {},
): string {
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

export function createPackageJson(overrides: JsonObject = {}): JsonObject {
  const baseDevEngines = toJsonObject(BASE_PACKAGE_JSON['devEngines']);
  const overrideDevEngines = toJsonObject(overrides['devEngines']);

  return {
    ...BASE_PACKAGE_JSON,
    ...overrides,
    engines: mergeJsonObjects(BASE_PACKAGE_JSON['engines'], overrides['engines']),
    devEngines: {
      ...baseDevEngines,
      ...overrideDevEngines,
      runtime: mergeJsonObjects(baseDevEngines['runtime'], overrideDevEngines['runtime']),
      packageManager: mergeJsonObjects(
        baseDevEngines['packageManager'],
        overrideDevEngines['packageManager'],
      ),
    },
    scripts: mergeJsonObjects(BASE_PACKAGE_JSON['scripts'], overrides['scripts']),
    dependencies: mergeJsonObjects(BASE_PACKAGE_JSON['dependencies'], overrides['dependencies']),
    devDependencies: mergeJsonObjects(
      BASE_PACKAGE_JSON['devDependencies'],
      overrides['devDependencies'],
    ),
    optionalDependencies: mergeJsonObjects(
      BASE_PACKAGE_JSON['optionalDependencies'],
      overrides['optionalDependencies'],
    ),
    peerDependencies: mergeJsonObjects(
      BASE_PACKAGE_JSON['peerDependencies'],
      overrides['peerDependencies'],
    ),
  };
}

export function runAudit(
  rootPath: string,
  options: {
    pnpmRuntime?: PnpmRuntimeInfo;
    toolchainPolicy?: GovernanceToolchainPolicy;
  } = {},
): GovernanceProjectReport {
  const audit = auditPnpmGovernance(
    [rootPath],
    {},
    options.pnpmRuntime ?? PNPM_RUNTIME,
    options.toolchainPolicy ?? GOVERNANCE_TOOLCHAIN_POLICY,
  );

  if (audit.projects.length !== 1) {
    throw new Error(`Expected exactly one audited project, received ${audit.projects.length}.`);
  }

  const [project] = audit.projects;
  if (!project) {
    throw new Error('Expected an audited project to be present.');
  }

  return project;
}

export function getCheck(
  project: GovernanceProjectReport,
  property: string,
): GovernanceCheck | undefined {
  return project.checks.find((check) => check.property === property);
}

export function captureConsoleOutput(action: () => void): string {
  const lines: string[] = [];
  const consoleLogSpy = vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
    lines.push(args.join(' '));
  });

  try {
    action();
  } finally {
    consoleLogSpy.mockRestore();
  }

  return lines.join('\n');
}

export function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
}
