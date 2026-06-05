import { describe, expect, it } from 'vitest';
import YAML from 'yaml';

import {
  MONOREPO_WORKSPACE_EXACT_RULES,
  SHARED_WORKSPACE_EMPTY_ARRAY_RULES,
  SHARED_WORKSPACE_EMPTY_OBJECT_RULES,
  SHARED_WORKSPACE_EXACT_RULES,
  SINGLE_PROJECT_FORBIDDEN_WORKSPACE_RULES,
} from '../../../../../src/domain/pnpm-governance';
import {
  BASE_WORKSPACE_TEXT,
  PNPM_RUNTIME,
  buildMonorepoWorkspaceText,
  createFixtureProject,
  createPackageJson,
  getCheck,
  runAudit,
} from '@test/shared/utils/pnpm-governance-fixtures';

type MutableRecord = Record<string, unknown>;

const SHARED_EXACT_RULE_ENTRIES: Array<{ property: string; expected: unknown }> = SHARED_WORKSPACE_EXACT_RULES.map(([property, expected]) => ({
  property: String(property),
  expected,
}));

const MONOREPO_EXACT_RULE_ENTRIES: Array<{ property: string; expected: unknown }> = MONOREPO_WORKSPACE_EXACT_RULES.map(([property, expected]) => ({
  property: String(property),
  expected,
}));

const SINGLE_PROJECT_FORBIDDEN_VALUES: Record<string, unknown> = {
  packages: ['apps/*'],
  includeWorkspaceRoot: false,
  sharedWorkspaceLockfile: true,
  disallowWorkspaceCycles: true,
  failIfNoMatch: true,
  linkWorkspacePackages: false,
  preferWorkspacePackages: false,
  saveWorkspaceProtocol: true,
  injectWorkspacePackages: false,
  dedupeInjectedDeps: true,
  hoistWorkspacePackages: false,
  resolvePeersFromWorkspaceRoot: true,
  packageConfigs: [],
};

function isMutableRecord(value: unknown): value is MutableRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function parseWorkspaceText(text: string): MutableRecord {
  const parsed: unknown = YAML.parse(text);
  if (!isMutableRecord(parsed)) {
    throw new TypeError('Expected pnpm-workspace content to parse into an object.');
  }
  return parsed;
}

function serializeWorkspaceText(workspace: MutableRecord): string {
  return `${YAML.stringify(workspace).trimEnd()}\n`;
}

function mutateWorkspaceText(
  baseText: string,
  mutator: (workspace: MutableRecord) => void,
): string {
  const workspace = parseWorkspaceText(baseText);
  mutator(workspace);
  return serializeWorkspaceText(workspace);
}

function setNestedValue(target: MutableRecord, propertyPath: string, value: unknown): void {
  const segments = propertyPath.split('.');
  let current: MutableRecord = target;
  for (const segment of segments.slice(0, -1)) {
    const existing = current[segment];
    if (!isMutableRecord(existing)) {
      const next: MutableRecord = {};
      current[segment] = next;
      current = next;
      continue;
    }
    current = existing;
  }

  const leaf = segments[segments.length - 1];
  if (typeof leaf !== 'string' || leaf.length === 0) {
    throw new TypeError(`Invalid property path: ${propertyPath}`);
  }
  current[leaf] = value;
}

function deleteNestedValue(target: MutableRecord, propertyPath: string): void {
  const segments = propertyPath.split('.');
  let current: MutableRecord = target;
  for (const segment of segments.slice(0, -1)) {
    const existing = current[segment];
    if (!isMutableRecord(existing)) {
      return;
    }
    current = existing;
  }

  const leaf = segments[segments.length - 1];
  if (typeof leaf !== 'string' || leaf.length === 0) {
    throw new TypeError(`Invalid property path: ${propertyPath}`);
  }
  delete current[leaf];
}

function invalidExactValue(expected: unknown): unknown {
  if (typeof expected === 'boolean') {
    return !expected;
  }
  if (typeof expected === 'number') {
    return expected === 60 ? 61 : Math.max(0, expected - 1);
  }
  if (typeof expected === 'string') {
    switch (expected) {
      case 'no-downgrade':
        return 'allow';
      case 'error':
        return 'warn';
      case 'time-based':
        return 'highest';
      case '.pnpm':
        return 'node_modules/.pnpm';
      case '':
        return '^';
      default:
        return `${expected}-invalid`;
    }
  }
  throw new TypeError(`Unsupported exact-rule value: ${String(expected)}`);
}

describe('pnpm governance rule matrix', () => {
  it('marks all shared exact workspace rules as ok in the single-project baseline', async () => {
    const project = runAudit(await createFixtureProject({
      workspaceText: BASE_WORKSPACE_TEXT,
    }));

    for (const { property } of SHARED_EXACT_RULE_ENTRIES) {
      expect(getCheck(project, property)?.status, property).toBe('ok');
    }
  });

  it.each(SHARED_EXACT_RULE_ENTRIES)(
    'rejects invalid shared exact workspace rule $property',
    async ({ property, expected }) => {
      const rootPath = await createFixtureProject({
        workspaceText: mutateWorkspaceText(BASE_WORKSPACE_TEXT, (workspace) => {
          setNestedValue(workspace, property, invalidExactValue(expected));
        }),
      });

      const project = runAudit(rootPath);
      expect(getCheck(project, property)?.status).toBe('invalid');
    },
  );

  it('marks all shared empty-array rules as ok in the single-project baseline', async () => {
    const project = runAudit(await createFixtureProject({
      workspaceText: BASE_WORKSPACE_TEXT,
    }));

    for (const property of SHARED_WORKSPACE_EMPTY_ARRAY_RULES) {
      expect(getCheck(project, property)?.status, property).toBe('ok');
    }
  });

  it.each(SHARED_WORKSPACE_EMPTY_ARRAY_RULES)(
    'rejects non-empty shared array rule %s',
    async (property) => {
      const rootPath = await createFixtureProject({
        workspaceText: mutateWorkspaceText(BASE_WORKSPACE_TEXT, (workspace) => {
          setNestedValue(workspace, property, ['exception']);
        }),
      });

      const project = runAudit(rootPath);
      expect(getCheck(project, property)?.status).toBe('invalid');
    },
  );

  it('marks all shared explicit-empty object rules as ok in the single-project baseline', async () => {
    const project = runAudit(await createFixtureProject({
      workspaceText: BASE_WORKSPACE_TEXT,
    }));

    for (const property of SHARED_WORKSPACE_EMPTY_OBJECT_RULES) {
      expect(getCheck(project, property)?.status, property).toBe('ok');
    }
  });

  it.each(SHARED_WORKSPACE_EMPTY_OBJECT_RULES)(
    'rejects non-empty shared object exception surface %s',
    async (property) => {
      const rootPath = await createFixtureProject({
        workspaceText: mutateWorkspaceText(BASE_WORKSPACE_TEXT, (workspace) => {
          setNestedValue(workspace, property, { reviewed: 'exception' });
        }),
      });

      const project = runAudit(rootPath);
      expect(getCheck(project, property)?.status).toBe('invalid');
      expect(getCheck(project, property)?.message ?? '').toMatch(/stay empty in Fortress mode/i);
    },
  );

  it.each([
    {
      property: 'trustPolicyExclude',
      value: ['legacy-mirror'],
      expectedRecoveryHint: /trust-policy or registry governance/i,
      expectedTargetState: '[]',
    },
    {
      property: 'overrides',
      value: { minimatch: '10.2.5' },
      expectedRecoveryHint: /canonical catalog or dependency policy changes/i,
      expectedTargetState: '{}',
    },
    {
      property: 'packageExtensions',
      value: {
        'minimatch@10.2.5': {
          peerDependencies: {
            semver: '7.8.0',
          },
        },
      },
      expectedRecoveryHint: /upstream manifest fixes or canonical package policy changes/i,
      expectedTargetState: '{}',
    },
  ])(
    'keeps $property as a failing yellow exception surface',
    async ({ property, value, expectedRecoveryHint, expectedTargetState }) => {
      const rootPath = await createFixtureProject({
        workspaceText: mutateWorkspaceText(BASE_WORKSPACE_TEXT, (workspace) => {
          setNestedValue(workspace, property, value);
        }),
      });

      const project = runAudit(rootPath);
      const exceptionCheck = getCheck(project, property);

      expect(project.status).toBe('failed');
      expect(exceptionCheck?.status).toBe('invalid');
      expect(exceptionCheck?.presentationTone).toBe('warning');
      expect(exceptionCheck?.message ?? '').toMatch(/still fails governance/i);
      expect(exceptionCheck?.message ?? '').toContain(expectedTargetState);
      expect(exceptionCheck?.message ?? '').toMatch(expectedRecoveryHint);
    },
  );

  it('marks all single-project forbidden monorepo-only surfaces as omitted', async () => {
    const project = runAudit(await createFixtureProject({
      workspaceText: BASE_WORKSPACE_TEXT,
    }));

    for (const property of SINGLE_PROJECT_FORBIDDEN_WORKSPACE_RULES) {
      expect(getCheck(project, property)?.status, property).toBe('ok');
    }
  });

  it.each(SINGLE_PROJECT_FORBIDDEN_WORKSPACE_RULES)(
    'rejects monorepo-only surface %s in a single-project repository',
    async (property) => {
      if (property === 'packages') {
        return;
      }
      const value = SINGLE_PROJECT_FORBIDDEN_VALUES[property];
      if (value === undefined) {
        throw new TypeError(`Missing single-project forbidden value for ${property}`);
      }

      const rootPath = await createFixtureProject({
        workspaceText: mutateWorkspaceText(BASE_WORKSPACE_TEXT, (workspace) => {
          setNestedValue(workspace, property, value);
        }),
      });

      const project = runAudit(rootPath);
      expect(getCheck(project, property)?.status).toBe('invalid');
    },
  );

  it('classifies an explicit packages declaration as monorepo topology instead of a single-project omission', async () => {
    const rootPath = await createFixtureProject({
      workspaceText: mutateWorkspaceText(BASE_WORKSPACE_TEXT, (workspace) => {
        setNestedValue(workspace, 'packages', ['apps/*']);
      }),
      workspaceMembers: [
        {
          relativePath: 'apps/fixture-app',
          packageJson: createPackageJson({
            name: '@fixture/fixture-app',
          }),
        },
      ],
    });

    const project = runAudit(rootPath);

    expect(project.classification.kind).toBe('pnpm-monorepo');
    expect(getCheck(project, 'packages')?.status).toBe('ok');
  });

  it('marks all monorepo exact rules as ok in the monorepo baseline', async () => {
    const project = runAudit(await createFixtureProject({
      workspaceText: buildMonorepoWorkspaceText(BASE_WORKSPACE_TEXT),
      workspaceMembers: [
        {
          relativePath: 'packages/fixture-app',
          packageJson: createPackageJson({
            name: '@fixture/fixture-app',
          }),
        },
      ],
    }));

    for (const { property } of MONOREPO_EXACT_RULE_ENTRIES) {
      expect(getCheck(project, property)?.status, property).toBe('ok');
    }
  });

  it.each(MONOREPO_EXACT_RULE_ENTRIES)(
    'rejects invalid monorepo exact rule $property',
    async ({ property, expected }) => {
      const rootPath = await createFixtureProject({
        workspaceText: mutateWorkspaceText(
          buildMonorepoWorkspaceText(BASE_WORKSPACE_TEXT),
          (workspace) => {
            setNestedValue(workspace, property, invalidExactValue(expected));
          },
        ),
        workspaceMembers: [
          {
            relativePath: 'packages/fixture-app',
            packageJson: createPackageJson({
              name: '@fixture/fixture-app',
            }),
          },
        ],
      });

      const project = runAudit(rootPath);
      expect(getCheck(project, property)?.status).toBe('invalid');
    },
  );

  it('marks monorepo array surfaces as ok in the monorepo baseline', async () => {
    const project = runAudit(await createFixtureProject({
      workspaceText: buildMonorepoWorkspaceText(BASE_WORKSPACE_TEXT),
      workspaceMembers: [
        {
          relativePath: 'packages/fixture-app',
          packageJson: createPackageJson({
            name: '@fixture/fixture-app',
          }),
        },
      ],
    }));

    expect(getCheck(project, 'packages')?.status).toBe('ok');
    expect(getCheck(project, 'packageConfigs')?.status).toBe('ok');
  });

  it('rejects an empty monorepo packages array', async () => {
    const rootPath = await createFixtureProject({
      workspaceText: mutateWorkspaceText(
        buildMonorepoWorkspaceText(BASE_WORKSPACE_TEXT),
        (workspace) => {
          setNestedValue(workspace, 'packages', []);
        },
      ),
      workspaceMembers: [
        {
          relativePath: 'packages/fixture-app',
          packageJson: createPackageJson({
            name: '@fixture/fixture-app',
          }),
        },
      ],
    });

    const project = runAudit(rootPath);
    expect(getCheck(project, 'packages')?.status).toBe('invalid');
  });

  it('rejects a missing monorepo packageConfigs array', async () => {
    const rootPath = await createFixtureProject({
      workspaceText: mutateWorkspaceText(
        buildMonorepoWorkspaceText(BASE_WORKSPACE_TEXT),
        (workspace) => {
          deleteNestedValue(workspace, 'packageConfigs');
        },
      ),
      workspaceMembers: [
        {
          relativePath: 'packages/fixture-app',
          packageJson: createPackageJson({
            name: '@fixture/fixture-app',
          }),
        },
      ],
    });

    const project = runAudit(rootPath);
    expect(getCheck(project, 'packageConfigs')?.status).toBe('missing');
  });

  it('accepts the exact runtime identity contract when nodeVersion and devEngines.runtime.version match', async () => {
    const project = runAudit(await createFixtureProject({
      workspaceText: BASE_WORKSPACE_TEXT,
    }));

    expect(getCheck(project, 'nodeVersion')?.status).toBe('ok');
    expect(getCheck(project, 'devEngines.runtime.version')?.status).toBe('ok');
    expect(getCheck(project, 'devEngines.runtime.version = nodeVersion')?.status).toBe('ok');
    expect(getCheck(project, 'engines.node')?.status).toBe('ok');
  });

  it('rejects runtime identity drift between package.json and pnpm-workspace.yaml', async () => {
    const rootPath = await createFixtureProject({
      workspaceText: mutateWorkspaceText(BASE_WORKSPACE_TEXT, (workspace) => {
        setNestedValue(workspace, 'nodeVersion', '26.2.1');
      }),
    });

    const project = runAudit(rootPath);
    const driftCheck = getCheck(project, 'devEngines.runtime.version = nodeVersion');

    expect(driftCheck?.status).toBe('invalid');
    expect(driftCheck?.message ?? '').toMatch(/runtime drift/i);
  });

  it('rejects ranged devEngines runtime versions', async () => {
    const rootPath = await createFixtureProject({
      packageJson: createPackageJson({
        devEngines: {
          runtime: {
            name: 'node',
            version: '>=26.2.0',
            onFail: 'error',
          },
        },
      }),
    });

    const project = runAudit(rootPath);
    expect(getCheck(project, 'devEngines.runtime.version')?.status).toBe('invalid');
  });

  it('rejects root engines.node when it is set', async () => {
    const rootPath = await createFixtureProject({
      packageJson: createPackageJson({
        engines: {
          node: '>=26.2.0',
        },
      }),
    });

    const project = runAudit(rootPath);
    const enginesCheck = getCheck(project, 'engines.node');

    expect(enginesCheck?.status).toBe('invalid');
    expect(enginesCheck?.message ?? '').toMatch(/must stay unset/i);
  });

  it('rejects non-exact root packageManager versions', async () => {
    const rootPath = await createFixtureProject({
      packageJson: createPackageJson({
        packageManager: 'pnpm@11.2.x',
      }),
    });

    const project = runAudit(rootPath);
    expect(getCheck(project, 'packageManager')?.status).toBe('invalid');
  });

  it('rejects non-exact devEngines.packageManager.version values', async () => {
    const rootPath = await createFixtureProject({
      packageJson: createPackageJson({
        devEngines: {
          packageManager: {
            name: 'pnpm',
            version: `^${PNPM_RUNTIME.requiredVersion}`,
            onFail: 'error',
          },
        },
      }),
    });

    const project = runAudit(rootPath);
    expect(getCheck(project, 'devEngines.packageManager.version')?.status).toBe('invalid');
  });

  it('mentions the preferred internal registry path when registries.default is missing', async () => {
    const rootPath = await createFixtureProject({
      workspaceText: mutateWorkspaceText(BASE_WORKSPACE_TEXT, (workspace) => {
        deleteNestedValue(workspace, 'registries.default');
      }),
    });

    const project = runAudit(rootPath);
    const registryCheck = getCheck(project, 'registries.default');

    expect(registryCheck?.status).toBe('missing');
    expect(registryCheck?.message ?? '').toMatch(/Nexus/i);
    expect(registryCheck?.message ?? '').toMatch(/official npm registry/i);
    expect(registryCheck?.message ?? '').toContain('https://registry.npmjs.org/');
  });
});
