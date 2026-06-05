import { readFileSync } from 'node:fs';

import semver from 'semver';

export interface NodeRuntimeContract {
  version: string;
  major: number;
  checkedAt: string;
  source: string;
}

export interface GovernancePnpmPolicy {
  requiredVersion: string;
  requiredMajor: number;
  latestVersion: string | null;
  minimumReleaseAgeMinutes: number;
  latestPublishedAt: string | null;
  requiredPublishedAt: string | null;
  releaseAgeCutoff: string | null;
  latestDeferredByMinimumReleaseAge: boolean;
  checkedAt: string;
  source: string;
  liveResolved: boolean;
}

export interface GovernanceNodePolicy {
  minimumLtsVersion: string;
  minimumLtsMajor: number;
  latestVersion: string | null;
  latestMajor: number | null;
  checkedAt: string;
  source: string;
  ltsCodename: string | null;
  liveResolved: boolean;
}

export interface GovernanceToolchainPolicy {
  pnpm: GovernancePnpmPolicy;
  node: GovernanceNodePolicy;
  warnings: string[];
}

const REFERENCE_TOOLCHAIN_SOURCE = 'TS_PACKAGE_MANAGER_PNPM_WORKSPACE_FORTRESS_CORE_REFERENCE_001.mdc';

export const CURRENT_NODE_LTS: NodeRuntimeContract = Object.freeze({
  version: '26.2.0',
  major: 26,
  checkedAt: '2026-05-26',
  source: REFERENCE_TOOLCHAIN_SOURCE,
});

export const FORTRESS_MINIMUM_RELEASE_AGE_MINUTES = 10080;
export const REQUIRED_PNPM_VERSION = resolveCheckedInReferencePnpmVersion();
export const REQUIRED_PNPM_MAJOR = semver.major(REQUIRED_PNPM_VERSION);
export const OFFICIAL_NPM_REGISTRY_URL = 'https://registry.npmjs.org/';
export const PNPM_WORKSPACE_BASENAME = 'pnpm-workspace.yaml';
export const PNPM_LOCKFILE_BASENAME = 'pnpm-lock.yaml';
export const PROJECT_AUTH_FILE_BASENAMES = new Set(['.npmrc', 'auth.ini']);
export const MANIFEST_DEPENDENCY_SECTIONS = Object.freeze([
  'dependencies',
  'devDependencies',
  'optionalDependencies',
  'peerDependencies',
]);
export const MANIFEST_CATALOG_DEPENDENCY_SECTIONS = Object.freeze([
  'dependencies',
  'devDependencies',
]);
export const GOVERNANCE_OWNER_SENTINEL_BASENAMES = Object.freeze([
  '.git',
  '.hg',
  '.svn',
]);

export const GOVERNANCE_DISCOVERY_EXCLUDED_DIR_NAMES = new Set([
  '.git',
  '.hg',
  '.svn',
  '.angular',
  '.build',
  '.next',
  '.nx',
  '.nuxt',
  '.turbo',
  '.cache',
  '.parcel-cache',
  '.pnpm',
  '.pnpm-store',
  '.npm',
  '.yarn',
  '.bun',
  '_cacache',
  '_npx',
  'node_modules',
  'jspm_packages',
  'bower_components',
  'coverage',
  'dist',
  'build',
  'out',
  'tmp',
  'temp',
]);

export const SHARED_WORKSPACE_EXACT_RULES = Object.freeze([
  ['minimumReleaseAge', FORTRESS_MINIMUM_RELEASE_AGE_MINUTES],
  ['minimumReleaseAgeIgnoreMissingTime', false],
  ['minimumReleaseAgeStrict', true],
  ['trustPolicy', 'no-downgrade'],
  ['blockExoticSubdeps', true],
  ['strictDepBuilds', true],
  ['dangerouslyAllowAllBuilds', false],
  ['strictSsl', true],
  ['engineStrict', true],
  ['pmOnFail', 'error'],
  ['runtimeOnFail', 'error'],
  ['lockfile', true],
  ['preferFrozenLockfile', true],
  ['lockfileIncludeTarballUrl', true],
  ['resolutionMode', 'time-based'],
  ['registrySupportsTimeField', false],
  ['nodeLinker', 'isolated'],
  ['enableGlobalVirtualStore', false],
  ['hoist', false],
  ['shamefullyHoist', false],
  ['virtualStoreDir', '.pnpm'],
  ['virtualStoreDirMaxLength', 60],
  ['verifyStoreIntegrity', true],
  ['strictStorePkgContentCheck', true],
  ['autoInstallPeers', false],
  ['strictPeerDependencies', true],
  ['ignoreCompatibilityDb', true],
  ['updateNotifier', false],
  ['saveExact', true],
  ['savePrefix', ''],
  ['catalogMode', 'strict'],
  ['cleanupUnusedCatalogs', true],
  ['enablePrePostScripts', false],
  ['verifyDepsBeforeRun', 'error'],
]);

export const SHARED_WORKSPACE_EMPTY_ARRAY_RULES = Object.freeze([
  'minimumReleaseAgeExclude',
  'trustPolicyExclude',
  'hoistPattern',
  'publicHoistPattern',
  'peerDependencyRules.ignoreMissing',
  'peerDependencyRules.allowAny',
]);

export const SHARED_WORKSPACE_EMPTY_OBJECT_RULES = Object.freeze([
  'peerDependencyRules.allowedVersions',
  'overrides',
  'packageExtensions',
  'allowedDeprecatedVersions',
]);

export const FORTRESS_EXCEPTION_SURFACE_RULES = Object.freeze([
  'trustPolicyExclude',
  'overrides',
  'packageExtensions',
]);

export const SHARED_WORKSPACE_OBJECT_RULES = Object.freeze([
  'allowBuilds',
  'catalog',
]);

export const MONOREPO_WORKSPACE_EXACT_RULES = Object.freeze([
  ['includeWorkspaceRoot', false],
  ['sharedWorkspaceLockfile', true],
  ['disallowWorkspaceCycles', true],
  ['failIfNoMatch', true],
  ['linkWorkspacePackages', false],
  ['preferWorkspacePackages', false],
  ['saveWorkspaceProtocol', true],
  ['injectWorkspacePackages', false],
  ['dedupeInjectedDeps', true],
  ['hoistWorkspacePackages', false],
  ['resolvePeersFromWorkspaceRoot', true],
]);

export const MONOREPO_WORKSPACE_ARRAY_RULES = Object.freeze([
  'packages',
  'packageConfigs',
]);

export const SINGLE_PROJECT_FORBIDDEN_WORKSPACE_RULES = Object.freeze([
  'packages',
  'includeWorkspaceRoot',
  'sharedWorkspaceLockfile',
  'disallowWorkspaceCycles',
  'failIfNoMatch',
  'linkWorkspacePackages',
  'preferWorkspacePackages',
  'saveWorkspaceProtocol',
  'injectWorkspacePackages',
  'dedupeInjectedDeps',
  'hoistWorkspacePackages',
  'resolvePeersFromWorkspaceRoot',
  'packageConfigs',
]);

export const SECURITY_EXCEPTION_WORKSPACE_RULES = Object.freeze([
  'trustPolicyIgnoreAfter',
]);

export const PNPM_RECOMMENDED_SECURITY_PROPERTIES = Object.freeze([
  'minimumReleaseAge',
  'minimumReleaseAgeIgnoreMissingTime',
  'minimumReleaseAgeStrict',
  'minimumReleaseAgeExclude',
  'trustPolicy',
  'trustPolicyExclude',
  'blockExoticSubdeps',
  'strictDepBuilds',
  'allowBuilds',
  'dangerouslyAllowAllBuilds',
  'strictSsl',
  'nodeVersion',
  'engineStrict',
  'pmOnFail',
  'runtimeOnFail',
  'lockfile',
  'preferFrozenLockfile',
  'lockfileIncludeTarballUrl',
  'resolutionMode',
  'registrySupportsTimeField',
  'nodeLinker',
  'enableGlobalVirtualStore',
  'hoist',
  'hoistPattern',
  'publicHoistPattern',
  'shamefullyHoist',
  'virtualStoreDir',
  'virtualStoreDirMaxLength',
  'verifyStoreIntegrity',
  'strictStorePkgContentCheck',
  'autoInstallPeers',
  'strictPeerDependencies',
  'peerDependencyRules',
  'overrides',
  'packageExtensions',
  'allowedDeprecatedVersions',
  'ignoreCompatibilityDb',
  'updateNotifier',
  'saveExact',
  'savePrefix',
  'catalog',
  'catalogs',
  'catalogMode',
  'cleanupUnusedCatalogs',
  'enablePrePostScripts',
  'verifyDepsBeforeRun',
  'packageManager',
  'engines.node',
  'devEngines.runtime',
  'devEngines.packageManager',
]);

const ALLOWED_PROJECT_NPMRC_GLOBAL_KEYS = new Set([
  'ca',
  'ca[]',
  'cafile',
  'cert',
  'key',
]);

const ALLOWED_PROJECT_NPMRC_REGISTRY_KEY_SUFFIXES = new Set([
  '_authToken',
  'cafile',
  'ca',
  'cert',
  'certfile',
  'key',
  'keyfile',
]);

const GOVERNANCE_UNMANAGED_PATH_RULES = Object.freeze([
  {
    id: 'installed-program-files',
    description: 'Installed Windows applications under Program Files',
    platforms: ['win32'],
    pattern: /^(?:[a-z]:)?\/program files(?: \(x86\))?(?:\/|$)/u,
  },
  {
    id: 'windows-store-apps',
    description: 'Windows Store application payloads',
    platforms: ['win32'],
    pattern: /^(?:[a-z]:)?\/program files\/windowsapps(?:\/|$)/u,
  },
  {
    id: 'local-program-bundles',
    description: 'Per-user installed application bundles',
    platforms: ['win32'],
    pattern: /^(?:[a-z]:)?\/users\/[^/]+\/appdata\/local\/programs(?:\/|$)/u,
  },
  {
    id: 'user-editor-extension-store',
    description: 'User-level IDE and editor extension stores',
    platforms: ['win32', 'darwin', 'linux'],
    pattern: /^(?:[a-z]:)?\/(?:users|home)\/[^/]+\/\.(?:vscode|cursor|windsurf|trae|antigravity)\/extensions(?:\/|$)/u,
  },
  {
    id: 'user-agent-tooling',
    description: 'User-level agent plugin and tool state',
    platforms: ['win32', 'darwin', 'linux'],
    pattern: /^(?:[a-z]:)?\/(?:users|home)\/[^/]+\/\.(?:codex|continue)(?:\/|$)/u,
  },
  {
    id: 'pnpm-runtime-store',
    description: 'pnpm runtime store and cache material',
    platforms: ['win32'],
    pattern: /^(?:[a-z]:)?\/users\/[^/]+\/appdata\/local\/(?:pnpm|pnpm-cache)(?:\/|$)/u,
  },
  {
    id: 'corepack-runtime-store',
    description: 'Corepack-managed package-manager payloads',
    platforms: ['win32'],
    pattern: /^(?:[a-z]:)?\/users\/[^/]+\/appdata\/local\/node\/corepack(?:\/|$)/u,
  },
  {
    id: 'cypress-runtime-cache',
    description: 'Cypress runtime cache bundles',
    platforms: ['win32'],
    pattern: /^(?:[a-z]:)?\/users\/[^/]+\/appdata\/local\/cypress\/cache(?:\/|$)/u,
  },
  {
    id: 'trunk-runtime-store',
    description: 'Trunk plugin and tool payloads',
    platforms: ['win32'],
    pattern: /^(?:[a-z]:)?\/users\/[^/]+\/appdata\/local\/trunk(?:\/|$)/u,
  },
  {
    id: 'typescript-runtime-cache',
    description: 'Editor-managed TypeScript runtime caches',
    platforms: ['win32'],
    pattern: /^(?:[a-z]:)?\/users\/[^/]+\/appdata\/local\/microsoft\/typescript(?:\/|$)/u,
  },
  {
    id: 'electron-app-resources',
    description: 'Embedded Electron application resources',
    platforms: ['win32', 'darwin', 'linux'],
    pattern: /\/resources\/app(?:\.asar\.unpacked)?(?:\/|$)/u,
  },
  {
    id: 'desktop-runtime-assets',
    description: 'Embedded desktop runtime asset payloads',
    platforms: ['win32', 'darwin', 'linux'],
    pattern: /(?:^|\/)(desktop-assets|trusted-ui)(?:\/|$)/u,
  },
  {
    id: 'macos-app-bundles',
    description: 'Installed macOS .app bundles',
    platforms: ['darwin'],
    pattern: /^\/(?:applications|users\/[^/]+\/applications)\/.+\.app\/contents(?:\/|$)/u,
  },
  {
    id: 'linux-opt-app-bundles',
    description: 'Installed Linux application bundles under /opt',
    platforms: ['linux'],
    pattern: /^\/opt\/.+\/resources\/app(?:\/|$)/u,
  },
]);

function isGovernanceRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function parseCheckedInPackageManagerVersion(value: unknown): string | null {
  if (typeof value !== 'string') {
    return null;
  }

  const match = value.match(/^pnpm@(.+)$/u);
  if (!match) {
    return null;
  }

  const [, rawVersion] = match;
  return typeof rawVersion === 'string' ? semver.valid(rawVersion) : null;
}

function parseCheckedInDevEnginePnpmVersion(value: unknown): string | null {
  if (!isGovernanceRecord(value)) {
    return null;
  }

  const packageManager = value['packageManager'];
  if (!isGovernanceRecord(packageManager)) {
    return null;
  }

  const name = packageManager['name'];
  if (name !== undefined && name !== 'pnpm') {
    return null;
  }

  const version = packageManager['version'];
  return typeof version === 'string' ? semver.valid(version) : null;
}

function resolveCheckedInReferencePnpmVersion(): string {
  const manifestText = readFileSync(new URL('../../package.json', import.meta.url), 'utf8');
  const manifest: unknown = JSON.parse(manifestText);
  if (!isGovernanceRecord(manifest)) {
    throw new TypeError('The checked-in package.json must contain a JSON object.');
  }

  const packageManagerVersion = parseCheckedInPackageManagerVersion(manifest['packageManager']);
  const devEngineVersion = parseCheckedInDevEnginePnpmVersion(manifest['devEngines']);
  if (packageManagerVersion && devEngineVersion && packageManagerVersion !== devEngineVersion) {
    throw new TypeError(
      `The checked-in PNPM contract drifted: packageManager pins ${packageManagerVersion}, but devEngines.packageManager.version pins ${devEngineVersion}.`,
    );
  }

  const referenceVersion = packageManagerVersion ?? devEngineVersion;
  if (!referenceVersion) {
    throw new TypeError(
      'The checked-in package.json must pin pnpm exactly in packageManager or devEngines.packageManager.version.',
    );
  }

  return referenceVersion;
}

export function isGovernanceDiscoveryExcludedDirName(dirName: string): boolean {
  return GOVERNANCE_DISCOVERY_EXCLUDED_DIR_NAMES.has(String(dirName).toLowerCase());
}

export function normalizeGovernancePathForMatching(inputPath: string): string {
  return String(inputPath).replace(/\\/g, '/').toLowerCase();
}

export function classifyGovernanceUnmanagedPath(
  inputPath: string,
  platform: NodeJS.Platform,
): { id: string; description: string } | null {
  const normalizedPath = normalizeGovernancePathForMatching(inputPath);
  for (const rule of GOVERNANCE_UNMANAGED_PATH_RULES) {
    if (!rule.platforms.includes(platform)) {
      continue;
    }
    if (rule.pattern.test(normalizedPath)) {
      return {
        id: rule.id,
        description: rule.description,
      };
    }
  }
  return null;
}

export function isAllowedProjectNpmrcKey(rawKey: string): boolean {
  const key = String(rawKey).trim();
  if (!key) {
    return false;
  }
  if (ALLOWED_PROJECT_NPMRC_GLOBAL_KEYS.has(key)) {
    return true;
  }

  const registryScopedMatch = key.match(/^\/\/.+[:/]([A-Za-z][A-Za-z0-9[\]_-]*)$/u);
  if (!registryScopedMatch) {
    return false;
  }
  const registrySuffix = registryScopedMatch[1];
  if (typeof registrySuffix !== 'string') {
    return false;
  }
  return ALLOWED_PROJECT_NPMRC_REGISTRY_KEY_SUFFIXES.has(registrySuffix);
}

export function isFortressExceptionSurfaceRule(property: string): boolean {
  return FORTRESS_EXCEPTION_SURFACE_RULES.includes(String(property));
}

export function isForbiddenProjectTokenHelperKey(rawKey: string): boolean {
  const key = String(rawKey).trim();
  return key === 'tokenHelper' || /[:/]tokenHelper$/u.test(key);
}

export function createReferenceGovernanceToolchainPolicy(): GovernanceToolchainPolicy {
  return {
    pnpm: {
      requiredVersion: REQUIRED_PNPM_VERSION,
      requiredMajor: REQUIRED_PNPM_MAJOR,
      latestVersion: null,
      minimumReleaseAgeMinutes: FORTRESS_MINIMUM_RELEASE_AGE_MINUTES,
      latestPublishedAt: null,
      requiredPublishedAt: null,
      releaseAgeCutoff: null,
      latestDeferredByMinimumReleaseAge: false,
      checkedAt: CURRENT_NODE_LTS.checkedAt,
      source: REFERENCE_TOOLCHAIN_SOURCE,
      liveResolved: false,
    },
    node: {
      minimumLtsVersion: CURRENT_NODE_LTS.version,
      minimumLtsMajor: CURRENT_NODE_LTS.major,
      latestVersion: null,
      latestMajor: null,
      checkedAt: CURRENT_NODE_LTS.checkedAt,
      source: CURRENT_NODE_LTS.source,
      ltsCodename: null,
      liveResolved: false,
    },
    warnings: [],
  };
}
