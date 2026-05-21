export const CURRENT_NODE_LTS = Object.freeze({
  version: '24.16.0',
  major: 24,
  checkedAt: '2026-05-21',
  source: 'https://nodejs.org/en/about/previous-releases',
});

export const REQUIRED_PNPM_MAJOR = 11;
export const PNPM_WORKSPACE_BASENAME = 'pnpm-workspace.yaml';
export const PNPM_LOCKFILE_BASENAME = 'pnpm-lock.yaml';
export const PROJECT_AUTH_FILE_BASENAMES = new Set(['.npmrc', 'auth.ini']);
export const MANIFEST_DEPENDENCY_SECTIONS = Object.freeze([
  'dependencies',
  'devDependencies',
  'optionalDependencies',
  'peerDependencies',
]);

export const GOVERNANCE_DISCOVERY_EXCLUDED_DIR_NAMES = new Set([
  '.git',
  '.hg',
  '.svn',
  '.next',
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
  ['minimumReleaseAge', 10080],
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
]);

export const SHARED_WORKSPACE_OBJECT_RULES = Object.freeze([
  'allowBuilds',
  'catalog',
  'overrides',
  'packageExtensions',
  'allowedDeprecatedVersions',
]);

export const MONOREPO_WORKSPACE_EXACT_RULES = Object.freeze([
  ['includeWorkspaceRoot', false],
  ['sharedWorkspaceLockfile', true],
  ['disallowWorkspaceCycles', true],
  ['failIfNoMatch', true],
  ['linkWorkspacePackages', false],
  ['preferWorkspacePackages', false],
  ['saveWorkspaceProtocol', true],
  ['savePrefix', ''],
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
  'savePrefix',
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
  'catalog',
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

export function isGovernanceDiscoveryExcludedDirName(dirName) {
  return GOVERNANCE_DISCOVERY_EXCLUDED_DIR_NAMES.has(String(dirName).toLowerCase());
}

export function isAllowedProjectNpmrcKey(rawKey) {
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
  return ALLOWED_PROJECT_NPMRC_REGISTRY_KEY_SUFFIXES.has(registryScopedMatch[1]);
}

export function isForbiddenProjectTokenHelperKey(rawKey) {
  const key = String(rawKey).trim();
  return key === 'tokenHelper' || /[:/]tokenHelper$/u.test(key);
}
