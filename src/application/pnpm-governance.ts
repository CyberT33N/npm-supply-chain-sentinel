import fs from 'node:fs';
import path from 'node:path';

import { minimatch } from 'minimatch';
import semver from 'semver';
import YAML from 'yaml';

import {
  GOVERNANCE_OWNER_SENTINEL_BASENAMES,
  MANIFEST_CATALOG_DEPENDENCY_SECTIONS,
  MANIFEST_DEPENDENCY_SECTIONS,
  MONOREPO_WORKSPACE_ARRAY_RULES,
  MONOREPO_WORKSPACE_EXACT_RULES,
  OFFICIAL_NPM_REGISTRY_URL,
  PNPM_LOCKFILE_BASENAME,
  PNPM_RECOMMENDED_SECURITY_PROPERTIES,
  PNPM_WORKSPACE_BASENAME,
  PROJECT_AUTH_FILE_BASENAMES,
  SECURITY_EXCEPTION_WORKSPACE_RULES,
  SHARED_WORKSPACE_EMPTY_ARRAY_RULES,
  SHARED_WORKSPACE_EMPTY_OBJECT_RULES,
  SHARED_WORKSPACE_EXACT_RULES,
  SHARED_WORKSPACE_OBJECT_RULES,
  SINGLE_PROJECT_FORBIDDEN_WORKSPACE_RULES,
  type GovernanceNodePolicy,
  type GovernancePnpmPolicy,
  type GovernanceToolchainPolicy,
  type NodeRuntimeContract,
  classifyGovernanceUnmanagedPath,
  createReferenceGovernanceToolchainPolicy,
  isAllowedProjectNpmrcKey,
  isFortressExceptionSurfaceRule,
  isForbiddenProjectTokenHelperKey,
  isGovernanceDiscoveryExcludedDirName,
} from '../domain/pnpm-governance';
import { SCAN_MODE_MACHINE } from '../domain/policy';
import {
  direntIsDirectory,
  fileExists,
  type JsonReadResult,
  normalizeForDisplay,
  normalizeSlashes,
  readFileTextSafe,
  readJsonSafe,
  statSafe,
} from '../infrastructure/fs-utils';
import { commandExists, runCommand } from '../infrastructure/process-utils';

const GITIGNORE_BASENAME = '.gitignore';
const NVMRC_BASENAME = '.nvmrc';
const PACKAGE_JSON_BASENAME = 'package.json';
const GOVERNANCE_DISCOVERY_REASON_UNMANAGED_PATH = 'unmanaged-path';
const GOVERNANCE_DISCOVERY_REASON_MISSING_OWNERSHIP = 'missing-ownership';
const EMBEDDED_RUNTIME_DEPENDENCY_NAMES = Object.freeze([
  'electron',
]);

type ScanMode = typeof SCAN_MODE_MACHINE | 'project';
type GovernanceDiscoveryReason =
  | typeof GOVERNANCE_DISCOVERY_REASON_UNMANAGED_PATH
  | typeof GOVERNANCE_DISCOVERY_REASON_MISSING_OWNERSHIP;
type GovernanceCheckStatus = 'ok' | 'warning' | 'missing' | 'invalid';
export type GovernanceCheckPresentationTone = 'default' | 'warning';
type GovernanceProjectKind = 'node-project' | 'unknown' | 'pnpm-monorepo' | 'pnpm-single-project';
type GovernanceRepoMode = 'single-project' | 'monorepo';
type GovernanceProjectStatus = 'passed' | 'failed' | 'warning';

interface ProjectAuthFileAuditTarget {
  filePath: string;
  inspectProperties: boolean;
}

const PROJECT_AUTH_LOCAL_POLICY_DRIFT_MESSAGE =
  'Keeping repository policy inside a gitignored auth-local file creates hidden machine-local behavior and confusing install drift across developers and CI.';

interface GovernanceOptions {
  mode?: ScanMode;
  includeTrash?: boolean;
}

interface RuntimeDetectionSuccess {
  available: true;
  version: string;
}

interface RuntimeDetectionFailure {
  available: false;
  warning: string;
}

type RuntimeDetection = RuntimeDetectionSuccess | RuntimeDetectionFailure;

export interface PnpmRuntimeInfo {
  available: boolean;
  version: string | null;
  major: number | null;
  requiredMajor: number;
  requiredVersion: string;
  matchesRequiredMajor: boolean;
  matchesRequiredVersion: boolean;
  warning: string | null;
}

interface GovernanceDiscoveryDecision {
  managed: boolean;
  reason?: GovernanceDiscoveryReason;
}

interface ProjectRootCandidateInfo {
  rootPath: string;
  hasPackageJson: boolean;
  hasWorkspaceFile: boolean;
}

export interface GovernanceDiscoverySummary {
  candidateRootCount: number;
  acceptedRootCount: number;
  suppressedRootCount: number;
  suppressedUnmanagedPathCount: number;
  suppressedMissingOwnershipCount: number;
}

interface RuntimeContract extends Record<string, unknown> {
  name?: unknown;
  version?: unknown;
  onFail?: unknown;
}

interface EnginesContract extends Record<string, unknown> {
  node?: unknown;
  pnpm?: unknown;
  runtime?: RuntimeContract;
}

interface DevEnginesContract extends Record<string, unknown> {
  runtime?: RuntimeContract;
  packageManager?: RuntimeContract;
}

interface ManifestLike extends Record<string, unknown> {
  packageManager?: unknown;
  devEngines?: DevEnginesContract;
  pnpm?: unknown;
  name?: unknown;
  engines?: EnginesContract;
  dependencies?: Record<string, unknown>;
  devDependencies?: Record<string, unknown>;
  optionalDependencies?: Record<string, unknown>;
  peerDependencies?: Record<string, unknown>;
}

interface WorkspaceConfig extends Record<string, unknown> {
  packages?: unknown;
}

interface YamlReadResult {
  rawText: string | null;
  value: unknown | null;
}

interface RuntimeContractAuditResult {
  present: boolean;
  exactVersion: string | null;
}

export interface GovernanceCheck {
  file: string;
  property: string;
  status: GovernanceCheckStatus;
  presentationTone: GovernanceCheckPresentationTone;
  expected: string | null;
  actual: string | null;
  message: string;
}

interface GovernanceCheckInput {
  file: string;
  property: string;
  status: GovernanceCheckStatus;
  presentationTone?: GovernanceCheckPresentationTone;
  expected?: string | null;
  actual?: string | null;
  message: string;
}

const WORKSPACE_POLICY_SURFACES = new Map<string, string>(buildWorkspacePolicySurfaceEntries());
const GLOBAL_PNPM_CONFIG_SURFACES = new Map<string, string>(buildNormalizedSurfaceEntries([
  ['httpsProxy', 'httpsProxy'],
  ['httpProxy', 'httpProxy'],
  ['noProxy', 'noProxy'],
  ['namedRegistries', 'namedRegistries'],
  ['nodeDownloadMirrors', 'nodeDownloadMirrors'],
  ['nodeMirror', 'nodeDownloadMirrors'],
  ['npmrcAuthFile', 'npmrcAuthFile'],
  ['localAddress', 'localAddress'],
  ['storeDir', 'storeDir'],
  ['cacheDir', 'cacheDir'],
  ['stateDir', 'stateDir'],
  ['sideEffectsCache', 'sideEffectsCache'],
  ['sideEffectsCacheReadonly', 'sideEffectsCacheReadonly'],
  ['supportedArchitectures', 'supportedArchitectures'],
  ['ignoredOptionalDependencies', 'ignoredOptionalDependencies'],
  ['configDependencies', 'configDependencies'],
  ['requiredScripts', 'requiredScripts'],
  ['tag', 'tag'],
  ['maxsockets', 'maxsockets'],
  ['networkConcurrency', 'networkConcurrency'],
  ['fetchRetries', 'fetchRetries'],
  ['fetchRetryFactor', 'fetchRetryFactor'],
  ['fetchRetryMintimeout', 'fetchRetryMintimeout'],
  ['fetchRetryMaxtimeout', 'fetchRetryMaxtimeout'],
  ['fetchTimeout', 'fetchTimeout'],
  ['fetchWarnTimeoutMs', 'fetchWarnTimeoutMs'],
  ['fetchMinSpeedKiBps', 'fetchMinSpeedKiBps'],
  ['shellEmulator', 'shellEmulator'],
  ['optimisticRepeatInstall', 'optimisticRepeatInstall'],
  ['modulesCacheMaxAge', 'modulesCacheMaxAge'],
  ['dlxCacheMaxAge', 'dlxCacheMaxAge'],
]));
const PACKAGE_JSON_TOOLCHAIN_SURFACES = new Map<string, string>(buildNormalizedSurfaceEntries([
  ['packageManager', 'packageManager'],
  ['engines.pnpm', 'engines.pnpm'],
  ['engines.runtime', 'engines.runtime'],
  ['engines.runtime.version', 'engines.runtime.version'],
  ['devEngines.runtime', 'devEngines.runtime'],
  ['devEngines.runtime.version', 'devEngines.runtime.version'],
  ['devEngines.packageManager', 'devEngines.packageManager'],
  ['devEngines.packageManager.version', 'devEngines.packageManager.version'],
  ['engines.node', 'engines.node'],
]));

export interface GovernanceProjectSummary {
  okCount: number;
  warningCount: number;
  missingCount: number;
  invalidCount: number;
}

export interface GovernanceProjectClassification {
  kind: GovernanceProjectKind;
  isPnpmProject: boolean;
  signals: string[];
  repoMode: GovernanceRepoMode;
}

export interface GovernanceWorkspaceMember {
  rootPath: string;
  packageJson: JsonReadResult;
}

export interface GovernanceProjectTopology {
  role: 'root' | 'nested-domain';
  parentRootPath: string | null;
  parentDisplayPath: string | null;
  lineageRootPaths: string[];
  lineageDisplayPaths: string[];
}

export interface GovernanceProjectFiles {
  packageJson: string | null;
  pnpmWorkspace: string | null;
  pnpmLockfile: string | null;
  npmrc: string | null;
  authIni: string | null;
  gitignore: string | null;
}

export interface GovernanceProjectReport {
  rootPath: string;
  displayPath: string;
  classification: GovernanceProjectClassification;
  files: GovernanceProjectFiles;
  checks: GovernanceCheck[];
  workspaceMembers: GovernanceWorkspaceMember[];
  status: GovernanceProjectStatus;
  summary: GovernanceProjectSummary;
  topology?: GovernanceProjectTopology;
}

export interface GovernanceAuditSummary {
  projectCount: number;
  rootProjectCount: number;
  nestedPnpmDomainCount: number;
  pnpmProjectCount: number;
  pnpmSingleProjectCount: number;
  pnpmMonorepoCount: number;
  standalonePnpmSingleProjectCount: number;
  rootPnpmMonorepoCount: number;
  nestedPnpmSingleProjectCount: number;
  nestedPnpmMonorepoCount: number;
  nonPnpmNodeProjectCount: number;
  passCount: number;
  failCount: number;
  warningCount: number;
  machineWarning: string | null;
}

export interface GovernanceAudit {
  pnpmRuntime: PnpmRuntimeInfo;
  nodeRuntimeContract: NodeRuntimeContract;
  toolchainPolicy: GovernanceToolchainPolicy;
  recommendedProperties: readonly string[];
  discovery: GovernanceDiscoverySummary;
  projects: GovernanceProjectReport[];
  summary: GovernanceAuditSummary;
}

function isObjectRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function toManifest(value: unknown): ManifestLike | null {
  return isObjectRecord(value) ? value : null;
}

function toWorkspaceConfig(value: unknown): WorkspaceConfig | null {
  return isObjectRecord(value) ? value : null;
}

export function inspectPnpmRuntime(
  pnpmPolicy: GovernancePnpmPolicy = createReferenceGovernanceToolchainPolicy().pnpm,
): PnpmRuntimeInfo {
  const runtime = detectPnpmRuntimeVersion(pnpmPolicy.requiredVersion);
  if (!runtime.available) {
    return {
      available: false,
      version: null,
      major: null,
      requiredMajor: pnpmPolicy.requiredMajor,
      requiredVersion: pnpmPolicy.requiredVersion,
      matchesRequiredMajor: false,
      matchesRequiredVersion: false,
      warning: runtime.warning ?? `pnpm is not installed on this machine. Install pnpm ${pnpmPolicy.requiredVersion} to activate Fortress governance settings.`,
    };
  }

  const versionText = runtime.version;
  const major = versionText ? semver.major(versionText) : null;
  return {
    available: true,
    version: versionText,
    major,
    requiredMajor: pnpmPolicy.requiredMajor,
    requiredVersion: pnpmPolicy.requiredVersion,
    matchesRequiredMajor: major === pnpmPolicy.requiredMajor,
    matchesRequiredVersion: versionText === pnpmPolicy.requiredVersion,
    warning:
      versionText === pnpmPolicy.requiredVersion
        ? null
        : buildPnpmRuntimePolicyMismatchMessage(versionText ?? 'unknown', pnpmPolicy),
  };
}

function detectPnpmRuntimeVersion(requiredVersion: string): RuntimeDetection {
  const candidates = process.platform === 'win32'
    ? [
        { command: 'cmd.exe', args: ['/d', '/s', '/c', 'pnpm --version'] },
        { command: 'cmd.exe', args: ['/d', '/s', '/c', 'corepack pnpm --version'] },
      ]
    : [
        { command: 'pnpm', args: ['--version'] },
        { command: 'corepack', args: ['pnpm', '--version'] },
      ];

  for (const candidate of candidates) {
    if (!commandExists(candidate.command, candidate.args)) {
      continue;
    }
    const result = runCommand(candidate.command, candidate.args);
    if (result.error || result.status !== 0) {
      continue;
    }
    const version = extractSemverFromText(`${result.stdout ?? ''}\n${result.stderr ?? ''}`);
    if (version) {
      return {
        available: true,
        version,
      };
    }
  }

  return {
    available: false,
    warning: `pnpm is not installed on this machine. Install pnpm ${requiredVersion} to activate Fortress governance settings.`,
  };
}

function buildPnpmRuntimePolicyMismatchMessage(
  installedVersion: string,
  pnpmPolicy: GovernancePnpmPolicy,
): string {
  if (
    pnpmPolicy.latestDeferredByMinimumReleaseAge
    && pnpmPolicy.latestVersion
    && pnpmPolicy.latestVersion !== pnpmPolicy.requiredVersion
  ) {
    return `pnpm ${installedVersion} is installed, but Fortress currently requires pnpm ${pnpmPolicy.requiredVersion}. The official latest release ${pnpmPolicy.latestVersion} is still inside the minimumReleaseAge window (published ${pnpmPolicy.latestPublishedAt ?? 'unknown'}, cutoff ${pnpmPolicy.releaseAgeCutoff ?? 'unknown'}).`;
  }

  return `pnpm ${installedVersion} is installed, but this policy expects pnpm ${pnpmPolicy.requiredVersion}.`;
}

function buildPnpmRequiredVersionMessage(
  subject: 'packageManager' | 'devEngines.packageManager.version',
  pnpmPolicy: GovernancePnpmPolicy,
): string {
  if (
    pnpmPolicy.latestDeferredByMinimumReleaseAge
    && pnpmPolicy.latestVersion
    && pnpmPolicy.latestVersion !== pnpmPolicy.requiredVersion
  ) {
    return `${subject} must pin PNPM ${pnpmPolicy.requiredVersion} exactly. The official latest PNPM release ${pnpmPolicy.latestVersion} was published at ${pnpmPolicy.latestPublishedAt ?? 'unknown'} and is still newer than the minimumReleaseAge cutoff ${pnpmPolicy.releaseAgeCutoff ?? 'unknown'}.`;
  }

  return `${subject} must pin PNPM ${pnpmPolicy.requiredVersion} exactly.`;
}

function extractSemverFromText(text: string): string | null {
  for (const rawLine of String(text).split(/\r?\n/u)) {
    const line = rawLine.trim();
    if (!line) {
      continue;
    }
    const direct = semver.valid(line);
    if (direct) {
      return direct;
    }
    const coerced = semver.coerce(line)?.version;
    if (coerced) {
      return coerced;
    }
  }
  return null;
}

export function auditPnpmGovernance(
  rootPaths: readonly string[],
  options: GovernanceOptions = {},
  pnpmRuntime: PnpmRuntimeInfo = inspectPnpmRuntime(),
  toolchainPolicy: GovernanceToolchainPolicy = createReferenceGovernanceToolchainPolicy(),
): GovernanceAudit {
  const discovery = discoverProjectRoots(rootPaths, options);
  const auditedProjects = discovery.projectRoots
    .map((rootPath) => auditProjectRoot(rootPath, options, pnpmRuntime, toolchainPolicy))
    .sort((left, right) => left.rootPath.localeCompare(right.rootPath));
  const projects = attachProjectTopology(collapseWorkspaceMembers(auditedProjects));

  return {
    pnpmRuntime,
    nodeRuntimeContract: buildNodeRuntimeContract(toolchainPolicy.node),
    toolchainPolicy,
    recommendedProperties: PNPM_RECOMMENDED_SECURITY_PROPERTIES,
    discovery: discovery.summary,
    projects,
    summary: summarizeGovernance(projects, pnpmRuntime),
  };
}

function buildNodeRuntimeContract(nodePolicy: GovernanceNodePolicy): NodeRuntimeContract {
  return {
    version: nodePolicy.minimumLtsVersion,
    major: nodePolicy.minimumLtsMajor,
    checkedAt: nodePolicy.checkedAt,
    source: nodePolicy.source,
  };
}

function discoverProjectRoots(
  rootPaths: readonly string[],
  options: GovernanceOptions,
): { projectRoots: string[]; summary: GovernanceDiscoverySummary } {
  const discovered = new Map<string, ProjectRootCandidateInfo>();
  const visited = new Set<string>();
  const scanRoots = [...new Set(rootPaths.map((rootPath) => path.resolve(rootPath)))];
  const explicitScanRoots = new Set(scanRoots);
  const stack: string[] = [...scanRoots];

  while (stack.length > 0) {
    const current = stack.pop();
    if (typeof current !== 'string') {
      continue;
    }
    const currentStats = statSafe(current);
    if (!currentStats?.isDirectory()) {
      continue;
    }
    if (shouldSkipGovernancePath(current, options, explicitScanRoots)) {
      continue;
    }

    const realCurrent = safeRealpath(current);
    if (visited.has(realCurrent)) {
      continue;
    }
    visited.add(realCurrent);

    const candidateInfo = getProjectRootCandidateInfo(current);
    if (candidateInfo) {
      discovered.set(candidateInfo.rootPath, candidateInfo);
    }

    let entries = [];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      if (!direntIsDirectory(entry, fullPath)) {
        continue;
      }
      if (isDirectorySymlink(fullPath)) {
        continue;
      }
      if (shouldSkipGovernanceDirectory(entry.name, options)) {
        continue;
      }
      if (shouldSkipGovernancePath(fullPath, options, explicitScanRoots)) {
        continue;
      }
      stack.push(fullPath);
    }
  }

  const candidateRoots = [...discovered.keys()].sort((left, right) => left.localeCompare(right));
  const baseDecisions = new Map<string, GovernanceDiscoveryDecision>();
  const acceptedRoots = new Set<string>();

  for (const candidateRoot of candidateRoots) {
    const decision = classifyGovernanceCandidateRoot(candidateRoot, explicitScanRoots, options);
    baseDecisions.set(candidateRoot, decision);
    if (decision.managed) {
      acceptedRoots.add(candidateRoot);
    }
  }

  promoteNestedWorkspaceDomains(candidateRoots, discovered, acceptedRoots);

  const projectRoots: string[] = [];
  const suppressedCounts = {
    unmanagedPathCount: 0,
    missingOwnershipCount: 0,
  };

  for (const candidateRoot of candidateRoots) {
    if (acceptedRoots.has(candidateRoot)) {
      projectRoots.push(candidateRoot);
      continue;
    }
    const decision = baseDecisions.get(candidateRoot);
    if (decision?.reason === GOVERNANCE_DISCOVERY_REASON_UNMANAGED_PATH) {
      suppressedCounts.unmanagedPathCount += 1;
      continue;
    }
    suppressedCounts.missingOwnershipCount += 1;
  }

  return {
    projectRoots,
    summary: {
      candidateRootCount: candidateRoots.length,
      acceptedRootCount: projectRoots.length,
      suppressedRootCount: candidateRoots.length - projectRoots.length,
      suppressedUnmanagedPathCount: suppressedCounts.unmanagedPathCount,
      suppressedMissingOwnershipCount: suppressedCounts.missingOwnershipCount,
    },
  };
}

function getProjectRootCandidateInfo(rootPath: string): ProjectRootCandidateInfo | null {
  const resolvedRootPath = path.resolve(rootPath);
  const hasPackageJson = fileExists(path.join(resolvedRootPath, PACKAGE_JSON_BASENAME));
  const hasWorkspaceFile = fileExists(path.join(resolvedRootPath, PNPM_WORKSPACE_BASENAME));
  if (!hasPackageJson && !hasWorkspaceFile) {
    return null;
  }
  return {
    rootPath: resolvedRootPath,
    hasPackageJson,
    hasWorkspaceFile,
  };
}

function shouldSkipGovernanceDirectory(dirName: string, options: GovernanceOptions): boolean {
  const lowered = String(dirName).toLowerCase();
  if (isGovernanceDiscoveryExcludedDirName(lowered)) {
    return true;
  }
  if (
    options.mode === SCAN_MODE_MACHINE &&
    !options.includeTrash &&
    lowered === '$recycle.bin'
  ) {
    return true;
  }
  return false;
}

function shouldSkipGovernancePath(
  fullPath: string,
  options: GovernanceOptions,
  explicitScanRoots: ReadonlySet<string>,
): boolean {
  if (options.mode !== SCAN_MODE_MACHINE) {
    return false;
  }
  const resolvedPath = path.resolve(fullPath);
  if (explicitScanRoots.has(resolvedPath)) {
    return false;
  }
  if (hasGovernanceOwnershipSignal(resolvedPath)) {
    return false;
  }
  return Boolean(classifyGovernanceUnmanagedPath(resolvedPath, process.platform));
}

function classifyGovernanceCandidateRoot(
  rootPath: string,
  explicitScanRoots: ReadonlySet<string>,
  options: GovernanceOptions,
): GovernanceDiscoveryDecision {
  if (options.mode === SCAN_MODE_MACHINE) {
    if (hasGovernanceOwnershipSignal(rootPath)) {
      return {
        managed: true,
      };
    }
    if (classifyGovernanceUnmanagedPath(rootPath, process.platform)) {
      return {
        managed: false,
        reason: GOVERNANCE_DISCOVERY_REASON_UNMANAGED_PATH,
      };
    }
    return {
      managed: false,
      reason: GOVERNANCE_DISCOVERY_REASON_MISSING_OWNERSHIP,
    };
  }

  if (explicitScanRoots.has(path.resolve(rootPath)) || hasGovernanceOwnershipSignal(rootPath)) {
    return {
      managed: true,
    };
  }
  return {
    managed: false,
    reason: GOVERNANCE_DISCOVERY_REASON_MISSING_OWNERSHIP,
  };
}

function hasGovernanceOwnershipSignal(rootPath: string): boolean {
  return GOVERNANCE_OWNER_SENTINEL_BASENAMES.some((basename) =>
    fileExists(path.join(rootPath, basename)),
  );
}

function promoteNestedWorkspaceDomains(
  candidateRoots: readonly string[],
  candidateInfoByPath: ReadonlyMap<string, ProjectRootCandidateInfo>,
  acceptedRoots: Set<string>,
): void {
  let changed = true;
  while (changed) {
    changed = false;
    for (const candidateRoot of candidateRoots) {
      if (acceptedRoots.has(candidateRoot)) {
        continue;
      }
      const candidateInfo = candidateInfoByPath.get(candidateRoot);
      if (!candidateInfo?.hasWorkspaceFile) {
        continue;
      }
      if (!findNearestAcceptedWorkspaceAncestor(candidateRoot, acceptedRoots, candidateInfoByPath)) {
        continue;
      }
      acceptedRoots.add(candidateRoot);
      changed = true;
    }
  }
}

function findNearestAcceptedWorkspaceAncestor(
  candidateRoot: string,
  acceptedRoots: ReadonlySet<string>,
  candidateInfoByPath: ReadonlyMap<string, ProjectRootCandidateInfo>,
): string | null {
  let nearestAncestor = null;
  for (const acceptedRoot of acceptedRoots) {
    if (acceptedRoot === candidateRoot) {
      continue;
    }
    if (!isPathInside(candidateRoot, acceptedRoot)) {
      continue;
    }
    if (!candidateInfoByPath.get(acceptedRoot)?.hasWorkspaceFile) {
      continue;
    }
    if (!nearestAncestor || depthOf(acceptedRoot) > depthOf(nearestAncestor)) {
      nearestAncestor = acceptedRoot;
    }
  }
  return nearestAncestor;
}

function collapseWorkspaceMembers(projects: readonly GovernanceProjectReport[]): GovernanceProjectReport[] {
  const accepted: GovernanceProjectReport[] = [];
  const monorepos: GovernanceProjectReport[] = [];

  for (const project of [...projects].sort((left, right) => depthOf(left.rootPath) - depthOf(right.rootPath))) {
    const parentMonorepo = monorepos.find((candidate) =>
      isWorkspaceMemberProject(project.rootPath, candidate),
    );
    if (parentMonorepo && !project.files.pnpmWorkspace) {
      continue;
    }

    accepted.push(project);
    if (project.classification.kind === 'pnpm-monorepo') {
      monorepos.push(project);
    }
  }

  return accepted.sort((left, right) => left.rootPath.localeCompare(right.rootPath));
}

function attachProjectTopology(projects: readonly GovernanceProjectReport[]): GovernanceProjectReport[] {
  const withTopology: GovernanceProjectReport[] = [];
  for (const project of [...projects].sort((left, right) => depthOf(left.rootPath) - depthOf(right.rootPath))) {
    const parentProject = findNearestAcceptedAncestorProject(project.rootPath, withTopology);
    withTopology.push({
      ...project,
      topology: buildProjectTopology(project, parentProject),
    });
  }
  return withTopology.sort((left, right) => left.rootPath.localeCompare(right.rootPath));
}

function findNearestAcceptedAncestorProject(
  projectRootPath: string,
  projects: readonly GovernanceProjectReport[],
): GovernanceProjectReport | null {
  let nearestAncestor: GovernanceProjectReport | null = null;
  for (const project of projects) {
    if (project.rootPath === projectRootPath) {
      continue;
    }
    if (!isPathInside(projectRootPath, project.rootPath)) {
      continue;
    }
    if (!nearestAncestor || depthOf(project.rootPath) > depthOf(nearestAncestor.rootPath)) {
      nearestAncestor = project;
    }
  }
  return nearestAncestor;
}

function buildProjectTopology(
  project: GovernanceProjectReport,
  parentProject: GovernanceProjectReport | null,
): GovernanceProjectTopology {
  const role = parentProject ? 'nested-domain' : 'root';
  const parentTopology = parentProject?.topology;
  const lineageRootPaths = parentTopology
    ? [...parentTopology.lineageRootPaths, project.rootPath]
    : [project.rootPath];
  const lineageDisplayPaths = parentTopology
    ? [...parentTopology.lineageDisplayPaths, project.displayPath]
    : [project.displayPath];

  return {
    role,
    parentRootPath: parentProject?.rootPath ?? null,
    parentDisplayPath: parentProject?.displayPath ?? null,
    lineageRootPaths,
    lineageDisplayPaths,
  };
}

function isWorkspaceMemberProject(projectRootPath: string, monorepoProject: GovernanceProjectReport): boolean {
  if (!isPathInside(projectRootPath, monorepoProject.rootPath)) {
    return false;
  }
  return (monorepoProject.workspaceMembers ?? []).some((member) => member.rootPath === projectRootPath);
}

function auditProjectRoot(
  rootPath: string,
  _options: GovernanceOptions,
  pnpmRuntime: PnpmRuntimeInfo,
  toolchainPolicy: GovernanceToolchainPolicy,
): GovernanceProjectReport {
  const packageJsonPath = path.join(rootPath, PACKAGE_JSON_BASENAME);
  const workspacePath = path.join(rootPath, PNPM_WORKSPACE_BASENAME);
  const pnpmLockfilePath = path.join(rootPath, PNPM_LOCKFILE_BASENAME);
  const npmrcPath = path.join(rootPath, '.npmrc');
  const authIniPath = path.join(rootPath, 'auth.ini');
  const gitignorePath = path.join(rootPath, GITIGNORE_BASENAME);

  const packageJson = readJsonSafe(packageJsonPath);
  const workspaceDocument = readYamlSafe(workspacePath);
  const checks: GovernanceCheck[] = [];
  const workspaceMembers: GovernanceWorkspaceMember[] = [];

  if (fileExists(packageJsonPath) && !packageJson.value) {
    pushCheck(checks, {
      file: PACKAGE_JSON_BASENAME,
      property: PACKAGE_JSON_BASENAME,
      status: 'invalid',
      message: `${PACKAGE_JSON_BASENAME} could not be parsed as JSON.`,
    });
  }
  if (fileExists(workspacePath) && !workspaceDocument.value) {
    pushCheck(checks, {
      file: PNPM_WORKSPACE_BASENAME,
      property: PNPM_WORKSPACE_BASENAME,
      status: 'invalid',
      message: `${PNPM_WORKSPACE_BASENAME} could not be parsed as YAML.`,
    });
  }

  const classification = classifyProject(rootPath, packageJson.value, workspaceDocument, pnpmLockfilePath);

  if (classification.isPnpmProject) {
    const workspaceConfig = toWorkspaceConfig(workspaceDocument.value);
    if (classification.kind === 'pnpm-monorepo' && workspaceDocument.value) {
      const members = discoverWorkspaceMembers(rootPath, workspaceConfig?.packages);
      workspaceMembers.push(...members);
    }

    auditPnpmRuntime(checks, pnpmRuntime);
    auditWorkspaceFile(checks, classification, workspaceDocument, pnpmRuntime.requiredMajor);
    auditRootPackageJson(
      checks,
      packageJson,
      classification,
      rootPath,
      workspaceMembers,
      toolchainPolicy.pnpm,
    );
    auditForbiddenNvmrcFiles(checks, rootPath);
    if (
      classification.repoMode === 'single-project'
      && !detectEmbeddedRuntimeDependency(toManifest(packageJson.value))
    ) {
      auditRuntimeIdentityContract(checks, packageJson.value, workspaceConfig);
      auditNodeRuntimeVersionPolicy(checks, packageJson.value, workspaceConfig, toolchainPolicy.node);
    }
    auditLockfile(checks, pnpmLockfilePath);
    auditProjectAuthFiles(checks, gitignorePath, [
      {
        filePath: npmrcPath,
        inspectProperties: true,
      },
      {
        filePath: authIniPath,
        inspectProperties: false,
      },
    ]);

    if (classification.kind === 'pnpm-monorepo' && workspaceDocument.value) {
      auditWorkspaceMembers(checks, workspaceMembers);
    }
  } else {
    pushCheck(checks, {
      file: PACKAGE_JSON_BASENAME,
      property: 'packageManager',
      status: 'warning',
      message: `Node project at ${normalizeForDisplay(rootPath)} is not governed by PNPM ${pnpmRuntime.requiredMajor}.x Fortress settings.`,
    });
  }

  const summary = summarizeProjectChecks(checks);
  return {
    rootPath: path.resolve(rootPath),
    displayPath: normalizeForDisplay(rootPath),
    classification,
    files: {
      packageJson: fileExists(packageJsonPath) ? packageJsonPath : null,
      pnpmWorkspace: fileExists(workspacePath) ? workspacePath : null,
      pnpmLockfile: fileExists(pnpmLockfilePath) ? pnpmLockfilePath : null,
      npmrc: fileExists(npmrcPath) ? npmrcPath : null,
      authIni: fileExists(authIniPath) ? authIniPath : null,
      gitignore: fileExists(gitignorePath) ? gitignorePath : null,
    },
    checks,
    workspaceMembers,
    status: classifyAuditStatus(classification, summary),
    summary,
  };
}

function classifyProject(
  rootPath: string,
  packageJson: unknown,
  workspaceDocument: YamlReadResult,
  pnpmLockfilePath: string,
): GovernanceProjectClassification {
  const signals: string[] = [];
  const workspaceRawText = workspaceDocument.rawText ?? '';
  const manifest = toManifest(packageJson);
  const hasWorkspaceFile = fileExists(path.join(rootPath, PNPM_WORKSPACE_BASENAME));
  const hasPackageJson = fileExists(path.join(rootPath, PACKAGE_JSON_BASENAME));
  const packageManagerField = typeof manifest?.packageManager === 'string' ? manifest.packageManager : null;
  const devEnginePackageManager = manifest?.devEngines?.packageManager;
  const hasPnpmLockfile = fileExists(pnpmLockfilePath);

  if (hasWorkspaceFile) {
    signals.push('pnpm-workspace');
  }
  if (packageManagerField?.startsWith('pnpm@')) {
    signals.push('packageManager');
  }
  if (devEnginePackageManager?.name === 'pnpm') {
    signals.push('devEngines.packageManager');
  }
  if (hasPnpmLockfile) {
    signals.push(PNPM_LOCKFILE_BASENAME);
  }

  const isPnpmProject = signals.length > 0;
  if (!isPnpmProject) {
    return {
      kind: hasPackageJson ? 'node-project' : 'unknown',
      isPnpmProject: false,
      signals,
      repoMode: 'single-project',
    };
  }

  const workspaceValue = toWorkspaceConfig(workspaceDocument.value);
  const looksLikeMonorepo = Array.isArray(workspaceValue?.packages)
    || workspaceRawText.includes('\npackages:')
    || workspaceRawText.startsWith('packages:');

  return {
    kind: looksLikeMonorepo ? 'pnpm-monorepo' : 'pnpm-single-project',
    isPnpmProject: true,
    signals,
    repoMode: looksLikeMonorepo ? 'monorepo' : 'single-project',
  };
}

function auditPnpmRuntime(checks: GovernanceCheck[], pnpmRuntime: PnpmRuntimeInfo): void {
  if (!pnpmRuntime.available) {
    pushCheck(checks, {
      file: 'machine',
      property: 'pnpm',
      status: 'warning',
      expected: `pnpm ${pnpmRuntime.requiredVersion} installed`,
      actual: 'missing',
      message: pnpmRuntime.warning ?? `pnpm ${pnpmRuntime.requiredVersion} is not installed on this machine.`,
    });
    return;
  }

  pushCheck(checks, {
    file: 'machine',
    property: 'pnpm',
    status: pnpmRuntime.matchesRequiredVersion ? 'ok' : 'warning',
    expected: `pnpm ${pnpmRuntime.requiredVersion}`,
    actual: pnpmRuntime.version ?? 'unknown',
    message: pnpmRuntime.matchesRequiredVersion
      ? `pnpm ${pnpmRuntime.version} is installed on this machine.`
      : pnpmRuntime.warning ?? `pnpm ${pnpmRuntime.requiredVersion} is required on this machine.`,
  });
}

function auditWorkspaceFile(
  checks: GovernanceCheck[],
  classification: GovernanceProjectClassification,
  workspaceDocument: YamlReadResult,
  requiredPnpmMajor: number,
): void {
  if (!workspaceDocument.value) {
    if (!workspaceDocument.rawText) {
      pushCheck(checks, {
        file: PNPM_WORKSPACE_BASENAME,
        property: PNPM_WORKSPACE_BASENAME,
        status: 'missing',
        message: `${PNPM_WORKSPACE_BASENAME} is required for PNPM ${requiredPnpmMajor}.x governance.`,
      });
    }
    return;
  }

  const workspace = toWorkspaceConfig(workspaceDocument.value);
  if (!workspace) {
    return;
  }

  for (const [property, expected] of SHARED_WORKSPACE_EXACT_RULES) {
    if (typeof property !== 'string') {
      continue;
    }
    if (property === 'minimumReleaseAge') {
      auditNumericMinimum(checks, workspace, PNPM_WORKSPACE_BASENAME, property, 10080, '10080 or stronger');
      continue;
    }
    if (property === 'virtualStoreDirMaxLength') {
      auditNumericMaximum(checks, workspace, PNPM_WORKSPACE_BASENAME, property, 60, '60 or lower');
      continue;
    }
    pushEqualityCheck(checks, workspace, PNPM_WORKSPACE_BASENAME, property, expected);
  }

  auditExactSemverString(checks, workspace, PNPM_WORKSPACE_BASENAME, 'nodeVersion');
  auditHttpsRegistry(checks, workspace, PNPM_WORKSPACE_BASENAME, 'registries.default');

  for (const property of SHARED_WORKSPACE_EMPTY_ARRAY_RULES) {
    auditEmptyArray(checks, workspace, PNPM_WORKSPACE_BASENAME, property);
  }
  for (const property of SHARED_WORKSPACE_EMPTY_OBJECT_RULES) {
    auditEmptyObject(checks, workspace, PNPM_WORKSPACE_BASENAME, property);
  }
  auditTrustPolicyExcludeExactVersionSelectors(checks, workspace);
  auditTrustPolicyExcludeResponseOrderWarning(checks, workspace);
  auditOverridesNarrowSelectors(checks, workspace);
  auditOverridesExactVersionTargets(checks, workspace);
  for (const property of SHARED_WORKSPACE_OBJECT_RULES) {
    auditObjectSurface(checks, workspace, PNPM_WORKSPACE_BASENAME, property);
  }
  auditAllowBuildsSurface(checks, workspace);
  auditCatalogExactVersions(checks, workspace);

  for (const property of SECURITY_EXCEPTION_WORKSPACE_RULES) {
    const actual = getNestedValue(workspace, property);
    if (actual !== undefined) {
      pushCheck(checks, {
        file: PNPM_WORKSPACE_BASENAME,
        property,
        status: 'invalid',
        expected: 'unset',
        actual: formatValue(actual),
        message: `${property} weakens the trust gate and should stay unset in Fortress mode.`,
      });
    } else {
      pushCheck(checks, {
        file: PNPM_WORKSPACE_BASENAME,
        property,
        status: 'ok',
        expected: 'unset',
        actual: 'unset',
        message: `${property} is not configured.`,
      });
    }
  }

  if (classification.kind === 'pnpm-single-project') {
    for (const property of SINGLE_PROJECT_FORBIDDEN_WORKSPACE_RULES) {
      const actual = getNestedValue(workspace, property);
      if (actual === undefined) {
        pushCheck(checks, {
          file: PNPM_WORKSPACE_BASENAME,
          property,
          status: 'ok',
          expected: 'unset',
          actual: 'unset',
          message: `${property} is correctly omitted in a single-project repo.`,
        });
        continue;
      }
      pushCheck(checks, {
        file: PNPM_WORKSPACE_BASENAME,
        property,
        status: 'invalid',
        expected: 'unset',
        actual: formatValue(actual),
        message: `${property} is monorepo-specific and should not be configured for a single-project repository.`,
      });
    }
    return;
  }

  for (const [property, expected] of MONOREPO_WORKSPACE_EXACT_RULES) {
    if (typeof property !== 'string') {
      continue;
    }
    pushEqualityCheck(checks, workspace, PNPM_WORKSPACE_BASENAME, property, expected);
  }
  for (const property of MONOREPO_WORKSPACE_ARRAY_RULES) {
    if (property === 'packages') {
      auditNonEmptyArray(checks, workspace, PNPM_WORKSPACE_BASENAME, property);
      continue;
    }
    auditArraySurface(checks, workspace, PNPM_WORKSPACE_BASENAME, property);
  }
}

function auditRootPackageJson(
  checks: GovernanceCheck[],
  packageJson: JsonReadResult,
  classification: GovernanceProjectClassification,
  rootPath: string,
  workspaceMembers: readonly GovernanceWorkspaceMember[],
  pnpmPolicy: GovernancePnpmPolicy,
): void {
  if (!packageJson.rawText) {
    pushCheck(checks, {
      file: PACKAGE_JSON_BASENAME,
      property: PACKAGE_JSON_BASENAME,
      status: 'missing',
      message: `${PACKAGE_JSON_BASENAME} is required at the project root.`,
    });
    return;
  }

  if (!packageJson.value) {
    return;
  }

  const manifest = toManifest(packageJson.value);
  if (!manifest) {
    return;
  }
  const embeddedRuntimeDependency = detectEmbeddedRuntimeDependency(manifest);
  auditPackageManagerField(checks, manifest, pnpmPolicy);
  auditEnginesNode(checks, manifest);
  auditEnginesPnpm(checks, manifest);
  auditRuntimeSurfaceGovernance(
    checks,
    manifest,
    PACKAGE_JSON_BASENAME,
    classification.repoMode,
    embeddedRuntimeDependency,
  );
  auditDevPackageManager(checks, manifest, pnpmPolicy);
  const workspaceNameToRoot = buildWorkspaceNameToRootMap(workspaceMembers);
  auditWorkspaceProtocolUsage(checks, manifest, rootPath, workspaceNameToRoot);
  auditCatalogDependencyUsage(checks, manifest, rootPath, workspaceNameToRoot);

  if (manifest.pnpm !== undefined) {
    pushCheck(checks, {
      file: PACKAGE_JSON_BASENAME,
      property: 'pnpm',
      status: 'invalid',
      message: 'PNPM no longer reads settings from package.json#pnpm. Move policy into pnpm-workspace.yaml.',
    });
  } else {
    pushCheck(checks, {
      file: PACKAGE_JSON_BASENAME,
      property: 'pnpm',
      status: 'ok',
      expected: 'unset',
      actual: 'unset',
      message: 'package.json#pnpm is not used.',
    });
  }

  if (classification.kind === 'pnpm-monorepo' && typeof manifest.name !== 'string') {
    pushCheck(checks, {
      file: PACKAGE_JSON_BASENAME,
      property: 'name',
      status: 'warning',
      message: 'The monorepo root package.json should define a root package name for clearer governance and tooling identity.',
    });
  }
}

function auditPackageManagerField(
  checks: GovernanceCheck[],
  manifest: ManifestLike,
  pnpmPolicy: GovernancePnpmPolicy,
): void {
  const rawValue = manifest.packageManager;
  if (typeof rawValue !== 'string') {
    pushCheck(checks, {
      file: PACKAGE_JSON_BASENAME,
      property: 'packageManager',
      status: 'missing',
      expected: `pnpm@${pnpmPolicy.requiredVersion}`,
      message: buildPnpmRequiredVersionMessage('packageManager', pnpmPolicy),
    });
    return;
  }

  const match = rawValue.match(/^pnpm@(.+)$/u);
  if (!match) {
    pushCheck(checks, {
      file: PACKAGE_JSON_BASENAME,
      property: 'packageManager',
      status: 'invalid',
      expected: `pnpm@${pnpmPolicy.requiredVersion}`,
      actual: rawValue,
      message: 'packageManager must point to pnpm.',
    });
    return;
  }

  const matchedVersion = match[1];
  const version = typeof matchedVersion === 'string' ? semver.valid(matchedVersion) : null;
  if (!version) {
    pushCheck(checks, {
      file: PACKAGE_JSON_BASENAME,
      property: 'packageManager',
      status: 'invalid',
      expected: `pnpm@${pnpmPolicy.requiredVersion}`,
      actual: rawValue,
      message: 'packageManager must pin an exact PNPM semver version.',
    });
    return;
  }

  if (version !== pnpmPolicy.requiredVersion) {
    pushCheck(checks, {
      file: PACKAGE_JSON_BASENAME,
      property: 'packageManager',
      status: 'invalid',
      expected: `pnpm@${pnpmPolicy.requiredVersion}`,
      actual: rawValue,
      message: buildPnpmRequiredVersionMessage('packageManager', pnpmPolicy),
    });
    return;
  }

  pushCheck(checks, {
    file: PACKAGE_JSON_BASENAME,
    property: 'packageManager',
    status: 'ok',
    expected: `pnpm@${pnpmPolicy.requiredVersion}`,
    actual: rawValue,
    message: `packageManager pins ${rawValue}.`,
  });
}

function auditEnginesNode(checks: GovernanceCheck[], manifest: ManifestLike): void {
  const enginesNode = manifest?.engines?.node;
  if (enginesNode === undefined) {
    pushCheck(checks, {
      file: PACKAGE_JSON_BASENAME,
      property: 'engines.node',
      status: 'ok',
      expected: 'unset',
      actual: 'unset',
      message: 'engines.node is intentionally unset so the root engine gate stays anchored in pnpm-workspace.yaml#nodeVersion and any deliberate root devEngines.runtime contract.',
    });
    return;
  }

  pushCheck(checks, {
    file: PACKAGE_JSON_BASENAME,
    property: 'engines.node',
    status: 'invalid',
    expected: 'unset',
    actual: formatValue(enginesNode),
    message: 'engines.node must stay unset by default. Treat it only as an explicit compatibility contract, never as a parallel root runtime authority.',
  });
}

function auditEnginesPnpm(checks: GovernanceCheck[], manifest: ManifestLike): void {
  const enginesPnpm = manifest?.engines?.pnpm;
  if (enginesPnpm === undefined) {
    pushCheck(checks, {
      file: PACKAGE_JSON_BASENAME,
      property: 'engines.pnpm',
      status: 'ok',
      expected: 'unset',
      actual: 'unset',
      message: 'engines.pnpm is intentionally unset because packageManager and devEngines.packageManager already define the PNPM control plane.',
    });
    return;
  }

  pushCheck(checks, {
    file: PACKAGE_JSON_BASENAME,
    property: 'engines.pnpm',
    status: 'invalid',
    expected: 'unset',
    actual: formatValue(enginesPnpm),
    message: 'engines.pnpm must stay unset. The PNPM control plane belongs in packageManager and devEngines.packageManager, not in a third compatibility surface.',
  });
}

function auditRuntimeSurfaceGovernance(
  checks: GovernanceCheck[],
  manifest: ManifestLike,
  manifestFile: string,
  repoMode: GovernanceRepoMode,
  embeddedRuntimeDependency: string | null,
): void {
  const enginesRuntime = manifest?.engines?.runtime;
  const devRuntime = manifest?.devEngines?.runtime;
  if (embeddedRuntimeDependency) {
    auditForbiddenEmbeddedRuntimeSurface(
      checks,
      manifestFile,
      'engines.runtime',
      enginesRuntime,
      embeddedRuntimeDependency,
    );
    auditForbiddenEmbeddedRuntimeSurface(
      checks,
      manifestFile,
      'devEngines.runtime',
      devRuntime,
      embeddedRuntimeDependency,
    );
    return;
  }

  const enginesRuntimeAudit = auditRuntimeContractSurface(
    checks,
    manifestFile,
    'engines.runtime',
    enginesRuntime,
  );
  const devRuntimeAudit = auditRuntimeContractSurface(
    checks,
    manifestFile,
    'devEngines.runtime',
    devRuntime,
    {
      required: enginesRuntime !== undefined,
      requiredMessage: 'devEngines.runtime must also be declared when engines.runtime is set.',
    },
  );

  if (enginesRuntimeAudit.present && devRuntimeAudit.exactVersion) {
    const enginesRuntimeExactVersion = enginesRuntimeAudit.exactVersion;
    if (!enginesRuntimeExactVersion) {
      return;
    }
    if (enginesRuntimeExactVersion !== devRuntimeAudit.exactVersion) {
      pushCheck(checks, {
        file: manifestFile,
        property: 'engines.runtime.version = devEngines.runtime.version',
        status: 'invalid',
        expected: 'same exact semver in both runtime surfaces',
        actual: `${enginesRuntimeExactVersion} vs ${devRuntimeAudit.exactVersion}`,
        message: 'engines.runtime.version and devEngines.runtime.version must remain identical when both runtime surfaces are declared.',
      });
      return;
    }

    pushCheck(checks, {
      file: manifestFile,
      property: 'engines.runtime.version = devEngines.runtime.version',
      status: 'ok',
      expected: 'same exact semver in both runtime surfaces',
      actual: enginesRuntimeExactVersion,
      message: `engines.runtime.version and devEngines.runtime.version are aligned on ${enginesRuntimeExactVersion}.`,
    });
  }

  if (repoMode === 'monorepo') {
    return;
  }
}

function auditRuntimeContractSurface(
  checks: GovernanceCheck[],
  manifestFile: string,
  propertyPrefix: 'devEngines.runtime' | 'engines.runtime',
  surfaceValue: unknown,
  options: {
    required?: boolean;
    requiredMessage?: string;
  } = {},
): RuntimeContractAuditResult {
  if (surfaceValue === undefined) {
    if (options.required) {
      pushCheck(checks, {
        file: manifestFile,
        property: propertyPrefix,
        status: 'missing',
        message: options.requiredMessage ?? `${propertyPrefix} must be declared.`,
      });
    }
    return {
      present: false,
      exactVersion: null,
    };
  }

  if (!isPlainObject(surfaceValue)) {
    pushCheck(checks, {
      file: manifestFile,
      property: propertyPrefix,
      status: 'invalid',
      expected: 'runtime contract object',
      actual: formatValue(surfaceValue),
      message: `${propertyPrefix} must be an object with name, version, and onFail.`,
    });
    return {
      present: true,
      exactVersion: null,
    };
  }

  const runtime = surfaceValue;
  if (runtime['name'] !== 'node') {
    pushCheck(checks, {
      file: manifestFile,
      property: `${propertyPrefix}.name`,
      status: 'invalid',
      expected: 'node',
      actual: formatValue(runtime['name']),
      message: `${propertyPrefix}.name must be "node".`,
    });
  } else {
    pushCheck(checks, {
      file: manifestFile,
      property: `${propertyPrefix}.name`,
      status: 'ok',
      expected: 'node',
      actual: 'node',
      message: `${propertyPrefix}.name is node.`,
    });
  }

  let exactVersion: string | null = null;
  const version = typeof runtime['version'] === 'string' ? runtime['version'] : null;
  if (!version) {
    pushCheck(checks, {
      file: manifestFile,
      property: `${propertyPrefix}.version`,
      status: 'missing',
      expected: 'exact semver string',
      message: `${propertyPrefix}.version must be declared.`,
    });
  } else {
    exactVersion = semver.valid(version);
    if (!exactVersion) {
      pushCheck(checks, {
        file: manifestFile,
        property: `${propertyPrefix}.version`,
        status: 'invalid',
        expected: 'exact semver string',
        actual: version,
        message: `${propertyPrefix}.version must be an exact semver string with no range markers such as ^, ~, >, or >=.`,
      });
    } else {
      pushCheck(checks, {
        file: manifestFile,
        property: `${propertyPrefix}.version`,
        status: 'ok',
        expected: 'exact semver string',
        actual: exactVersion,
        message: `${propertyPrefix}.version pins the exact approved Node.js runtime contract at ${exactVersion}.`,
      });
    }
  }

  pushEqualityCheck(checks, runtime, manifestFile, 'onFail', 'error', `${propertyPrefix}.onFail`);
  return {
    present: true,
    exactVersion,
  };
}

function auditForbiddenEmbeddedRuntimeSurface(
  checks: GovernanceCheck[],
  manifestFile: string,
  property: 'devEngines.runtime' | 'engines.runtime',
  actual: unknown,
  embeddedRuntimeDependency: string,
): void {
  if (actual === undefined) {
    return;
  }
  pushCheck(checks, {
    file: manifestFile,
    property,
    status: 'invalid',
    expected: 'unset',
    actual: formatValue(actual),
    message: `${property} must stay unset for an embedded-runtime package surface detected via ${embeddedRuntimeDependency}. Embedded applications such as Electron must not publish host-node runtime contracts here.`,
  });
}

function auditDevPackageManager(
  checks: GovernanceCheck[],
  manifest: ManifestLike,
  pnpmPolicy: GovernancePnpmPolicy,
): void {
  const packageManager = manifest?.devEngines?.packageManager;
  if (!packageManager || typeof packageManager !== 'object') {
    pushCheck(checks, {
      file: PACKAGE_JSON_BASENAME,
      property: 'devEngines.packageManager',
      status: 'missing',
      message: 'devEngines.packageManager must pin the PNPM runtime contract.',
    });
    return;
  }

  if (packageManager.name !== 'pnpm') {
    pushCheck(checks, {
      file: PACKAGE_JSON_BASENAME,
      property: 'devEngines.packageManager.name',
      status: 'invalid',
      expected: 'pnpm',
      actual: formatValue(packageManager.name),
      message: 'devEngines.packageManager.name must be "pnpm".',
    });
  } else {
    pushCheck(checks, {
      file: PACKAGE_JSON_BASENAME,
      property: 'devEngines.packageManager.name',
      status: 'ok',
      expected: 'pnpm',
      actual: 'pnpm',
      message: 'devEngines.packageManager.name is pnpm.',
    });
  }

  const version = typeof packageManager.version === 'string' ? packageManager.version : null;
  if (!version) {
    pushCheck(checks, {
      file: PACKAGE_JSON_BASENAME,
      property: 'devEngines.packageManager.version',
      status: 'missing',
      expected: pnpmPolicy.requiredVersion,
      message: buildPnpmRequiredVersionMessage('devEngines.packageManager.version', pnpmPolicy),
    });
  } else {
    const exactVersion = semver.valid(version);
    if (!exactVersion) {
      pushCheck(checks, {
        file: PACKAGE_JSON_BASENAME,
        property: 'devEngines.packageManager.version',
        status: 'invalid',
        expected: pnpmPolicy.requiredVersion,
        actual: version,
        message: 'devEngines.packageManager.version must be an exact semver string with no range markers.',
      });
    } else if (exactVersion !== pnpmPolicy.requiredVersion) {
      pushCheck(checks, {
        file: PACKAGE_JSON_BASENAME,
        property: 'devEngines.packageManager.version',
        status: 'invalid',
        expected: pnpmPolicy.requiredVersion,
        actual: exactVersion,
        message: buildPnpmRequiredVersionMessage('devEngines.packageManager.version', pnpmPolicy),
      });
    } else {
      pushCheck(checks, {
        file: PACKAGE_JSON_BASENAME,
        property: 'devEngines.packageManager.version',
        status: 'ok',
        expected: pnpmPolicy.requiredVersion,
        actual: exactVersion,
        message: `devEngines.packageManager.version pins PNPM ${exactVersion}.`,
      });
    }
  }

  pushEqualityCheck(checks, packageManager, PACKAGE_JSON_BASENAME, 'onFail', 'error', 'devEngines.packageManager.onFail');
}

function auditRuntimeIdentityContract(
  checks: GovernanceCheck[],
  packageJson: unknown,
  workspace: WorkspaceConfig | null,
): void {
  const manifest = toManifest(packageJson);
  const runtimeVersion = typeof manifest?.devEngines?.runtime?.version === 'string'
    ? semver.valid(manifest.devEngines.runtime.version)
    : null;
  const nodeVersion = typeof workspace?.['nodeVersion'] === 'string'
    ? semver.valid(workspace['nodeVersion'])
    : null;
  if (!runtimeVersion || !nodeVersion) {
    return;
  }

  if (runtimeVersion !== nodeVersion) {
    pushCheck(checks, {
      file: PACKAGE_JSON_BASENAME,
      property: 'devEngines.runtime.version = nodeVersion',
      status: 'invalid',
      expected: 'same exact semver in package.json and pnpm-workspace.yaml',
      actual: `${runtimeVersion} vs ${nodeVersion}`,
      message: 'devEngines.runtime.version and pnpm-workspace.yaml#nodeVersion must remain identical to prevent Node.js runtime drift.',
    });
    return;
  }

  pushCheck(checks, {
    file: PACKAGE_JSON_BASENAME,
    property: 'devEngines.runtime.version = nodeVersion',
    status: 'ok',
    expected: 'same exact semver in package.json and pnpm-workspace.yaml',
    actual: runtimeVersion,
    message: `devEngines.runtime.version and pnpm-workspace.yaml#nodeVersion are aligned on ${runtimeVersion}.`,
  });
}

function auditNodeRuntimeVersionPolicy(
  checks: GovernanceCheck[],
  packageJson: unknown,
  workspace: WorkspaceConfig | null,
  nodePolicy: GovernanceNodePolicy,
): void {
  const manifest = toManifest(packageJson);
  const runtimeVersion = typeof manifest?.devEngines?.runtime?.version === 'string'
    ? semver.valid(manifest.devEngines.runtime.version)
    : null;
  const nodeVersion = typeof workspace?.['nodeVersion'] === 'string'
    ? semver.valid(workspace['nodeVersion'])
    : null;
  if (!runtimeVersion || !nodeVersion || runtimeVersion !== nodeVersion) {
    return;
  }

  const alignedRuntimeVersion = runtimeVersion;
  if (semver.lt(alignedRuntimeVersion, nodePolicy.minimumLtsVersion)) {
    pushCheck(checks, {
      file: PACKAGE_JSON_BASENAME,
      property: 'runtime contract >= current Node LTS',
      status: 'invalid',
      expected: nodePolicy.minimumLtsVersion,
      actual: alignedRuntimeVersion,
      message: `The aligned Node.js runtime contract ${alignedRuntimeVersion} is below the current Node.js LTS floor ${nodePolicy.minimumLtsVersion}. Upgrade package.json#devEngines.runtime.version and pnpm-workspace.yaml#nodeVersion together to at least ${nodePolicy.minimumLtsVersion}.`,
    });
    return;
  }

  pushCheck(checks, {
    file: PACKAGE_JSON_BASENAME,
    property: 'runtime contract >= current Node LTS',
    status: 'ok',
    expected: nodePolicy.minimumLtsVersion,
    actual: alignedRuntimeVersion,
    message: `The aligned Node.js runtime contract ${alignedRuntimeVersion} meets the current Node.js LTS floor ${nodePolicy.minimumLtsVersion}.`,
  });

  if (!nodePolicy.latestVersion) {
    return;
  }

  if (semver.eq(alignedRuntimeVersion, nodePolicy.latestVersion)) {
    pushCheck(checks, {
      file: PACKAGE_JSON_BASENAME,
      property: 'runtime contract = current Node latest',
      status: 'ok',
      expected: nodePolicy.latestVersion,
      actual: alignedRuntimeVersion,
      message: `The aligned Node.js runtime contract ${alignedRuntimeVersion} matches the current Node.js latest release.`,
    });
    return;
  }

  if (semver.lt(alignedRuntimeVersion, nodePolicy.latestVersion)) {
    pushCheck(checks, {
      file: PACKAGE_JSON_BASENAME,
      property: 'runtime contract = current Node latest',
      status: 'warning',
      expected: nodePolicy.latestVersion,
      actual: alignedRuntimeVersion,
      message: `The aligned Node.js runtime contract ${alignedRuntimeVersion} meets the current LTS floor, but the current Node.js latest release is ${nodePolicy.latestVersion}. Upgrade package.json#devEngines.runtime.version and pnpm-workspace.yaml#nodeVersion together to ${nodePolicy.latestVersion}.`,
    });
    return;
  }

  pushCheck(checks, {
    file: PACKAGE_JSON_BASENAME,
    property: 'runtime contract = current Node latest',
    status: 'warning',
    expected: nodePolicy.latestVersion,
    actual: alignedRuntimeVersion,
    message: `The aligned Node.js runtime contract ${alignedRuntimeVersion} is newer than the currently resolved official Node.js latest release ${nodePolicy.latestVersion}. Reconfirm the upstream release contract before treating this version as the canonical baseline.`,
  });
}

function auditLockfile(checks: GovernanceCheck[], pnpmLockfilePath: string): void {
  if (!fileExists(pnpmLockfilePath)) {
    pushCheck(checks, {
      file: PNPM_LOCKFILE_BASENAME,
      property: PNPM_LOCKFILE_BASENAME,
      status: 'missing',
      message: `${PNPM_LOCKFILE_BASENAME} is required for deterministic PNPM installs.`,
    });
    return;
  }

  pushCheck(checks, {
    file: PNPM_LOCKFILE_BASENAME,
    property: PNPM_LOCKFILE_BASENAME,
    status: 'ok',
    message: `${PNPM_LOCKFILE_BASENAME} is present.`,
  });
}

function auditProjectAuthFiles(
  checks: GovernanceCheck[],
  gitignorePath: string,
  authFiles: readonly ProjectAuthFileAuditTarget[],
): void {
  const gitignorePatterns = readGitignorePatterns(gitignorePath);
  for (const authFile of authFiles) {
    const authFilePath = authFile.filePath;
    if (!fileExists(authFilePath)) {
      pushCheck(checks, {
        file: path.basename(authFilePath),
        property: path.basename(authFilePath),
        status: 'ok',
        expected: 'optional auth-local file',
        actual: 'absent',
        message: `${path.basename(authFilePath)} is absent, which is acceptable.`,
      });
      continue;
    }

    const basename = path.basename(authFilePath);
    if (!isAuthFileGitignored(basename, gitignorePatterns)) {
      pushCheck(checks, {
        file: basename,
        property: `${basename} gitignore`,
        status: 'invalid',
        message: `${basename} exists in the project root and must be gitignored.`,
      });
    } else {
      pushCheck(checks, {
        file: basename,
        property: `${basename} gitignore`,
        status: 'ok',
        message: `${basename} is gitignored.`,
      });
    }

    if (!authFile.inspectProperties) {
      continue;
    }

    const parsedKeys = parseNpmrcKeys(authFilePath);
    if (parsedKeys.length === 0) {
      pushCheck(checks, {
        file: basename,
        property: basename,
        status: 'ok',
        message: `${basename} exists but does not contain active config keys.`,
      });
      continue;
    }

    for (const { key } of parsedKeys) {
      if (isForbiddenProjectTokenHelperKey(key)) {
        pushCheck(checks, {
          file: basename,
          property: key,
          status: 'invalid',
          message: `${key} is not allowed in a project-local .npmrc. tokenHelper is only permitted in the user-level .npmrc because a project-local helper path could execute arbitrary local binaries.`,
        });
        continue;
      }
      if (!isAllowedProjectNpmrcKey(key)) {
        const migrationMessage = explainMisplacedProjectAuthSetting(key);
        pushCheck(checks, {
          file: basename,
          property: key,
          status: 'invalid',
          message: migrationMessage
            ?? `${key} is not an allowed project-local PNPM auth or certificate property. Keep project-local .npmrc limited to auth and certificate material; move repository policy to pnpm-workspace.yaml and machine-local infrastructure settings to the global PNPM config.yaml instead.`,
        });
        continue;
      }

      pushCheck(checks, {
        file: basename,
        property: key,
        status: 'ok',
        message: `${key} is an allowed auth-local property.`,
      });
    }
  }

  if (!fileExists(gitignorePath)) {
    pushCheck(checks, {
      file: GITIGNORE_BASENAME,
      property: GITIGNORE_BASENAME,
      status: 'warning',
      message: `${GITIGNORE_BASENAME} is missing. Add .npmrc and auth.ini ignore rules if auth-local files are ever used.`,
    });
  }
}

function auditForbiddenNvmrcFiles(checks: GovernanceCheck[], projectRootPath: string): void {
  const nvmrcPaths = discoverForbiddenNvmrcPaths(projectRootPath);
  if (nvmrcPaths.length === 0) {
    pushCheck(checks, {
      file: NVMRC_BASENAME,
      property: NVMRC_BASENAME,
      status: 'ok',
      expected: 'absent',
      actual: 'absent',
      message: 'No committed .nvmrc file was discovered under the governed project root.',
    });
    return;
  }

  for (const nvmrcPath of nvmrcPaths) {
    pushCheck(checks, {
      file: nvmrcPath,
      property: NVMRC_BASENAME,
      status: 'invalid',
      expected: 'absent',
      actual: 'present',
      message: '.nvmrc is forbidden in Fortress governance. The runtime truth belongs in pnpm-workspace.yaml#nodeVersion and deliberate package runtime surfaces, not in a parallel nvm convenience file.',
    });
  }
}

function discoverForbiddenNvmrcPaths(projectRootPath: string): string[] {
  const discovered: string[] = [];
  const stack = [projectRootPath];
  const visited = new Set<string>();

  while (stack.length > 0) {
    const current = stack.pop();
    if (typeof current !== 'string') {
      continue;
    }
    const realCurrent = safeRealpath(current);
    if (visited.has(realCurrent)) {
      continue;
    }
    visited.add(realCurrent);

    let entries = [];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      if (direntIsDirectory(entry, fullPath)) {
        if (isDirectorySymlink(fullPath) || shouldSkipGovernanceDirectory(entry.name, {})) {
          continue;
        }
        if (fileExists(path.join(fullPath, PNPM_WORKSPACE_BASENAME))) {
          continue;
        }
        stack.push(fullPath);
        continue;
      }
      if (entry.name === NVMRC_BASENAME) {
        discovered.push(path.resolve(fullPath));
      }
    }
  }

  return discovered.sort((left, right) => left.localeCompare(right));
}

function explainMisplacedProjectAuthSetting(rawKey: string): string | null {
  if (rawKey === 'registry') {
    return 'registry must not live in a project-local .npmrc. In Fortress mode, the approved default registry is a visible repository policy. Move it to pnpm-workspace.yaml#registries.default so every developer and CI runner resolves against the same reviewed origin instead of inheriting a hidden machine-local override.';
  }

  if (/^@[^:]+:registry$/u.test(rawKey)) {
    return `${rawKey} must not live in a project-local .npmrc. Scoped registry topology is repository policy, not auth-local secret material. Move it to pnpm-workspace.yaml#registries so the scope-to-registry contract stays explicit and reviewable.`;
  }

  const normalizedKey = normalizeConfigKeyForLookup(rawKey);
  if (normalizedKey === normalizeConfigKeyForLookup('useNodeVersion')) {
    return 'useNodeVersion must not live in a project-local .npmrc. PNPM removed useNodeVersion from .npmrc-based governance. Model the root engine gate in pnpm-workspace.yaml#nodeVersion and any deliberate package-local runtime contract in package.json#devEngines.runtime or package.json#engines.runtime instead.';
  }

  if (normalizedKey === normalizeConfigKeyForLookup('nodeVersion')) {
    return `nodeVersion must not live in a project-local .npmrc. Move it to pnpm-workspace.yaml#nodeVersion. Deliberate package-local runtime contracts belong in package.json#devEngines.runtime or package.json#engines.runtime instead. ${PROJECT_AUTH_LOCAL_POLICY_DRIFT_MESSAGE}`;
  }

  const packageJsonSurface = PACKAGE_JSON_TOOLCHAIN_SURFACES.get(normalizedKey);
  if (packageJsonSurface) {
    return `${rawKey} must not live in a project-local .npmrc. This toolchain contract belongs in package.json#${packageJsonSurface}, not in an auth-local secret file. ${PROJECT_AUTH_LOCAL_POLICY_DRIFT_MESSAGE}`;
  }

  const workspaceSurface = WORKSPACE_POLICY_SURFACES.get(normalizedKey);
  if (workspaceSurface) {
    return `${rawKey} must not live in a project-local .npmrc. Move it to pnpm-workspace.yaml#${workspaceSurface}. ${PROJECT_AUTH_LOCAL_POLICY_DRIFT_MESSAGE}`;
  }

  const globalConfigSurface = GLOBAL_PNPM_CONFIG_SURFACES.get(normalizedKey);
  if (globalConfigSurface) {
    return `${rawKey} must not live in a project-local .npmrc. This setting is infrastructure- or machine-local rather than repository auth material. Move it to the global PNPM config.yaml#${globalConfigSurface} (or equivalent runner/user provisioning) instead.`;
  }

  return null;
}

function auditWorkspaceMembers(
  checks: GovernanceCheck[],
  members: readonly GovernanceWorkspaceMember[],
): void {
  if (members.length === 0) {
    pushCheck(checks, {
      file: PNPM_WORKSPACE_BASENAME,
      property: 'packages',
      status: 'invalid',
      message: 'The workspace declares package globs, but no workspace package.json files were discovered.',
    });
    return;
  }

  const workspaceNameToRoot = buildWorkspaceNameToRootMap(members);

  for (const member of members) {
    const memberManifestPath = path.join(member.rootPath, PACKAGE_JSON_BASENAME);
    const isNestedWorkspaceDomain = fileExists(path.join(member.rootPath, PNPM_WORKSPACE_BASENAME));
    if (!member.packageJson.rawText || !toManifest(member.packageJson.value)) {
      pushCheck(checks, {
        file: normalizeForDisplay(memberManifestPath),
        property: PACKAGE_JSON_BASENAME,
        status: 'invalid',
        message: `Workspace package at ${normalizeForDisplay(member.rootPath)} has an unreadable or invalid package.json.`,
      });
      continue;
    }
    const memberManifest = toManifest(member.packageJson.value) ?? {};

    for (const authFileName of PROJECT_AUTH_FILE_BASENAMES) {
      const authFilePath = path.join(member.rootPath, authFileName);
      if (fileExists(authFilePath)) {
        pushCheck(checks, {
          file: normalizeForDisplay(authFilePath),
          property: authFileName,
          status: 'invalid',
          message: `Workspace package ${normalizeForDisplay(member.rootPath)} contains ${authFileName}. Use root-level auth files and packageConfigs instead.`,
        });
      }
    }

    if (!isNestedWorkspaceDomain) {
      auditWorkspaceLeafPackageManagerSurfaces(checks, memberManifest, memberManifestPath);
      auditRuntimeSurfaceGovernance(
        checks,
        memberManifest,
        memberManifestPath,
        'monorepo',
        detectEmbeddedRuntimeDependency(memberManifest),
      );
    }

    auditWorkspaceProtocolUsage(checks, memberManifest, member.rootPath, workspaceNameToRoot);
    auditCatalogDependencyUsage(checks, memberManifest, member.rootPath, workspaceNameToRoot);
  }
}

function auditWorkspaceLeafPackageManagerSurfaces(
  checks: GovernanceCheck[],
  manifest: ManifestLike,
  manifestFile: string,
): void {
  auditForbiddenWorkspaceLeafSurface(
    checks,
    manifestFile,
    'packageManager',
    manifest.packageManager,
    'Workspace leaf packages must not declare packageManager. The shared PNPM install domain has exactly one root control plane.',
  );
  auditForbiddenWorkspaceLeafSurface(
    checks,
    manifestFile,
    'devEngines.packageManager',
    manifest?.devEngines?.packageManager,
    'Workspace leaf packages must not declare devEngines.packageManager. The PNPM control plane belongs on the workspace root only.',
  );
  auditForbiddenWorkspaceLeafSurface(
    checks,
    manifestFile,
    'engines.pnpm',
    manifest?.engines?.pnpm,
    'Workspace leaf packages must not declare engines.pnpm. Do not introduce a parallel PNPM version authority beneath the workspace root.',
  );
}

function auditForbiddenWorkspaceLeafSurface(
  checks: GovernanceCheck[],
  manifestFile: string,
  property: string,
  actual: unknown,
  message: string,
): void {
  if (actual === undefined) {
    return;
  }
  pushCheck(checks, {
    file: manifestFile,
    property,
    status: 'invalid',
    expected: 'unset',
    actual: formatValue(actual),
    message,
  });
}

function detectEmbeddedRuntimeDependency(manifest: ManifestLike | null): string | null {
  if (!manifest) {
    return null;
  }

  for (const section of MANIFEST_DEPENDENCY_SECTIONS) {
    const dependencies = manifest[section];
    if (!isObjectRecord(dependencies)) {
      continue;
    }
    for (const dependencyName of EMBEDDED_RUNTIME_DEPENDENCY_NAMES) {
      if (dependencyName in dependencies) {
        return dependencyName;
      }
    }
  }

  return null;
}

function auditWorkspaceProtocolUsage(
  checks: GovernanceCheck[],
  manifest: ManifestLike,
  manifestRootPath: string,
  workspaceNameToRoot: ReadonlyMap<string, string>,
): void {
  for (const section of MANIFEST_DEPENDENCY_SECTIONS) {
    const dependencies = manifest?.[section];
    if (!dependencies || typeof dependencies !== 'object') {
      continue;
    }

    for (const [dependencyName, specifier] of Object.entries(dependencies)) {
      if (!workspaceNameToRoot.has(dependencyName)) {
        continue;
      }
      if (workspaceNameToRoot.get(dependencyName) === manifestRootPath) {
        continue;
      }
      if (typeof specifier === 'string' && specifier.startsWith('workspace:')) {
        pushCheck(checks, {
          file: normalizeForDisplay(path.join(manifestRootPath, PACKAGE_JSON_BASENAME)),
          property: `${section}.${dependencyName}`,
          status: 'ok',
          expected: 'workspace:* or workspace:^ / workspace:~ / exact workspace version',
          actual: specifier,
          message: `${dependencyName} uses the workspace: protocol.`,
        });
        continue;
      }

      pushCheck(checks, {
        file: normalizeForDisplay(path.join(manifestRootPath, PACKAGE_JSON_BASENAME)),
        property: `${section}.${dependencyName}`,
        status: 'invalid',
        expected: 'workspace: protocol',
        actual: formatValue(specifier),
        message: `${dependencyName} is a local workspace package and must be referenced via the workspace: protocol.`,
      });
    }
  }
}

function buildWorkspaceNameToRootMap(
  members: readonly GovernanceWorkspaceMember[],
): ReadonlyMap<string, string> {
  const workspaceNameToRoot = new Map<string, string>();
  for (const member of members) {
    const manifest = toManifest(member.packageJson.value);
    if (typeof manifest?.name === 'string') {
      workspaceNameToRoot.set(manifest.name, member.rootPath);
    }
  }
  return workspaceNameToRoot;
}

function auditCatalogDependencyUsage(
  checks: GovernanceCheck[],
  manifest: ManifestLike,
  manifestRootPath: string,
  workspaceNameToRoot: ReadonlyMap<string, string>,
): void {
  for (const section of MANIFEST_CATALOG_DEPENDENCY_SECTIONS) {
    const dependencies = manifest?.[section];
    if (!dependencies || typeof dependencies !== 'object') {
      continue;
    }

    for (const [dependencyName, specifier] of Object.entries(dependencies)) {
      if (workspaceNameToRoot.has(dependencyName)) {
        continue;
      }

      if (typeof specifier === 'string' && specifier.startsWith('catalog:')) {
        pushCheck(checks, {
          file: normalizeForDisplay(path.join(manifestRootPath, PACKAGE_JSON_BASENAME)),
          property: `${section}.${dependencyName}`,
          status: 'ok',
          expected: 'catalog: reference',
          actual: specifier,
          message: `${dependencyName} delegates version governance to a shared PNPM catalog reference.`,
        });
        continue;
      }

      pushCheck(checks, {
        file: normalizeForDisplay(path.join(manifestRootPath, PACKAGE_JSON_BASENAME)),
        property: `${section}.${dependencyName}`,
        status: 'invalid',
        expected: 'catalog: reference',
        actual: formatValue(specifier),
        message: `${dependencyName} must migrate its exact approved version into pnpm-workspace.yaml#catalog and reference it via catalog:.`,
      });
    }
  }
}

function discoverWorkspaceMembers(rootPath: string, workspacePatterns: unknown): GovernanceWorkspaceMember[] {
  if (!Array.isArray(workspacePatterns)) {
    return [];
  }

  const normalizedPatterns = workspacePatterns.filter((pattern) => typeof pattern === 'string');
  const positivePatterns = normalizedPatterns.filter((pattern) => !pattern.startsWith('!'));
  const negativePatterns = normalizedPatterns
    .filter((pattern) => pattern.startsWith('!'))
    .map((pattern) => pattern.slice(1));

  const discovered: GovernanceWorkspaceMember[] = [];
  const stack: string[] = [rootPath];
  const visited = new Set<string>();

  while (stack.length > 0) {
    const current = stack.pop();
    if (typeof current !== 'string') {
      continue;
    }
    const realCurrent = safeRealpath(current);
    if (visited.has(realCurrent)) {
      continue;
    }
    visited.add(realCurrent);

    let entries = [];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      if (direntIsDirectory(entry, fullPath)) {
        if (isDirectorySymlink(fullPath)) {
          continue;
        }
        if (shouldSkipGovernanceDirectory(entry.name, {})) {
          continue;
        }
        stack.push(fullPath);
        continue;
      }

      if (entry.name !== PACKAGE_JSON_BASENAME) {
        continue;
      }

      const packageRoot = path.dirname(fullPath);
      if (packageRoot === rootPath) {
        continue;
      }

      const relativeRoot = normalizeSlashes(path.relative(rootPath, packageRoot));
      if (!matchesWorkspacePattern(relativeRoot, positivePatterns, negativePatterns)) {
        continue;
      }

      discovered.push({
        rootPath: path.resolve(packageRoot),
        packageJson: readJsonSafe(fullPath),
      });
    }
  }

  return discovered.sort((left, right) => left.rootPath.localeCompare(right.rootPath));
}

function matchesWorkspacePattern(
  relativeRoot: string,
  positivePatterns: readonly string[],
  negativePatterns: readonly string[],
): boolean {
  if (positivePatterns.length === 0) {
    return false;
  }
  const positive = positivePatterns.some((pattern) => minimatch(relativeRoot, pattern, { dot: true }));
  if (!positive) {
    return false;
  }
  return !negativePatterns.some((pattern) => minimatch(relativeRoot, pattern, { dot: true }));
}

function readYamlSafe(filePath: string): YamlReadResult {
  if (!fileExists(filePath)) {
    return {
      rawText: null,
      value: null,
    };
  }

  try {
    const rawText = readFileTextSafe(filePath);
    return {
      rawText,
      value: YAML.parse(rawText),
    };
  } catch {
    return {
      rawText: fileExists(filePath) ? readTextOrNull(filePath) : null,
      value: null,
    };
  }
}

function readTextOrNull(filePath: string): string | null {
  try {
    return readFileTextSafe(filePath);
  } catch {
    return null;
  }
}

function readGitignorePatterns(gitignorePath: string): string[] {
  if (!fileExists(gitignorePath)) {
    return [];
  }
  try {
    return readFileTextSafe(gitignorePath)
      .split(/\r?\n/u)
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith('#'));
  } catch {
    return [];
  }
}

function isAuthFileGitignored(basename: string, patterns: readonly string[]): boolean {
  return patterns.some((pattern) => {
    const normalizedPattern = pattern.replace(/\\/g, '/');
    return normalizedPattern === basename || normalizedPattern === `/${basename}`;
  });
}

function parseNpmrcKeys(filePath: string): Array<{ key: string }> {
  let text = '';
  try {
    text = readFileTextSafe(filePath);
  } catch {
    return [];
  }

  return text
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#') && !line.startsWith(';'))
    .map((line) => {
      const separatorIndex = line.indexOf('=');
      return {
        key: (separatorIndex === -1 ? line : line.slice(0, separatorIndex)).trim(),
      };
    })
    .filter((entry) => entry.key);
}

function buildWorkspacePolicySurfaceEntries(): Array<[string, string]> {
  const propertyPaths = new Set<string>([
    ...SHARED_WORKSPACE_EXACT_RULES.map(([property]) => String(property)),
    ...SHARED_WORKSPACE_EMPTY_ARRAY_RULES,
    ...SHARED_WORKSPACE_EMPTY_OBJECT_RULES,
    ...SHARED_WORKSPACE_OBJECT_RULES,
    ...MONOREPO_WORKSPACE_EXACT_RULES.map(([property]) => String(property)),
    ...MONOREPO_WORKSPACE_ARRAY_RULES,
    ...SINGLE_PROJECT_FORBIDDEN_WORKSPACE_RULES,
    ...SECURITY_EXCEPTION_WORKSPACE_RULES,
    'catalogs',
    'registries.default',
  ]);

  return [...propertyPaths]
    .sort((left, right) => left.localeCompare(right))
    .map((propertyPath) => [normalizeConfigKeyForLookup(propertyPath), propertyPath] as [string, string]);
}

function buildNormalizedSurfaceEntries(
  entries: ReadonlyArray<readonly [string, string]>,
): Array<[string, string]> {
  return entries.map(([key, surface]) => [normalizeConfigKeyForLookup(key), surface] as [string, string]);
}

function normalizeConfigKeyForLookup(rawKey: string): string {
  return String(rawKey).replace(/[^a-z0-9]/giu, '').toLowerCase();
}

function auditNumericMinimum(
  checks: GovernanceCheck[],
  object: Record<string, unknown>,
  fileName: string,
  property: string,
  minimumExpected: number,
  expectedLabel: string,
): void {
  const actual = getNestedValue(object, property);
  if (typeof actual !== 'number') {
    pushCheck(checks, {
      file: fileName,
      property,
      status: 'missing',
      expected: expectedLabel,
      actual: formatValue(actual),
      message: `${property} must be a number with a minimum of ${minimumExpected}.`,
    });
    return;
  }

  if (actual < minimumExpected) {
    pushCheck(checks, {
      file: fileName,
      property,
      status: 'invalid',
      expected: expectedLabel,
      actual: formatValue(actual),
      message: `${property} is weaker than the Fortress baseline of ${minimumExpected}.`,
    });
    return;
  }

  pushCheck(checks, {
    file: fileName,
    property,
    status: 'ok',
    expected: expectedLabel,
    actual: formatValue(actual),
    message: `${property} is ${actual}.`,
  });
}

function auditNumericMaximum(
  checks: GovernanceCheck[],
  object: Record<string, unknown>,
  fileName: string,
  property: string,
  maximumExpected: number,
  expectedLabel: string,
): void {
  const actual = getNestedValue(object, property);
  if (typeof actual !== 'number') {
    pushCheck(checks, {
      file: fileName,
      property,
      status: 'missing',
      expected: expectedLabel,
      actual: formatValue(actual),
      message: `${property} must be a number no greater than ${maximumExpected}.`,
    });
    return;
  }

  if (actual > maximumExpected) {
    pushCheck(checks, {
      file: fileName,
      property,
      status: 'invalid',
      expected: expectedLabel,
      actual: formatValue(actual),
      message: `${property} exceeds the Windows-safe Fortress maximum of ${maximumExpected}.`,
    });
    return;
  }

  pushCheck(checks, {
    file: fileName,
    property,
    status: 'ok',
    expected: expectedLabel,
    actual: formatValue(actual),
    message: `${property} is ${actual}.`,
  });
}

function auditExactSemverString(
  checks: GovernanceCheck[],
  object: Record<string, unknown>,
  fileName: string,
  property: string,
): void {
  const actual = getNestedValue(object, property);
  if (typeof actual !== 'string') {
    pushCheck(checks, {
      file: fileName,
      property,
      status: 'missing',
      expected: 'exact semver string',
      actual: formatValue(actual),
      message: `${property} must be declared as an exact semver string.`,
    });
    return;
  }

  const valid = semver.valid(actual);
  if (!valid) {
    pushCheck(checks, {
      file: fileName,
      property,
      status: 'invalid',
      expected: 'exact semver string',
      actual,
      message: `${property} must be an exact semver string.`,
    });
    return;
  }

  pushCheck(checks, {
    file: fileName,
    property,
    status: 'ok',
    expected: 'exact semver string',
    actual: valid,
    message: `${property} is pinned to ${valid}.`,
  });
}

function auditHttpsRegistry(
  checks: GovernanceCheck[],
  object: Record<string, unknown>,
  fileName: string,
  property: string,
): void {
  const actual = getNestedValue(object, property);
  if (typeof actual !== 'string') {
    pushCheck(checks, {
      file: fileName,
      property,
      status: 'missing',
      expected: 'HTTPS registry URL',
      actual: formatValue(actual),
      message: `${property} must point to an approved HTTPS registry. Prefer a reviewed internal Nexus registry; if none exists, use the official npm registry ${OFFICIAL_NPM_REGISTRY_URL}.`,
    });
    return;
  }

  let protocol = null;
  try {
    protocol = new URL(actual).protocol;
  } catch {
    protocol = null;
  }
  if (protocol !== 'https:') {
    pushCheck(checks, {
      file: fileName,
      property,
      status: 'invalid',
      expected: 'HTTPS registry URL',
      actual,
      message: `${property} must use https. Approved defaults are a reviewed internal Nexus registry or the official npm registry ${OFFICIAL_NPM_REGISTRY_URL}.`,
    });
    return;
  }

  pushCheck(checks, {
    file: fileName,
    property,
    status: 'ok',
    expected: 'HTTPS registry URL',
    actual,
    message: `${property} uses HTTPS.`,
  });
}

function auditEmptyArray(
  checks: GovernanceCheck[],
  object: Record<string, unknown>,
  fileName: string,
  property: string,
): void {
  const actual = getNestedValue(object, property);
  if (!Array.isArray(actual)) {
    pushCheck(checks, {
      file: fileName,
      property,
      status: 'missing',
      expected: '[]',
      actual: formatValue(actual),
      message: `${property} must be present as an explicit empty array.`,
    });
    return;
  }

  if (actual.length > 0) {
    pushCheck(checks, {
      file: fileName,
      property,
      status: 'invalid',
      ...(isFortressExceptionSurfaceRule(property) ? { presentationTone: 'warning' as const } : {}),
      expected: '[]',
      actual: formatValue(actual),
      message: isFortressExceptionSurfaceRule(property)
        ? getFortressExceptionSurfaceViolationMessage(property, '[]')
        : `${property} must stay empty in Fortress mode.`,
    });
    return;
  }

  pushCheck(checks, {
    file: fileName,
    property,
    status: 'ok',
    expected: '[]',
    actual: '[]',
    message: `${property} is explicitly empty.`,
  });
}

function auditNonEmptyArray(
  checks: GovernanceCheck[],
  object: Record<string, unknown>,
  fileName: string,
  property: string,
): void {
  const actual = getNestedValue(object, property);
  if (!Array.isArray(actual)) {
    pushCheck(checks, {
      file: fileName,
      property,
      status: 'missing',
      expected: 'non-empty array',
      actual: formatValue(actual),
      message: `${property} must be a non-empty array.`,
    });
    return;
  }

  if (actual.length === 0) {
    pushCheck(checks, {
      file: fileName,
      property,
      status: 'invalid',
      expected: 'non-empty array',
      actual: '[]',
      message: `${property} must not be empty.`,
    });
    return;
  }

  pushCheck(checks, {
    file: fileName,
    property,
    status: 'ok',
    expected: 'non-empty array',
    actual: `${actual.length} entries`,
    message: `${property} contains ${actual.length} workspace patterns.`,
  });
}

function auditArraySurface(
  checks: GovernanceCheck[],
  object: Record<string, unknown>,
  fileName: string,
  property: string,
): void {
  const actual = getNestedValue(object, property);
  if (!Array.isArray(actual)) {
    pushCheck(checks, {
      file: fileName,
      property,
      status: 'missing',
      expected: 'array',
      actual: formatValue(actual),
      message: `${property} must be present as an array.`,
    });
    return;
  }

  pushCheck(checks, {
    file: fileName,
    property,
    status: 'ok',
    expected: 'array',
    actual: `${actual.length} entries`,
    message: `${property} is present as an array.`,
  });
}

function auditEmptyObject(
  checks: GovernanceCheck[],
  object: Record<string, unknown>,
  fileName: string,
  property: string,
): void {
  const actual = getNestedValue(object, property);
  if (!isPlainObject(actual)) {
    pushCheck(checks, {
      file: fileName,
      property,
      status: 'missing',
      expected: '{}',
      actual: formatValue(actual),
      message: `${property} must be present as an explicit empty object.`,
    });
    return;
  }

  if (Object.keys(actual).length > 0) {
    pushCheck(checks, {
      file: fileName,
      property,
      status: 'invalid',
      ...(isFortressExceptionSurfaceRule(property) ? { presentationTone: 'warning' as const } : {}),
      expected: '{}',
      actual: formatValue(actual),
      message: isFortressExceptionSurfaceRule(property)
        ? getFortressExceptionSurfaceViolationMessage(property, '{}')
        : `${property} must stay empty in Fortress mode.`,
    });
    return;
  }

  pushCheck(checks, {
    file: fileName,
    property,
    status: 'ok',
    expected: '{}',
    actual: '{}',
    message: `${property} is explicitly empty.`,
  });
}

function auditObjectSurface(
  checks: GovernanceCheck[],
  object: Record<string, unknown>,
  fileName: string,
  property: string,
): void {
  const actual = getNestedValue(object, property);
  if (!isPlainObject(actual)) {
    pushCheck(checks, {
      file: fileName,
      property,
      status: 'missing',
      expected: 'object map',
      actual: formatValue(actual),
      message: `${property} must be present as an object map.`,
    });
    return;
  }

  pushCheck(checks, {
    file: fileName,
    property,
    status: 'ok',
    expected: 'object map',
    actual: `${Object.keys(actual).length} keys`,
    message: `${property} is present as an object map.`,
  });
}

function auditAllowBuildsSurface(checks: GovernanceCheck[], workspace: Record<string, unknown>): void {
  const actual = getNestedValue(workspace, 'allowBuilds');
  if (!isPlainObject(actual)) {
    pushCheck(checks, {
      file: PNPM_WORKSPACE_BASENAME,
      property: 'allowBuilds',
      status: 'missing',
      expected: 'object map',
      actual: formatValue(actual),
      message: 'allowBuilds must be present as an object map.',
    });
    return;
  }

  const invalidKeys = Object.entries(actual).filter(([, value]) => typeof value !== 'boolean');
  if (invalidKeys.length > 0) {
    pushCheck(checks, {
      file: PNPM_WORKSPACE_BASENAME,
      property: 'allowBuilds',
      status: 'invalid',
      expected: 'boolean values only',
      actual: formatValue(actual),
      message: 'allowBuilds may only contain boolean allow/deny values.',
    });
    return;
  }

  pushCheck(checks, {
    file: PNPM_WORKSPACE_BASENAME,
    property: 'allowBuilds',
    status: 'ok',
    expected: 'object map',
    actual: `${Object.keys(actual).length} entries`,
    message: 'allowBuilds is present as a reviewed allow/deny map.',
  });
}

function auditCatalogExactVersions(checks: GovernanceCheck[], workspace: Record<string, unknown>): void {
  const catalog = getNestedValue(workspace, 'catalog');
  if (isPlainObject(catalog)) {
    auditCatalogVersionMap(checks, 'catalog', catalog);
  }

  const namedCatalogs = getNestedValue(workspace, 'catalogs');
  if (namedCatalogs === undefined) {
    return;
  }

  if (!isPlainObject(namedCatalogs)) {
    pushCheck(checks, {
      file: PNPM_WORKSPACE_BASENAME,
      property: 'catalogs',
      status: 'invalid',
      expected: 'object of named catalog maps',
      actual: formatValue(namedCatalogs),
      message: 'catalogs must be an object map of named PNPM catalog sections.',
    });
    return;
  }

  const namedCatalogEntries = Object.entries(namedCatalogs).sort(([leftName], [rightName]) =>
    leftName.localeCompare(rightName),
  );
  if (namedCatalogEntries.length === 0) {
    pushCheck(checks, {
      file: PNPM_WORKSPACE_BASENAME,
      property: 'catalogs',
      status: 'ok',
      expected: 'named catalog map',
      actual: '0 named catalogs',
      message: 'catalogs is present as an empty named catalog map.',
    });
    return;
  }

  for (const [catalogName, catalogValue] of namedCatalogEntries) {
    if (!isPlainObject(catalogValue)) {
      pushCheck(checks, {
        file: PNPM_WORKSPACE_BASENAME,
        property: `catalogs.${catalogName}`,
        status: 'invalid',
        expected: 'object of exact semver catalog entries',
        actual: formatValue(catalogValue),
        message: `catalogs.${catalogName} must be an object map of explicit exact versions.`,
      });
      continue;
    }

    auditCatalogVersionMap(checks, `catalogs.${catalogName}`, catalogValue);
  }
}

function auditCatalogVersionMap(
  checks: GovernanceCheck[],
  propertyPrefix: string,
  catalog: Record<string, unknown>,
): void {
  const entries = Object.entries(catalog).sort(([leftName], [rightName]) => leftName.localeCompare(rightName));
  const invalidEntries = entries.filter(([, specifier]) => !isCanonicalExactSemverString(specifier));

  if (invalidEntries.length > 0) {
    for (const [packageName, specifier] of invalidEntries) {
      pushCheck(checks, {
        file: PNPM_WORKSPACE_BASENAME,
        property: `${propertyPrefix}.${packageName}`,
        status: 'invalid',
        expected: 'exact semver like 1.2.3',
        actual: formatValue(specifier),
        message: `${propertyPrefix}.${packageName} must use an explicit exact semver version only. Range markers such as ^ or ~ are architecturally forbidden for supply-chain defense; migrate the approved exact version cleanly into this catalog entry.`,
      });
    }
    return;
  }

  pushCheck(checks, {
    file: PNPM_WORKSPACE_BASENAME,
    property: `${propertyPrefix} exact versions`,
    status: 'ok',
    expected: 'exact semver only',
    actual: entries.length === 1 ? '1 exact entry' : `${entries.length} exact entries`,
    message: entries.length === 0
      ? `${propertyPrefix} is present as an empty approval map. Future entries must use explicit exact semver versions only.`
      : `${propertyPrefix} entries are present and pinned to explicit exact semver versions only.`,
  });
}

function auditTrustPolicyExcludeExactVersionSelectors(
  checks: GovernanceCheck[],
  workspace: Record<string, unknown>,
): void {
  const actual = getNestedValue(workspace, 'trustPolicyExclude');
  if (!Array.isArray(actual) || actual.length === 0) {
    return;
  }

  let invalidEntryCount = 0;
  for (const [index, selector] of actual.entries()) {
    if (isExactPackageVersionSelector(selector)) {
      continue;
    }

    invalidEntryCount += 1;
    pushCheck(checks, {
      file: PNPM_WORKSPACE_BASENAME,
      property: `trustPolicyExclude[${index}]`,
      status: 'invalid',
      expected: 'exact package version selector like chokidar@4.0.3',
      actual: formatValue(selector),
      message: 'trustPolicyExclude entries must name one explicit exact package version only. Package-wide exclusions, latest, open ranges, wildcards, and logical OR selectors are architecturally forbidden on this break-glass trust-waiver surface; scope the exception to exactly one reviewed blocked version.',
    });
  }

  if (invalidEntryCount > 0) {
    return;
  }

  pushCheck(checks, {
    file: PNPM_WORKSPACE_BASENAME,
    property: 'trustPolicyExclude exact versions',
    status: 'ok',
    expected: 'exact package version selectors only',
    actual: actual.length === 1 ? '1 exact exception' : `${actual.length} exact exceptions`,
    message: 'trustPolicyExclude entries are present and pinned to one exact package version each.',
  });
}

function auditTrustPolicyExcludeResponseOrderWarning(
  checks: GovernanceCheck[],
  workspace: Record<string, unknown>,
): void {
  const actual = getNestedValue(workspace, 'trustPolicyExclude');
  if (!Array.isArray(actual) || actual.length === 0) {
    return;
  }

  pushCheck(checks, {
    file: PNPM_WORKSPACE_BASENAME,
    property: 'trustPolicyExclude response order',
    status: 'warning',
    expected: 'patch-only, compatibility-gated override-first trust-downgrade response order',
    actual: actual.length === 1 ? '1 configured trust waiver' : `${actual.length} configured trust waivers`,
    message: 'trustPolicyExclude is a break-glass surface. Checklist: confirm this is ERR_PNPM_TRUST_DOWNGRADE rather than a release-age, registry-time, or build-script incident; keep the direct dependency pinned exactly in its normal declaration surface; derive override candidates from the concrete consumer contract and restrict them to trust-compliant exact patch versions within the same major/minor line; verify contract fit, compatibility, evidence, real consumer behavior, and exception ownership before writing any override; if a clean exact patch override survives those gates, trustPolicyExclude is not architecturally correct and root overrides should have been used first; only keep trustPolicyExclude for the exact blocked version when no supplier-conformant exact patch override remains; remove the exception once upstream is policy-compliant again.',
  });
}

function auditOverridesNarrowSelectors(
  checks: GovernanceCheck[],
  workspace: Record<string, unknown>,
): void {
  const actual = getNestedValue(workspace, 'overrides');
  if (!isPlainObject(actual) || Object.keys(actual).length === 0) {
    return;
  }

  const entries = Object.entries(actual).sort(([leftSelector], [rightSelector]) =>
    leftSelector.localeCompare(rightSelector),
  );

  let invalidEntryCount = 0;
  for (const [selector] of entries) {
    const broadReason = explainBroadOverrideSelector(selector);
    if (!broadReason) {
      continue;
    }

    invalidEntryCount += 1;
    pushCheck(checks, {
      file: PNPM_WORKSPACE_BASENAME,
      property: `overrides selector.${selector}`,
      status: 'invalid',
      expected: 'exact parent-edge selector like react-dom@18.2.0>react',
      actual: formatValue(selector),
      message: `overrides.${selector} must use the full exact parent-edge form parent@exactVersion>child. Why: ${broadReason}. Problem: broad root overrides can silently capture future or unrelated consumers, widen rollback scope, and hide the exact repaired incident edge during forensics. Importance: high, because this creates repository-wide root control-plane technical debt.`,
    });
  }

  if (invalidEntryCount > 0) {
    return;
  }

  pushCheck(checks, {
    file: PNPM_WORKSPACE_BASENAME,
    property: 'overrides narrow selectors',
    status: 'ok',
    expected: 'exact parent-edge selectors only',
    actual: entries.length === 1 ? '1 narrow override selector' : `${entries.length} narrow override selectors`,
    message: 'overrides entries are scoped to exact parent-edge graph repairs only.',
  });
}

function auditOverridesExactVersionTargets(
  checks: GovernanceCheck[],
  workspace: Record<string, unknown>,
): void {
  const actual = getNestedValue(workspace, 'overrides');
  if (!isPlainObject(actual) || Object.keys(actual).length === 0) {
    return;
  }

  const entries = Object.entries(actual).sort(([leftSelector], [rightSelector]) =>
    leftSelector.localeCompare(rightSelector),
  );
  const invalidEntries = entries.filter(([, selectorTarget]) => !isCanonicalExactSemverString(selectorTarget));

  if (invalidEntries.length > 0) {
    for (const [selector, selectorTarget] of invalidEntries) {
      pushCheck(checks, {
        file: PNPM_WORKSPACE_BASENAME,
        property: `overrides.${selector}`,
        status: 'invalid',
        expected: 'exact semver like 1.2.3',
        actual: formatValue(selectorTarget),
        message: `overrides.${selector} must point to one explicit exact semver version only. Why: non-exact targets are too broad for a reviewed root graph-repair surface. Problem: latest, open ranges, wildcards, logical OR selectors, protocol indirection, or removal-style targets can drift resolution semantics, widen blast radius, and make rollback or forensics ambiguous. Importance: high, because root overrides must stay auditable and incident-scoped.`,
      });
    }
    return;
  }

  pushCheck(checks, {
    file: PNPM_WORKSPACE_BASENAME,
    property: 'overrides exact versions',
    status: 'ok',
    expected: 'exact semver override targets only',
    actual: entries.length === 1 ? '1 exact override target' : `${entries.length} exact override targets`,
    message: 'overrides values are present and pinned to explicit exact semver versions only.',
  });
}

function pushEqualityCheck(
  checks: GovernanceCheck[],
  object: Record<string, unknown>,
  fileName: string,
  property: string,
  expected: unknown,
  displayProperty = property,
): void {
  const actual = getNestedValue(object, property);
  if (actual === undefined) {
    pushCheck(checks, {
      file: fileName,
      property: displayProperty,
      status: 'missing',
      expected: formatValue(expected),
      message: `${displayProperty} is required.`,
    });
    return;
  }

  if (actual !== expected) {
    pushCheck(checks, {
      file: fileName,
      property: displayProperty,
      status: 'invalid',
      expected: formatValue(expected),
      actual: formatValue(actual),
      message: `${displayProperty} must be ${formatValue(expected)}.`,
    });
    return;
  }

  pushCheck(checks, {
    file: fileName,
    property: displayProperty,
    status: 'ok',
    expected: formatValue(expected),
    actual: formatValue(actual),
    message: `${displayProperty} is ${formatValue(expected)}.`,
  });
}

function summarizeGovernance(
  projects: readonly GovernanceProjectReport[],
  pnpmRuntime: PnpmRuntimeInfo,
): GovernanceAuditSummary {
  const summary: GovernanceAuditSummary = {
    projectCount: projects.length,
    rootProjectCount: 0,
    nestedPnpmDomainCount: 0,
    pnpmProjectCount: 0,
    pnpmSingleProjectCount: 0,
    pnpmMonorepoCount: 0,
    standalonePnpmSingleProjectCount: 0,
    rootPnpmMonorepoCount: 0,
    nestedPnpmSingleProjectCount: 0,
    nestedPnpmMonorepoCount: 0,
    nonPnpmNodeProjectCount: 0,
    passCount: 0,
    failCount: 0,
    warningCount: 0,
    machineWarning: null,
  };

  for (const project of projects) {
    const isNestedDomain = project.topology?.role === 'nested-domain';
    if (isNestedDomain) {
      summary.nestedPnpmDomainCount += 1;
    } else {
      summary.rootProjectCount += 1;
    }

    if (project.classification.isPnpmProject) {
      summary.pnpmProjectCount += 1;
    } else if (project.classification.kind === 'node-project') {
      summary.nonPnpmNodeProjectCount += 1;
    }

    if (project.classification.kind === 'pnpm-single-project') {
      summary.pnpmSingleProjectCount += 1;
      if (isNestedDomain) {
        summary.nestedPnpmSingleProjectCount += 1;
      } else {
        summary.standalonePnpmSingleProjectCount += 1;
      }
    }
    if (project.classification.kind === 'pnpm-monorepo') {
      summary.pnpmMonorepoCount += 1;
      if (isNestedDomain) {
        summary.nestedPnpmMonorepoCount += 1;
      } else {
        summary.rootPnpmMonorepoCount += 1;
      }
    }

    if (project.status === 'passed') {
      summary.passCount += 1;
    } else if (project.status === 'failed') {
      summary.failCount += 1;
    } else {
      summary.warningCount += 1;
    }
  }

  summary.machineWarning = pnpmRuntime.warning;
  return summary;
}

function summarizeProjectChecks(checks: readonly GovernanceCheck[]): GovernanceProjectSummary {
  return checks.reduce(
    (summary, check) => {
      if (check.status === 'ok') {
        summary.okCount += 1;
      } else if (check.status === 'warning') {
        summary.warningCount += 1;
      } else if (check.status === 'missing') {
        summary.missingCount += 1;
      } else if (check.status === 'invalid') {
        summary.invalidCount += 1;
      }
      return summary;
    },
    {
      okCount: 0,
      warningCount: 0,
      missingCount: 0,
      invalidCount: 0,
    },
  );
}

function classifyAuditStatus(
  classification: GovernanceProjectClassification,
  summary: GovernanceProjectSummary,
): GovernanceProjectStatus {
  if (!classification.isPnpmProject) {
    return 'warning';
  }
  if (summary.invalidCount > 0 || summary.missingCount > 0) {
    return 'failed';
  }
  if (summary.warningCount > 0) {
    return 'warning';
  }
  return 'passed';
}

function pushCheck(checks: GovernanceCheck[], check: GovernanceCheckInput): void {
  checks.push({
    file: check.file,
    property: check.property,
    status: check.status,
    presentationTone: check.presentationTone ?? 'default',
    expected: check.expected ?? null,
    actual: check.actual ?? null,
    message: check.message,
  });
}

function getNestedValue(target: Record<string, unknown>, propertyPath: string): unknown {
  let current: unknown = target;
  for (const key of String(propertyPath).split('.')) {
    if (!isObjectRecord(current)) {
      return undefined;
    }
    current = current[key];
  }
  return current;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function isCanonicalExactSemverString(value: unknown): boolean {
  if (typeof value !== 'string') {
    return false;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 && semver.valid(trimmed) === trimmed;
}

function isExactPackageVersionSelector(value: unknown): boolean {
  if (typeof value !== 'string') {
    return false;
  }

  const trimmed = value.trim();
  if (trimmed.length === 0) {
    return false;
  }

  const versionSeparatorIndex = trimmed.lastIndexOf('@');
  if (versionSeparatorIndex <= 0 || versionSeparatorIndex === trimmed.length - 1) {
    return false;
  }

  const packageName = trimmed.slice(0, versionSeparatorIndex);
  const version = trimmed.slice(versionSeparatorIndex + 1);

  return isCanonicalPackageSelectorName(packageName) && isCanonicalExactSemverString(version);
}

function explainBroadOverrideSelector(value: unknown): string | null {
  if (typeof value !== 'string') {
    return 'the selector is not a string and therefore cannot identify one exact parent edge';
  }

  const trimmed = value.trim();
  if (trimmed.length === 0) {
    return 'the selector is empty and therefore cannot identify one exact parent edge';
  }

  const firstEdgeSeparatorIndex = trimmed.indexOf('>');
  const lastEdgeSeparatorIndex = trimmed.lastIndexOf('>');
  if (
    firstEdgeSeparatorIndex <= 0
    || firstEdgeSeparatorIndex !== lastEdgeSeparatorIndex
    || firstEdgeSeparatorIndex === trimmed.length - 1
  ) {
    return 'it does not identify exactly one reviewed parent dependency edge';
  }

  const parentSelector = trimmed.slice(0, firstEdgeSeparatorIndex).trim();
  const childSelector = trimmed.slice(firstEdgeSeparatorIndex + 1).trim();

  if (!isExactPackageVersionSelector(parentSelector)) {
    return 'the parent consumer is not pinned to one exact version, so future parent drift could silently inherit the rewrite';
  }

  if (!isCanonicalPackageSelectorName(childSelector)) {
    return 'the child dependency is not named as one canonical package selector';
  }

  return null;
}

function isCanonicalPackageSelectorName(value: string): boolean {
  if (value.startsWith('@')) {
    return /^@[^/\s]+\/[^@\s/]+$/u.test(value);
  }
  return /^[^@\s/][^@\s/]*$/u.test(value);
}

function getFortressExceptionSurfaceViolationMessage(
  property: string,
  emptyState: '[]' | '{}',
): string {
  switch (property) {
    case 'trustPolicyExclude':
      return 'trustPolicyExclude must stay empty in Fortress mode. This still fails governance. The yellow presentation only marks a temporary architectural exception surface; in a strict Supply Chain Fortress architecture the target end-state is [] again. Replace the exclusions with stronger trust-policy or registry governance and drive trustPolicyExclude back to [].';
    case 'overrides':
      return 'overrides must stay empty in Fortress mode. This still fails governance. The yellow presentation only marks a temporary architectural exception surface; in a strict Supply Chain Fortress architecture the target end-state is {} again. Replace overrides with canonical catalog or dependency policy changes and drive overrides back to {}.';
    case 'packageExtensions':
      return 'packageExtensions must stay empty in Fortress mode. This still fails governance. The yellow presentation only marks a temporary architectural exception surface; in a strict Supply Chain Fortress architecture the target end-state is {} again. Replace packageExtensions with upstream manifest fixes or canonical package policy changes and drive packageExtensions back to {}.';
    default:
      return `${property} must stay empty in Fortress mode. This still fails governance. The yellow presentation only marks a temporary architectural exception surface; in a strict Supply Chain Fortress architecture the target end-state is ${emptyState} again. Replace the configured values with stronger canonical controls and drive ${property} back to ${emptyState}.`;
  }
}

function formatValue(value: unknown): string {
  if (value === undefined) {
    return 'unset';
  }
  if (typeof value === 'string') {
    return value;
  }
  return JSON.stringify(value);
}

function safeRealpath(fullPath: string): string {
  try {
    return fs.realpathSync.native(fullPath);
  } catch {
    return path.resolve(fullPath);
  }
}

function isDirectorySymlink(fullPath: string): boolean {
  try {
    return fs.lstatSync(fullPath).isSymbolicLink() && Boolean(statSafe(fullPath)?.isDirectory());
  } catch {
    return false;
  }
}

function isPathInside(candidatePath: string, ancestorPath: string): boolean {
  const relative = path.relative(ancestorPath, candidatePath);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

function depthOf(fullPath: string): number {
  return path.resolve(fullPath).split(path.sep).length;
}
