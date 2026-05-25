import fs from 'node:fs';
import path from 'node:path';

import { minimatch } from 'minimatch';
import semver from 'semver';
import YAML from 'yaml';

import {
  CURRENT_NODE_LTS,
  GOVERNANCE_OWNER_SENTINEL_BASENAMES,
  MANIFEST_DEPENDENCY_SECTIONS,
  MONOREPO_WORKSPACE_ARRAY_RULES,
  MONOREPO_WORKSPACE_EXACT_RULES,
  PNPM_LOCKFILE_BASENAME,
  PNPM_RECOMMENDED_SECURITY_PROPERTIES,
  PNPM_WORKSPACE_BASENAME,
  PROJECT_AUTH_FILE_BASENAMES,
  REQUIRED_PNPM_MAJOR,
  SECURITY_EXCEPTION_WORKSPACE_RULES,
  SHARED_WORKSPACE_EMPTY_ARRAY_RULES,
  SHARED_WORKSPACE_EMPTY_OBJECT_RULES,
  SHARED_WORKSPACE_EXACT_RULES,
  SHARED_WORKSPACE_OBJECT_RULES,
  SINGLE_PROJECT_FORBIDDEN_WORKSPACE_RULES,
  classifyGovernanceUnmanagedPath,
  isAllowedProjectNpmrcKey,
  isForbiddenProjectTokenHelperKey,
  isGovernanceDiscoveryExcludedDirName,
} from '../domain/pnpm-governance.mjs';
import { SCAN_MODE_MACHINE } from '../domain/policy.mjs';
import {
  direntIsDirectory,
  fileExists,
  normalizeForDisplay,
  normalizeSlashes,
  readFileTextSafe,
  readJsonSafe,
  statSafe,
} from '../infrastructure/fs-utils.mjs';
import { commandExists, runCommand } from '../infrastructure/process-utils.mjs';

const GITIGNORE_BASENAME = '.gitignore';
const PACKAGE_JSON_BASENAME = 'package.json';
const PROJECT_ROOT_SENTINELS = new Set([
  PACKAGE_JSON_BASENAME,
  PNPM_WORKSPACE_BASENAME,
]);
const GOVERNANCE_DISCOVERY_REASON_UNMANAGED_PATH = 'unmanaged-path';
const GOVERNANCE_DISCOVERY_REASON_MISSING_OWNERSHIP = 'missing-ownership';

export function inspectPnpmRuntime() {
  const runtime = detectPnpmRuntimeVersion();
  if (!runtime.available) {
    return {
      available: false,
      version: null,
      major: null,
      requiredMajor: REQUIRED_PNPM_MAJOR,
      matchesRequiredMajor: false,
      warning: runtime.warning ?? `pnpm is not installed on this machine. Install pnpm ${REQUIRED_PNPM_MAJOR}.x to activate Fortress governance settings.`,
    };
  }

  const versionText = runtime.version;
  const major = versionText ? semver.major(versionText) : null;
  return {
    available: true,
    version: versionText,
    major,
    requiredMajor: REQUIRED_PNPM_MAJOR,
    matchesRequiredMajor: major === REQUIRED_PNPM_MAJOR,
    warning:
      major === REQUIRED_PNPM_MAJOR
        ? null
        : `pnpm ${versionText ?? 'unknown'} is installed, but this policy expects pnpm ${REQUIRED_PNPM_MAJOR}.x.`,
  };
}

function detectPnpmRuntimeVersion() {
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
    warning: `pnpm is not installed on this machine. Install pnpm ${REQUIRED_PNPM_MAJOR}.x to activate Fortress governance settings.`,
  };
}

function extractSemverFromText(text) {
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

export function auditPnpmGovernance(rootPaths, options = {}, pnpmRuntime = inspectPnpmRuntime()) {
  const discovery = discoverProjectRoots(rootPaths, options);
  const auditedProjects = discovery.projectRoots
    .map((rootPath) => auditProjectRoot(rootPath, options, pnpmRuntime))
    .sort((left, right) => left.rootPath.localeCompare(right.rootPath));
  const projects = collapseWorkspaceMembers(auditedProjects);

  return {
    pnpmRuntime,
    nodeLtsFloor: CURRENT_NODE_LTS,
    recommendedProperties: PNPM_RECOMMENDED_SECURITY_PROPERTIES,
    discovery: discovery.summary,
    projects,
    summary: summarizeGovernance(projects, pnpmRuntime),
  };
}

function discoverProjectRoots(rootPaths, options) {
  const discovered = new Set();
  const visited = new Set();
  const scanRoots = [...new Set(rootPaths.map((rootPath) => path.resolve(rootPath)))];
  const explicitScanRoots = new Set(scanRoots);
  const stack = [...scanRoots];

  while (stack.length > 0) {
    const current = stack.pop();
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

    if (containsProjectRootSentinel(current)) {
      discovered.add(path.resolve(current));
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

  const candidateRoots = [...discovered].sort((left, right) => left.localeCompare(right));
  const projectRoots = [];
  const suppressedCounts = {
    unmanagedPathCount: 0,
    missingOwnershipCount: 0,
  };

  for (const candidateRoot of candidateRoots) {
    const decision = classifyGovernanceCandidateRoot(candidateRoot, explicitScanRoots, options);
    if (decision.managed) {
      projectRoots.push(candidateRoot);
      continue;
    }
    if (decision.reason === GOVERNANCE_DISCOVERY_REASON_UNMANAGED_PATH) {
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

function containsProjectRootSentinel(rootPath) {
  for (const fileName of PROJECT_ROOT_SENTINELS) {
    if (fileExists(path.join(rootPath, fileName))) {
      return true;
    }
  }
  return false;
}

function shouldSkipGovernanceDirectory(dirName, options) {
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

function shouldSkipGovernancePath(fullPath, options, explicitScanRoots) {
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

function classifyGovernanceCandidateRoot(rootPath, explicitScanRoots, options) {
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

function hasGovernanceOwnershipSignal(rootPath) {
  return GOVERNANCE_OWNER_SENTINEL_BASENAMES.some((basename) =>
    fileExists(path.join(rootPath, basename)),
  );
}

function collapseWorkspaceMembers(projects) {
  const accepted = [];
  const monorepos = [];

  for (const project of [...projects].sort((left, right) => depthOf(left.rootPath) - depthOf(right.rootPath))) {
    const parentMonorepo = monorepos.find((candidate) =>
      isWorkspaceMemberProject(project.rootPath, candidate),
    );
    if (parentMonorepo) {
      continue;
    }

    accepted.push(project);
    if (project.classification.kind === 'pnpm-monorepo') {
      monorepos.push(project);
    }
  }

  return accepted.sort((left, right) => left.rootPath.localeCompare(right.rootPath));
}

function isWorkspaceMemberProject(projectRootPath, monorepoProject) {
  if (!isPathInside(projectRootPath, monorepoProject.rootPath)) {
    return false;
  }
  return (monorepoProject.workspaceMembers ?? []).some((member) => member.rootPath === projectRootPath);
}

function auditProjectRoot(rootPath, options, pnpmRuntime) {
  const packageJsonPath = path.join(rootPath, PACKAGE_JSON_BASENAME);
  const workspacePath = path.join(rootPath, PNPM_WORKSPACE_BASENAME);
  const pnpmLockfilePath = path.join(rootPath, PNPM_LOCKFILE_BASENAME);
  const npmrcPath = path.join(rootPath, '.npmrc');
  const authIniPath = path.join(rootPath, 'auth.ini');
  const gitignorePath = path.join(rootPath, GITIGNORE_BASENAME);

  const packageJson = readJsonSafe(packageJsonPath);
  const workspaceDocument = readYamlSafe(workspacePath);
  const checks = [];
  const workspaceMembers = [];

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
    auditPnpmRuntime(checks, pnpmRuntime);
    auditWorkspaceFile(checks, classification, workspaceDocument);
    auditRootPackageJson(checks, packageJson, classification);
    auditLockfile(checks, pnpmLockfilePath);
    auditProjectAuthFiles(checks, gitignorePath, [npmrcPath, authIniPath]);

    if (classification.kind === 'pnpm-monorepo' && workspaceDocument.value) {
      const members = discoverWorkspaceMembers(rootPath, workspaceDocument.value.packages);
      workspaceMembers.push(...members);
      auditWorkspaceMembers(checks, rootPath, members, packageJson.value);
    }
  } else {
    pushCheck(checks, {
      file: PACKAGE_JSON_BASENAME,
      property: 'packageManager',
      status: 'warning',
      message: `Node project at ${normalizeForDisplay(rootPath)} is not governed by PNPM ${REQUIRED_PNPM_MAJOR}.x Fortress settings.`,
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

function classifyProject(rootPath, packageJson, workspaceDocument, pnpmLockfilePath) {
  const signals = [];
  const workspaceRawText = workspaceDocument.rawText ?? '';
  const hasWorkspaceFile = fileExists(path.join(rootPath, PNPM_WORKSPACE_BASENAME));
  const hasPackageJson = fileExists(path.join(rootPath, PACKAGE_JSON_BASENAME));
  const packageManagerField = typeof packageJson?.packageManager === 'string' ? packageJson.packageManager : null;
  const devEnginePackageManager = packageJson?.devEngines?.packageManager;
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

  const workspaceValue = workspaceDocument.value;
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

function auditPnpmRuntime(checks, pnpmRuntime) {
  if (!pnpmRuntime.available) {
    pushCheck(checks, {
      file: 'machine',
      property: 'pnpm',
      status: 'warning',
      expected: `pnpm ${REQUIRED_PNPM_MAJOR}.x installed`,
      actual: 'missing',
      message: pnpmRuntime.warning,
    });
    return;
  }

  pushCheck(checks, {
    file: 'machine',
    property: 'pnpm',
    status: pnpmRuntime.matchesRequiredMajor ? 'ok' : 'warning',
    expected: `pnpm ${REQUIRED_PNPM_MAJOR}.x`,
    actual: pnpmRuntime.version ?? 'unknown',
    message: pnpmRuntime.matchesRequiredMajor
      ? `pnpm ${pnpmRuntime.version} is installed on this machine.`
      : pnpmRuntime.warning,
  });
}

function auditWorkspaceFile(checks, classification, workspaceDocument) {
  if (!workspaceDocument.value) {
    if (!workspaceDocument.rawText) {
      pushCheck(checks, {
        file: PNPM_WORKSPACE_BASENAME,
        property: PNPM_WORKSPACE_BASENAME,
        status: 'missing',
        message: `${PNPM_WORKSPACE_BASENAME} is required for PNPM ${REQUIRED_PNPM_MAJOR}.x governance.`,
      });
    }
    return;
  }

  const workspace = workspaceDocument.value;

  for (const [property, expected] of SHARED_WORKSPACE_EXACT_RULES) {
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

  auditExactSemverFloor(checks, workspace, PNPM_WORKSPACE_BASENAME, 'nodeVersion', CURRENT_NODE_LTS.version);
  auditHttpsRegistry(checks, workspace, PNPM_WORKSPACE_BASENAME, 'registries.default');

  for (const property of SHARED_WORKSPACE_EMPTY_ARRAY_RULES) {
    auditEmptyArray(checks, workspace, PNPM_WORKSPACE_BASENAME, property);
  }
  for (const property of SHARED_WORKSPACE_EMPTY_OBJECT_RULES) {
    auditEmptyObject(checks, workspace, PNPM_WORKSPACE_BASENAME, property);
  }
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

function auditRootPackageJson(checks, packageJson, classification) {
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

  const manifest = packageJson.value;
  auditPackageManagerField(checks, manifest);
  auditEnginesNode(checks, manifest);
  auditDevRuntime(checks, manifest);
  auditDevPackageManager(checks, manifest);

  if (manifest.pnpm !== undefined) {
    pushCheck(checks, {
      file: PACKAGE_JSON_BASENAME,
      property: 'pnpm',
      status: 'invalid',
      message: 'PNPM 11 no longer reads settings from package.json#pnpm. Move policy into pnpm-workspace.yaml.',
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

function auditPackageManagerField(checks, manifest) {
  const rawValue = manifest.packageManager;
  if (typeof rawValue !== 'string') {
    pushCheck(checks, {
      file: PACKAGE_JSON_BASENAME,
      property: 'packageManager',
      status: 'missing',
      expected: `pnpm@${REQUIRED_PNPM_MAJOR}.x`,
      message: 'packageManager must pin PNPM 11 explicitly.',
    });
    return;
  }

  const match = rawValue.match(/^pnpm@(.+)$/u);
  if (!match) {
    pushCheck(checks, {
      file: PACKAGE_JSON_BASENAME,
      property: 'packageManager',
      status: 'invalid',
      expected: `pnpm@${REQUIRED_PNPM_MAJOR}.x`,
      actual: rawValue,
      message: 'packageManager must point to pnpm.',
    });
    return;
  }

  const version = semver.coerce(match[1])?.version ?? null;
  if (!version || semver.major(version) !== REQUIRED_PNPM_MAJOR) {
    pushCheck(checks, {
      file: PACKAGE_JSON_BASENAME,
      property: 'packageManager',
      status: 'invalid',
      expected: `pnpm@${REQUIRED_PNPM_MAJOR}.x`,
      actual: rawValue,
      message: `packageManager must pin PNPM ${REQUIRED_PNPM_MAJOR}.x.`,
    });
    return;
  }

  pushCheck(checks, {
    file: PACKAGE_JSON_BASENAME,
    property: 'packageManager',
    status: 'ok',
    expected: `pnpm@${REQUIRED_PNPM_MAJOR}.x`,
    actual: rawValue,
    message: `packageManager pins ${rawValue}.`,
  });
}

function auditEnginesNode(checks, manifest) {
  const enginesNode = manifest?.engines?.node;
  if (typeof enginesNode !== 'string') {
    pushCheck(checks, {
      file: PACKAGE_JSON_BASENAME,
      property: 'engines.node',
      status: 'missing',
      expected: `minimum ${CURRENT_NODE_LTS.version}`,
      message: 'engines.node must declare at least the current Node.js LTS floor.',
    });
    return;
  }

  const minimum = semver.minVersion(enginesNode);
  if (!minimum || semver.lt(minimum, CURRENT_NODE_LTS.version)) {
    pushCheck(checks, {
      file: PACKAGE_JSON_BASENAME,
      property: 'engines.node',
      status: 'invalid',
      expected: `minimum ${CURRENT_NODE_LTS.version}`,
      actual: enginesNode,
      message: `engines.node must not allow versions below ${CURRENT_NODE_LTS.version}.`,
    });
    return;
  }

  pushCheck(checks, {
    file: PACKAGE_JSON_BASENAME,
    property: 'engines.node',
    status: 'ok',
    expected: `minimum ${CURRENT_NODE_LTS.version}`,
    actual: enginesNode,
    message: `engines.node starts at ${minimum.version}.`,
  });
}

function auditDevRuntime(checks, manifest) {
  const runtime = manifest?.devEngines?.runtime;
  if (!runtime || typeof runtime !== 'object') {
    pushCheck(checks, {
      file: PACKAGE_JSON_BASENAME,
      property: 'devEngines.runtime',
      status: 'missing',
      message: 'devEngines.runtime must pin the Node.js runtime contract.',
    });
    return;
  }

  if (runtime.name !== 'node') {
    pushCheck(checks, {
      file: PACKAGE_JSON_BASENAME,
      property: 'devEngines.runtime.name',
      status: 'invalid',
      expected: 'node',
      actual: formatValue(runtime.name),
      message: 'devEngines.runtime.name must be "node".',
    });
  } else {
    pushCheck(checks, {
      file: PACKAGE_JSON_BASENAME,
      property: 'devEngines.runtime.name',
      status: 'ok',
      expected: 'node',
      actual: 'node',
      message: 'devEngines.runtime.name is node.',
    });
  }

  const version = typeof runtime.version === 'string' ? runtime.version : null;
  if (!version) {
    pushCheck(checks, {
      file: PACKAGE_JSON_BASENAME,
      property: 'devEngines.runtime.version',
      status: 'missing',
      expected: `minimum ${CURRENT_NODE_LTS.version}`,
      message: 'devEngines.runtime.version must be declared.',
    });
  } else {
    const minimum = semver.minVersion(version);
    if (!minimum || semver.lt(minimum, CURRENT_NODE_LTS.version)) {
      pushCheck(checks, {
        file: PACKAGE_JSON_BASENAME,
        property: 'devEngines.runtime.version',
        status: 'invalid',
        expected: `minimum ${CURRENT_NODE_LTS.version}`,
        actual: version,
        message: `devEngines.runtime.version must not allow versions below ${CURRENT_NODE_LTS.version}.`,
      });
    } else {
      pushCheck(checks, {
        file: PACKAGE_JSON_BASENAME,
        property: 'devEngines.runtime.version',
        status: 'ok',
        expected: `minimum ${CURRENT_NODE_LTS.version}`,
        actual: version,
        message: `devEngines.runtime.version starts at ${minimum.version}.`,
      });
    }
  }

  pushEqualityCheck(checks, runtime, PACKAGE_JSON_BASENAME, 'onFail', 'error', 'devEngines.runtime.onFail');
}

function auditDevPackageManager(checks, manifest) {
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
      expected: `${REQUIRED_PNPM_MAJOR}.x`,
      message: 'devEngines.packageManager.version must target PNPM 11.',
    });
  } else {
    const minimum = semver.minVersion(version);
    if (!minimum || semver.major(minimum) !== REQUIRED_PNPM_MAJOR) {
      pushCheck(checks, {
        file: PACKAGE_JSON_BASENAME,
        property: 'devEngines.packageManager.version',
        status: 'invalid',
        expected: `${REQUIRED_PNPM_MAJOR}.x`,
        actual: version,
        message: `devEngines.packageManager.version must target PNPM ${REQUIRED_PNPM_MAJOR}.x.`,
      });
    } else {
      pushCheck(checks, {
        file: PACKAGE_JSON_BASENAME,
        property: 'devEngines.packageManager.version',
        status: 'ok',
        expected: `${REQUIRED_PNPM_MAJOR}.x`,
        actual: version,
        message: `devEngines.packageManager.version starts at ${minimum.version}.`,
      });
    }
  }

  pushEqualityCheck(checks, packageManager, PACKAGE_JSON_BASENAME, 'onFail', 'error', 'devEngines.packageManager.onFail');
}

function auditLockfile(checks, pnpmLockfilePath) {
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

function auditProjectAuthFiles(checks, gitignorePath, authFilePaths) {
  const gitignorePatterns = readGitignorePatterns(gitignorePath);
  for (const authFilePath of authFilePaths) {
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
          message: `${key} is not allowed in a project-local auth file. tokenHelper is user-local only.`,
        });
        continue;
      }
      if (!isAllowedProjectNpmrcKey(key)) {
        pushCheck(checks, {
          file: basename,
          property: key,
          status: 'invalid',
          message: `${key} is not an allowed project-local PNPM auth or certificate property.`,
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

function auditWorkspaceMembers(checks, rootPath, members, rootPackageJson) {
  if (members.length === 0) {
    pushCheck(checks, {
      file: PNPM_WORKSPACE_BASENAME,
      property: 'packages',
      status: 'invalid',
      message: 'The workspace declares package globs, but no workspace package.json files were discovered.',
    });
    return;
  }

  const workspaceNameToRoot = new Map();
  for (const member of members) {
    if (member.packageJson?.value?.name) {
      workspaceNameToRoot.set(member.packageJson.value.name, member.rootPath);
    }
  }

  for (const member of members) {
    if (!member.packageJson.rawText || !member.packageJson.value) {
      pushCheck(checks, {
        file: normalizeForDisplay(path.join(member.rootPath, PACKAGE_JSON_BASENAME)),
        property: PACKAGE_JSON_BASENAME,
        status: 'invalid',
        message: `Workspace package at ${normalizeForDisplay(member.rootPath)} has an unreadable or invalid package.json.`,
      });
      continue;
    }

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

    auditWorkspaceProtocolUsage(checks, member.packageJson.value, member.rootPath, workspaceNameToRoot);
  }

  if (rootPackageJson && typeof rootPackageJson === 'object') {
    auditWorkspaceProtocolUsage(checks, rootPackageJson, rootPath, workspaceNameToRoot);
  }
}

function auditWorkspaceProtocolUsage(checks, manifest, manifestRootPath, workspaceNameToRoot) {
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

function discoverWorkspaceMembers(rootPath, workspacePatterns) {
  if (!Array.isArray(workspacePatterns)) {
    return [];
  }

  const normalizedPatterns = workspacePatterns.filter((pattern) => typeof pattern === 'string');
  const positivePatterns = normalizedPatterns.filter((pattern) => !pattern.startsWith('!'));
  const negativePatterns = normalizedPatterns
    .filter((pattern) => pattern.startsWith('!'))
    .map((pattern) => pattern.slice(1));

  const discovered = [];
  const stack = [rootPath];
  const visited = new Set();

  while (stack.length > 0) {
    const current = stack.pop();
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

function matchesWorkspacePattern(relativeRoot, positivePatterns, negativePatterns) {
  if (positivePatterns.length === 0) {
    return false;
  }
  const positive = positivePatterns.some((pattern) => minimatch(relativeRoot, pattern, { dot: true }));
  if (!positive) {
    return false;
  }
  return !negativePatterns.some((pattern) => minimatch(relativeRoot, pattern, { dot: true }));
}

function readYamlSafe(filePath) {
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

function readTextOrNull(filePath) {
  try {
    return readFileTextSafe(filePath);
  } catch {
    return null;
  }
}

function readGitignorePatterns(gitignorePath) {
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

function isAuthFileGitignored(basename, patterns) {
  return patterns.some((pattern) => {
    const normalizedPattern = pattern.replace(/\\/g, '/');
    return normalizedPattern === basename || normalizedPattern === `/${basename}`;
  });
}

function parseNpmrcKeys(filePath) {
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

function auditNumericMinimum(checks, object, fileName, property, minimumExpected, expectedLabel) {
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

function auditNumericMaximum(checks, object, fileName, property, maximumExpected, expectedLabel) {
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

function auditExactSemverFloor(checks, object, fileName, property, minimumVersion) {
  const actual = getNestedValue(object, property);
  const valid = typeof actual === 'string' ? semver.valid(actual) : null;
  if (!valid) {
    pushCheck(checks, {
      file: fileName,
      property,
      status: 'missing',
      expected: `exact semver >= ${minimumVersion}`,
      actual: formatValue(actual),
      message: `${property} must be an exact semver string.`,
    });
    return;
  }

  if (semver.lt(valid, minimumVersion)) {
    pushCheck(checks, {
      file: fileName,
      property,
      status: 'invalid',
      expected: `exact semver >= ${minimumVersion}`,
      actual: valid,
      message: `${property} is below the current Node.js LTS floor ${minimumVersion}.`,
    });
    return;
  }

  pushCheck(checks, {
    file: fileName,
    property,
    status: 'ok',
    expected: `exact semver >= ${minimumVersion}`,
    actual: valid,
    message: `${property} is pinned to ${valid}.`,
  });
}

function auditHttpsRegistry(checks, object, fileName, property) {
  const actual = getNestedValue(object, property);
  if (typeof actual !== 'string') {
    pushCheck(checks, {
      file: fileName,
      property,
      status: 'missing',
      expected: 'HTTPS registry URL',
      actual: formatValue(actual),
      message: `${property} must point to an approved HTTPS registry.`,
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
      message: `${property} must use https.`,
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

function auditEmptyArray(checks, object, fileName, property) {
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
      expected: '[]',
      actual: formatValue(actual),
      message: `${property} must stay empty in Fortress mode.`,
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

function auditNonEmptyArray(checks, object, fileName, property) {
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

function auditArraySurface(checks, object, fileName, property) {
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

function auditEmptyObject(checks, object, fileName, property) {
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
      expected: '{}',
      actual: formatValue(actual),
      message: `${property} must stay empty in Fortress mode.`,
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

function auditObjectSurface(checks, object, fileName, property) {
  const actual = getNestedValue(object, property);
  if (!isPlainObject(actual)) {
    pushCheck(checks, {
      file: fileName,
      property,
      status: 'missing',
      expected: 'object',
      actual: formatValue(actual),
      message: `${property} must be present as an object.`,
    });
    return;
  }

  pushCheck(checks, {
    file: fileName,
    property,
    status: 'ok',
    expected: 'object',
    actual: `${Object.keys(actual).length} keys`,
    message: `${property} is present as an object.`,
  });
}

function auditAllowBuildsSurface(checks, workspace) {
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

function auditCatalogExactVersions(checks, workspace) {
  const catalog = getNestedValue(workspace, 'catalog');
  if (!isPlainObject(catalog)) {
    return;
  }

  const entries = Object.entries(catalog).sort(([leftName], [rightName]) => leftName.localeCompare(rightName));
  const invalidEntries = entries.filter(([, specifier]) => !isCanonicalExactSemverString(specifier));

  if (invalidEntries.length > 0) {
    for (const [packageName, specifier] of invalidEntries) {
      pushCheck(checks, {
        file: PNPM_WORKSPACE_BASENAME,
        property: `catalog.${packageName}`,
        status: 'invalid',
        expected: 'exact semver like 1.2.3',
        actual: formatValue(specifier),
        message: 'Catalog entries must use explicit exact versions without ranges such as ^ or ~.',
      });
    }
    return;
  }

  pushCheck(checks, {
    file: PNPM_WORKSPACE_BASENAME,
    property: 'catalog exact versions',
    status: 'ok',
    expected: 'exact semver only',
    actual: entries.length === 1 ? '1 exact entry' : `${entries.length} exact entries`,
    message: entries.length === 0
      ? 'catalog is present as an empty approval map. Future entries must use explicit exact semver versions.'
      : 'catalog entries use explicit exact semver versions only.',
  });
}

function pushEqualityCheck(checks, object, fileName, property, expected, displayProperty = property) {
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

function summarizeGovernance(projects, pnpmRuntime) {
  const summary = {
    projectCount: projects.length,
    pnpmProjectCount: 0,
    pnpmSingleProjectCount: 0,
    pnpmMonorepoCount: 0,
    nonPnpmNodeProjectCount: 0,
    passCount: 0,
    failCount: 0,
    warningCount: 0,
  };

  for (const project of projects) {
    if (project.classification.isPnpmProject) {
      summary.pnpmProjectCount += 1;
    } else if (project.classification.kind === 'node-project') {
      summary.nonPnpmNodeProjectCount += 1;
    }

    if (project.classification.kind === 'pnpm-single-project') {
      summary.pnpmSingleProjectCount += 1;
    }
    if (project.classification.kind === 'pnpm-monorepo') {
      summary.pnpmMonorepoCount += 1;
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

function summarizeProjectChecks(checks) {
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

function classifyAuditStatus(classification, summary) {
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

function pushCheck(checks, check) {
  checks.push({
    file: check.file,
    property: check.property,
    status: check.status,
    expected: check.expected ?? null,
    actual: check.actual ?? null,
    message: check.message,
  });
}

function getNestedValue(target, propertyPath) {
  return String(propertyPath)
    .split('.')
    .reduce((current, key) => (current == null ? undefined : current[key]), target);
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function isCanonicalExactSemverString(value) {
  if (typeof value !== 'string') {
    return false;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 && semver.valid(trimmed) === trimmed;
}

function formatValue(value) {
  if (value === undefined) {
    return 'unset';
  }
  if (typeof value === 'string') {
    return value;
  }
  return JSON.stringify(value);
}

function safeRealpath(fullPath) {
  try {
    return fs.realpathSync.native(fullPath);
  } catch {
    return path.resolve(fullPath);
  }
}

function isDirectorySymlink(fullPath) {
  try {
    return fs.lstatSync(fullPath).isSymbolicLink() && Boolean(statSafe(fullPath)?.isDirectory());
  } catch {
    return false;
  }
}

function isPathInside(candidatePath, ancestorPath) {
  const relative = path.relative(ancestorPath, candidatePath);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

function depthOf(fullPath) {
  return path.resolve(fullPath).split(path.sep).length;
}
