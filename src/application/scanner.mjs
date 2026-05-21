import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { Worker } from 'node:worker_threads';

import { addFinding, createFindingsContainer, mergeFindings } from '../domain/findings.mjs';
import {
  EXTRA_SCAN_FILE_BASENAMES,
  LOCKFILE_NAMES,
  PACKAGE_JSON_NAME,
  SCAN_CANDIDATE_BASENAMES,
  SCAN_MODE_MACHINE,
  broadContentIndicators,
  dataset,
  exactRulesByName,
  ripgrepLiteralPatterns,
  shouldSkipDirectory,
  suspiciousPackageFileRulesByBasename,
  suspiciousPresenceBasenameRules,
  workflowSupportIndicators,
} from '../domain/policy.mjs';
import {
  direntIsDirectory,
  direntIsFile,
  escapeRegExp,
  fileExists,
  normalizeForDisplay,
  normalizeSlashes,
  platformMatches,
  readFileTextSafe,
  readJsonSafe,
  statSafe,
} from '../infrastructure/fs-utils.mjs';
import { runRipgrepLiteralScan } from '../infrastructure/ripgrep.mjs';
import { runCommand } from '../infrastructure/process-utils.mjs';

const broadIndicatorSet = new Set(broadContentIndicators);

export function createScanStats() {
  return {
    directoriesVisited: 0,
    candidateFilesVisited: 0,
    nodeModulesDirsVisited: 0,
    traversalErrors: {
      EACCES: 0,
      EPERM: 0,
      ENOENT: 0,
      OTHER: 0,
    },
  };
}

export function mergeStats(target, source) {
  if (!source) {
    return;
  }
  target.directoriesVisited += source.directoriesVisited ?? 0;
  target.candidateFilesVisited += source.candidateFilesVisited ?? 0;
  target.nodeModulesDirsVisited += source.nodeModulesDirsVisited ?? 0;
  for (const key of Object.keys(target.traversalErrors)) {
    target.traversalErrors[key] += source.traversalErrors?.[key] ?? 0;
  }
}

export function enumerateMachineRoots() {
  if (process.platform !== 'win32') {
    return ['/'];
  }

  const roots = [];
  for (let codePoint = 67; codePoint <= 90; codePoint += 1) {
    const drive = String.fromCharCode(codePoint);
    const driveRoot = `${drive}:\\`;
    const stats = statSafe(driveRoot);
    if (stats?.isDirectory()) {
      roots.push(driveRoot);
    }
  }
  return roots;
}

export function buildScanTasks(roots, mode, findings) {
  const tasks = [];
  let nextTaskId = 1;

  for (const rootPath of roots) {
    if (!rootLikelyContainsProjects(rootPath)) {
      addFinding(findings.errors, {
        type: 'missing-root',
        path: normalizeForDisplay(rootPath),
        message: `Scan root does not exist or is not a directory: ${normalizeForDisplay(rootPath)}`,
      });
      continue;
    }

    tasks.push({
      id: nextTaskId,
      rootPath,
      mode,
      shallow: true,
    });
    nextTaskId += 1;

    let entries = [];
    try {
      entries = fs.readdirSync(rootPath, { withFileTypes: true });
    } catch (error) {
      addFinding(findings.errors, {
        type: 'root-read-error',
        path: normalizeForDisplay(rootPath),
        message: `Could not enumerate ${normalizeForDisplay(rootPath)}: ${error.message}`,
      });
      continue;
    }

    for (const entry of entries) {
      const fullPath = path.join(rootPath, entry.name);
      if (!direntIsDirectory(entry, fullPath)) {
        continue;
      }
      if (entry.name === 'node_modules') {
        continue;
      }
      if (shouldSkipDirectory(entry.name, mode)) {
        continue;
      }
      tasks.push({
        id: nextTaskId,
        rootPath: fullPath,
        mode,
        shallow: false,
      });
      nextTaskId += 1;
    }
  }

  return tasks;
}

export function inspectFixedHomePaths(findings) {
  for (const rule of dataset.suspiciousHomePathPresenceRules) {
    if (!platformMatches(rule.platforms)) {
      continue;
    }
    inspectFileRuleAtPath(path.join(os.homedir(), rule.path), rule, findings);
  }

  for (const rule of dataset.suspiciousAbsolutePathRules) {
    if (!platformMatches(rule.platforms)) {
      continue;
    }
    inspectFileRuleAtPath(rule.path, rule, findings);
  }

  if (process.platform === 'win32') {
    for (const rule of dataset.suspiciousWindowsPathRules) {
      const basePath = process.env[rule.env];
      if (!basePath) {
        continue;
      }
      inspectFileRuleAtPath(path.join(basePath, rule.suffix), rule, findings);
    }
  }
}

export function inspectHomeContentRules(findings) {
  const homeRules = dataset.suspiciousProjectFileContentRules.filter((rule) =>
    ['.bashrc', '.zshrc', '.claude/settings.json'].some((suffix) =>
      normalizeSlashes(rule.relativePath).endsWith(suffix),
    ),
  );

  const candidatePaths = [
    path.join(os.homedir(), '.bashrc'),
    path.join(os.homedir(), '.zshrc'),
    path.join(os.homedir(), '.claude', 'settings.json'),
  ];

  for (const filePath of candidatePaths) {
    if (!fileExists(filePath)) {
      continue;
    }
    for (const rule of homeRules) {
      if (!normalizeSlashes(filePath).endsWith(normalizeSlashes(rule.relativePath))) {
        continue;
      }
      inspectContentRule(filePath, rule, findings);
    }
  }
}

export function inspectWindowsRegistry(findings) {
  if (process.platform !== 'win32') {
    return;
  }

  for (const rule of dataset.suspiciousWindowsRegistryRules) {
    const result = runCommand('reg', ['query', rule.key, '/v', rule.valueName]);
    if (result.status !== 0) {
      continue;
    }
    if (!result.stdout || !result.stdout.includes(rule.valueName)) {
      continue;
    }
    addFinding(findings.artifactHits, {
      type: 'windows-registry-hit',
      rule: rule.reason,
      path: `${rule.key} :: ${rule.valueName}`,
      confidence: 'high',
      message: `${rule.reason}: ${rule.key} -> ${rule.valueName}`,
    });
  }
}

export function runScanTask(task, reportProgress = () => {}) {
  const findings = createFindingsContainer();
  const stats = createScanStats();
  const taskStartedAt = Date.now();

  reportTaskProgress(reportProgress, task, 'task-started', {
    startedAt: taskStartedAt,
  });

  const discoveryStartedAt = Date.now();
  const { candidateFiles, nodeModulesDirs } = discoverScanTargets(
    task.rootPath,
    {
      mode: task.mode,
      shallow: task.shallow,
    },
    stats,
  );
  reportTaskProgress(reportProgress, task, 'discovery-complete', {
    elapsedMs: Date.now() - discoveryStartedAt,
    directoriesVisited: stats.directoriesVisited,
    candidateFilesDiscovered: candidateFiles.length,
    nodeModulesRootsDiscovered: nodeModulesDirs.length,
  });

  const projectSemanticStartedAt = Date.now();
  for (const filePath of candidateFiles) {
    scanCandidateFileSemantic(filePath, findings);
    inspectLoosePresenceByBasename(filePath, findings);
  }
  reportTaskProgress(reportProgress, task, 'project-semantic-complete', {
    elapsedMs: Date.now() - projectSemanticStartedAt,
    candidateFilesProcessed: candidateFiles.length,
  });

  reportTaskProgress(reportProgress, task, 'project-rg-started', {
    candidateFilesConsidered: candidateFiles.length,
  });
  const projectRgStartedAt = Date.now();
  const projectRgStats = applyProjectRipgrepResults(task, findings);
  reportTaskProgress(reportProgress, task, 'project-rg-complete', {
    elapsedMs: Date.now() - projectRgStartedAt,
    matchedFiles: projectRgStats.matchedFiles,
  });

  reportTaskProgress(reportProgress, task, 'node-modules-semantic-started', {
    nodeModulesRootsDiscovered: nodeModulesDirs.length,
  });
  const nodeModulesSemanticStartedAt = Date.now();
  let installedPackagesScanned = 0;
  let nodeModulesRipgrepMatchedFiles = 0;
  for (const nodeModulesDir of nodeModulesDirs) {
    const packageDirToName = scanInstalledPackagesSemantic(nodeModulesDir, findings, stats);
    installedPackagesScanned += packageDirToName.size;
    nodeModulesRipgrepMatchedFiles += applyNodeModulesRipgrepResults(nodeModulesDir, packageDirToName, findings).matchedFiles;
  }
  reportTaskProgress(reportProgress, task, 'node-modules-complete', {
    elapsedMs: Date.now() - nodeModulesSemanticStartedAt,
    nodeModulesRootsDiscovered: nodeModulesDirs.length,
    installedPackagesScanned,
    nodeModulesDirectoriesVisited: stats.nodeModulesDirsVisited,
    matchedFiles: nodeModulesRipgrepMatchedFiles,
  });

  const totalElapsedMs = Date.now() - taskStartedAt;
  reportTaskProgress(reportProgress, task, 'task-complete', {
    elapsedMs: totalElapsedMs,
    directoriesVisited: stats.directoriesVisited,
    candidateFilesVisited: stats.candidateFilesVisited,
    nodeModulesDirsVisited: stats.nodeModulesDirsVisited,
    candidateFilesDiscovered: candidateFiles.length,
    nodeModulesRootsDiscovered: nodeModulesDirs.length,
    installedPackagesScanned,
  });

  return {
    task,
    findings,
    stats,
  };
}

export async function runWorkerPool(tasks, findings, options, preflightPlan = null) {
  const mergedStats = createScanStats();

  if (tasks.length === 0) {
    return {
      scanStats: mergedStats,
      workersUsed: 0,
    };
  }

  const workerCount = Math.max(1, Math.min(options.workers, tasks.length));
  let nextIndex = 0;
  const progressState = createProgressState(tasks, workerCount, preflightPlan);

  if (options.verbose) {
    logOverallProgress(progressState, 'planned', {
      mode: tasks[0]?.mode ?? 'unknown',
      totalTasks: tasks.length,
      progressModel: progressState.progressModel,
    });
  }

  const heartbeatTimer = startScanHeartbeat(progressState, options);

  const runLoop = async () => {
    while (nextIndex < tasks.length) {
      const task = tasks[nextIndex];
      nextIndex += 1;

      let result;
      try {
        result = await createWorker(task, (event) => {
          if (!options.verbose) {
            return;
          }
          logTaskProgress(progressState, task, event);
        });
      } catch (error) {
        progressState.activeTasks.delete(task.id);
        addFinding(findings.errors, {
          type: 'worker-error',
          path: normalizeForDisplay(task.rootPath),
          message: `Worker failed for ${normalizeForDisplay(task.rootPath)}: ${error.message}`,
        });
        continue;
      }

      mergeFindings(findings, result.findings);
      mergeStats(mergedStats, result.stats);
    }
  };

  try {
    await Promise.all(Array.from({ length: workerCount }, () => runLoop()));
  } finally {
    stopScanHeartbeat(heartbeatTimer);
  }
  return {
    scanStats: mergedStats,
    workersUsed: workerCount,
  };
}

function recordTraversalError(stats, error) {
  const code = typeof error?.code === 'string' ? error.code : 'OTHER';
  if (code in stats.traversalErrors) {
    stats.traversalErrors[code] += 1;
    return;
  }
  stats.traversalErrors.OTHER += 1;
}

function rootLikelyContainsProjects(rootPath) {
  return fileExists(rootPath) && statSafe(rootPath)?.isDirectory();
}

function discoverScanTargets(rootPath, options, stats) {
  const stack = [rootPath];
  const candidateFiles = [];
  const nodeModulesDirs = [];
  const shallowRoot = Boolean(options.shallow);

  while (stack.length > 0) {
    const current = stack.pop();
    stats.directoriesVisited += 1;

    let entries = [];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch (error) {
      recordTraversalError(stats, error);
      continue;
    }

    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);

      if (direntIsDirectory(entry, fullPath)) {
        if (entry.name === 'node_modules') {
          nodeModulesDirs.push(fullPath);
          continue;
        }

        if (shouldSkipDirectory(entry.name, options.mode)) {
          continue;
        }

        if (shallowRoot && current === rootPath) {
          continue;
        }

        stack.push(fullPath);
        continue;
      }

      if (!direntIsFile(entry, fullPath)) {
        continue;
      }

      if (!isCandidateScanFile(fullPath, entry.name)) {
        continue;
      }

      candidateFiles.push(fullPath);
      stats.candidateFilesVisited += 1;
    }
  }

  return { candidateFiles, nodeModulesDirs };
}

function isCandidateScanFile(fullPath, baseName) {
  return SCAN_CANDIDATE_BASENAMES.has(baseName) || isWorkflowFile(fullPath, baseName);
}

function isWorkflowFile(filePath, baseName = path.basename(filePath)) {
  const normalized = normalizeSlashes(filePath);
  return normalized.includes('/.github/workflows/') && /\.(yml|yaml)$/i.test(baseName);
}

function scanCandidateFileSemantic(filePath, findings) {
  const baseName = path.basename(filePath);

  if (baseName === PACKAGE_JSON_NAME) {
    scanPackageJsonFile(filePath, findings);
    return;
  }

  if (LOCKFILE_NAMES.has(baseName)) {
    scanLockfile(filePath, findings);
  }
}

function scanPackageJsonFile(filePath, findings) {
  const { rawText, value } = readJsonSafe(filePath);
  if (!rawText) {
    return;
  }

  checkManifestNeedles(rawText, filePath, findings.heuristicHits);

  if (!value) {
    return;
  }

  const dependencySections = [
    'dependencies',
    'devDependencies',
    'optionalDependencies',
    'peerDependencies',
  ];
  for (const section of dependencySections) {
    const dependencies = value[section];
    if (!dependencies || typeof dependencies !== 'object') {
      continue;
    }
    for (const [packageName, rawSpec] of Object.entries(dependencies)) {
      const rules = exactRulesByName.get(packageName);
      if (!rules || typeof rawSpec !== 'string') {
        continue;
      }
      for (const rule of rules) {
        for (const version of rule.compromisedVersions) {
          if (!rawSpec.includes(version)) {
            continue;
          }
          addFinding(findings.exactHits, {
            type: 'exact-package-json-spec',
            campaignId: rule.campaignId,
            packageName,
            version,
            path: normalizeForDisplay(filePath),
            confidence: 'high',
            message: `${packageName} spec references compromised version ${version} in ${normalizeForDisplay(filePath)}`,
          });
        }
      }
    }
  }

  const scripts = value.scripts && typeof value.scripts === 'object' ? value.scripts : {};
  const scriptText = JSON.stringify(scripts);
  for (const rule of dataset.suspiciousPackageScriptRules) {
    if (!matchAllNeedles(scriptText, rule.match)) {
      continue;
    }
    addFinding(findings.heuristicHits, {
      type: 'heuristic-package-script',
      rule: rule.description,
      path: normalizeForDisplay(filePath),
      confidence: 'medium',
      message: `${rule.description} in ${normalizeForDisplay(filePath)}`,
    });
  }
}

function scanLockfile(filePath, findings) {
  let text = '';
  try {
    text = readFileTextSafe(filePath);
  } catch (error) {
    addFinding(findings.errors, {
      type: 'read-error',
      path: normalizeForDisplay(filePath),
      message: `Could not read ${normalizeForDisplay(filePath)}: ${error.message}`,
    });
    return;
  }

  findExactVersionHitsInText(text, filePath, findings.exactHits, 'exact-lockfile-hit');
  checkManifestNeedles(text, filePath, findings.heuristicHits);

  for (const marker of dataset.contentMarkers) {
    if (!text.includes(marker)) {
      continue;
    }
    addFinding(findings.heuristicHits, {
      type: 'heuristic-lockfile-marker',
      indicator: marker,
      path: normalizeForDisplay(filePath),
      confidence: 'medium',
      message: `Content marker "${marker}" found in ${normalizeForDisplay(filePath)}`,
    });
  }
}

function checkManifestNeedles(rawText, sourcePath, findings) {
  for (const rule of dataset.suspiciousPackageManifestNeedles) {
    if (!rawText.includes(rule.needle)) {
      continue;
    }
    addFinding(findings, {
      type: 'heuristic-manifest-needle',
      indicator: rule.needle,
      rule: rule.description,
      path: normalizeForDisplay(sourcePath),
      confidence: 'medium',
      message: `${rule.description} in ${normalizeForDisplay(sourcePath)}`,
    });
  }
}

function findExactVersionHitsInText(text, sourcePath, targetArray, category) {
  for (const rule of dataset.exactPackageVersionRules) {
    for (const version of rule.compromisedVersions) {
      if (!looksLikeMatchingLockEntry(text, rule.name, version)) {
        continue;
      }
      addFinding(targetArray, {
        type: category,
        campaignId: rule.campaignId,
        packageName: rule.name,
        version,
        path: normalizeForDisplay(sourcePath),
        confidence: 'high',
        message: `${rule.name}@${version} in ${normalizeForDisplay(sourcePath)}`,
      });
    }
  }
}

function looksLikeMatchingLockEntry(text, packageName, version) {
  const escapedName = escapeRegExp(packageName);
  const escapedVersion = escapeRegExp(version);
  const patterns = [
    new RegExp(`(?:^|[\\s"'` + '`' + `])${escapedName}@${escapedVersion}(?:$|[\\s:/"'` + '`' + `])`, 'm'),
    new RegExp(`node_modules\\/${escapedName.replaceAll('/', '\\/')}(?:["/\\\\][^\\n\\r]*)?[\\s\\S]{0,240}?"version"\\s*:\\s*"${escapedVersion}"`, 'm'),
    new RegExp(`"${escapedName}"[\\s\\S]{0,160}?"version"\\s*:\\s*"${escapedVersion}"`, 'm'),
    new RegExp(`${escapedName.replaceAll('/', '\\/')}[\\s\\S]{0,120}version:\\s*${escapedVersion}`, 'm'),
  ];
  return patterns.some((pattern) => pattern.test(text));
}

function inspectLoosePresenceByBasename(filePath, findings) {
  const baseName = path.basename(filePath);
  const reasons = suspiciousPresenceBasenameRules.get(baseName) ?? [];
  for (const reason of reasons) {
    addFinding(findings.artifactHits, {
      type: 'artifact-broad-presence-hit',
      rule: reason,
      path: normalizeForDisplay(filePath),
      confidence: 'medium',
      message: `${reason}: ${normalizeForDisplay(filePath)}`,
    });
  }
}

function applyProjectRipgrepResults(task, findings) {
  const includeGlobs = [
    ...[...SCAN_CANDIDATE_BASENAMES].map((basename) => `**/${basename}`),
    '**/.github/workflows/*.yml',
    '**/.github/workflows/*.yaml',
  ];
  const excludeGlobs = [
    '!**/node_modules/**',
    '!**/.git/**',
    '!**/.hg/**',
    '!**/.svn/**',
  ];
  if (task.mode !== SCAN_MODE_MACHINE) {
    for (const dirName of ['.next', '.nuxt', '.turbo', '.cache', '.parcel-cache', '.pnpm-store', 'coverage', 'dist', 'build', 'out', 'tmp', 'temp', 'vendor']) {
      excludeGlobs.push(`!**/${dirName}/**`);
    }
  }

  let matchesByFile;
  try {
    matchesByFile = runRipgrepLiteralScan({
      rootPath: task.rootPath,
      patterns: ripgrepLiteralPatterns,
      includeGlobs,
      excludeGlobs,
      maxDepth: task.shallow ? 1 : null,
      threads: 1,
    });
  } catch (error) {
    addFinding(findings.errors, {
      type: 'ripgrep-error',
      path: normalizeForDisplay(task.rootPath),
      message: `ripgrep failed for ${normalizeForDisplay(task.rootPath)}: ${error.message}`,
    });
    return {
      matchedFiles: 0,
    };
  }

  for (const [filePath, matchedNeedles] of matchesByFile.entries()) {
    applyBroadIndicatorHits(filePath, matchedNeedles, findings);
    applyProjectRuleHits(filePath, matchedNeedles, findings);
    applyWorkflowHeuristicHits(filePath, matchedNeedles, findings);
    applyLoosePayloadHits(filePath, matchedNeedles, findings, 'heuristic-loose-payload');
  }

  return {
    matchedFiles: matchesByFile.size,
  };
}

function applyBroadIndicatorHits(filePath, matchedNeedles, findings) {
  for (const indicator of matchedNeedles) {
    if (!broadIndicatorSet.has(indicator)) {
      continue;
    }
    addFinding(findings.heuristicHits, {
      type: 'broad-content-indicator',
      indicator,
      path: normalizeForDisplay(filePath),
      confidence: 'medium',
      message: `Indicator "${indicator}" in ${normalizeForDisplay(filePath)}`,
    });
  }
}

function applyProjectRuleHits(filePath, matchedNeedles, findings) {
  for (const rule of dataset.suspiciousProjectFileContentRules) {
    if (!isProjectRuleCandidate(filePath, rule)) {
      continue;
    }
    const allOk = !rule.matchAllNeedles || rule.matchAllNeedles.every((needle) => matchedNeedles.has(needle));
    const anyOk = !rule.matchAnyNeedles || rule.matchAnyNeedles.some((needle) => matchedNeedles.has(needle));
    if (!allOk || !anyOk) {
      continue;
    }
    addFinding(findings.artifactHits, {
      type: 'artifact-content-hit',
      rule: rule.reason,
      path: normalizeForDisplay(filePath),
      confidence: 'high',
      message: `${rule.reason} in ${normalizeForDisplay(filePath)}`,
    });
  }
}

function applyWorkflowHeuristicHits(filePath, matchedNeedles, findings) {
  if (!isWorkflowFile(filePath)) {
    return;
  }
  if (!matchedNeedles.has('toJSON(secrets)')) {
    return;
  }
  const hasKnownDestination = [...matchedNeedles].some((needle) =>
    workflowSupportIndicators.has(needle),
  );
  if (!hasKnownDestination) {
    return;
  }
  addFinding(findings.artifactHits, {
    type: 'workflow-exfiltration-heuristic',
    rule: 'Workflow exfiltration heuristic',
    path: normalizeForDisplay(filePath),
    confidence: 'high',
    message: `Suspicious secrets-exfiltration workflow at ${normalizeForDisplay(filePath)}`,
  });
}

function applyLoosePayloadHits(filePath, matchedNeedles, findings, type) {
  const baseName = path.basename(filePath);
  const matchingRules = suspiciousPackageFileRulesByBasename.get(baseName) ?? [];
  if (matchingRules.length === 0) {
    return;
  }

  const stats = statSafe(filePath);
  if (!stats?.isFile()) {
    return;
  }

  for (const rule of matchingRules) {
    if (rule.minSizeBytes && stats.size < rule.minSizeBytes) {
      continue;
    }
    if (rule.matchAnyNeedles && !rule.matchAnyNeedles.some((needle) => matchedNeedles.has(needle))) {
      continue;
    }
    addFinding(findings.heuristicHits, {
      type,
      rule: `${rule.family} payload signature`,
      path: normalizeForDisplay(filePath),
      confidence: 'high',
      message: `${rule.family} payload signature in ${normalizeForDisplay(filePath)}`,
    });
  }
}

function applyNodeModulesRipgrepResults(nodeModulesDir, packageDirToName, findings) {
  if (packageDirToName.size === 0) {
    return {
      matchedFiles: 0,
    };
  }

  const includeGlobs = [...suspiciousPackageFileRulesByBasename.keys()].map((basename) => `**/${basename}`);
  let matchesByFile;
  try {
    matchesByFile = runRipgrepLiteralScan({
      rootPath: nodeModulesDir,
      patterns: ripgrepLiteralPatterns,
      includeGlobs,
      excludeGlobs: ['!**/.bin/**'],
      threads: 1,
    });
  } catch (error) {
    addFinding(findings.errors, {
      type: 'ripgrep-error',
      path: normalizeForDisplay(nodeModulesDir),
      message: `ripgrep failed for ${normalizeForDisplay(nodeModulesDir)}: ${error.message}`,
    });
    return {
      matchedFiles: 0,
    };
  }

  for (const [filePath, matchedNeedles] of matchesByFile.entries()) {
    const packageName = resolveOwningPackageName(filePath, packageDirToName);
    if (!packageName) {
      continue;
    }
    const baseName = path.basename(filePath);
    const rules = suspiciousPackageFileRulesByBasename.get(baseName) ?? [];
    const stats = statSafe(filePath);
    if (!stats?.isFile()) {
      continue;
    }

    for (const rule of rules) {
      if (rule.relativePath === 'index.js' && !packageName.startsWith('@antv/')) {
        continue;
      }
      if (rule.minSizeBytes && stats.size < rule.minSizeBytes) {
        continue;
      }
      if (rule.matchAnyNeedles && !rule.matchAnyNeedles.some((needle) => matchedNeedles.has(needle))) {
        continue;
      }
      addFinding(findings.heuristicHits, {
        type: 'heuristic-package-file',
        packageName,
        path: normalizeForDisplay(filePath),
        rule: `${rule.family} payload signature`,
        confidence: 'high',
        message: `${rule.family} payload signature in ${normalizeForDisplay(filePath)}`,
      });
    }
  }

  return {
    matchedFiles: matchesByFile.size,
  };
}

function scanInstalledPackagesSemantic(nodeModulesDir, findings, stats) {
  const packageDirToName = new Map();
  if (!fileExists(nodeModulesDir)) {
    return packageDirToName;
  }

  const visited = new Set();
  const stack = [nodeModulesDir];

  while (stack.length > 0) {
    const current = stack.pop();
    let realCurrent = current;
    try {
      realCurrent = fs.realpathSync.native(current);
    } catch {
      realCurrent = path.resolve(current);
    }

    if (visited.has(realCurrent)) {
      continue;
    }
    visited.add(realCurrent);
    stats.nodeModulesDirsVisited += 1;

    let entries = [];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch (error) {
      recordTraversalError(stats, error);
      continue;
    }

    for (const entry of entries) {
      if (entry.name === '.bin') {
        continue;
      }

      const fullPath = path.join(current, entry.name);
      if (!direntIsDirectory(entry, fullPath)) {
        continue;
      }

      if (entry.name === 'node_modules') {
        stack.push(fullPath);
        continue;
      }

      const packageJsonPath = path.join(fullPath, PACKAGE_JSON_NAME);
      if (fileExists(packageJsonPath)) {
        const packageName = scanInstalledPackageDirSemantic(fullPath, findings);
        if (packageName) {
          packageDirToName.set(path.resolve(fullPath), packageName);
        }

        const nestedNodeModules = path.join(fullPath, 'node_modules');
        if (fileExists(nestedNodeModules)) {
          stack.push(nestedNodeModules);
        }
        continue;
      }

      stack.push(fullPath);
    }
  }

  return packageDirToName;
}

function scanInstalledPackageDirSemantic(packageDir, findings) {
  const packageJsonPath = path.join(packageDir, PACKAGE_JSON_NAME);
  if (!fileExists(packageJsonPath)) {
    return null;
  }

  const { rawText, value } = readJsonSafe(packageJsonPath);
  if (!rawText || !value || typeof value.name !== 'string') {
    return null;
  }

  const packageName = value.name;
  const packageVersion = typeof value.version === 'string' ? value.version : null;

  const exactRules = exactRulesByName.get(packageName) ?? [];
  for (const rule of exactRules) {
    for (const compromisedVersion of rule.compromisedVersions) {
      if (packageVersion !== compromisedVersion) {
        continue;
      }
      addFinding(findings.exactHits, {
        type: 'exact-installed-package',
        campaignId: rule.campaignId,
        packageName,
        version: compromisedVersion,
        path: normalizeForDisplay(packageDir),
        confidence: 'high',
        message: `${packageName}@${compromisedVersion} installed at ${normalizeForDisplay(packageDir)}`,
      });
    }
  }

  checkManifestNeedles(rawText, packageJsonPath, findings.heuristicHits);
  for (const rule of dataset.suspiciousPackageScriptRules) {
    if (!matchAllNeedles(rawText, rule.match)) {
      continue;
    }
    addFinding(findings.heuristicHits, {
      type: 'heuristic-installed-package-script',
      packageName,
      path: normalizeForDisplay(packageJsonPath),
      rule: rule.description,
      confidence: 'medium',
      message: `${rule.description} in installed ${packageName}`,
    });
  }

  return packageName;
}

function resolveOwningPackageName(filePath, packageDirToName) {
  let current = path.resolve(path.dirname(filePath));
  while (true) {
    const packageName = packageDirToName.get(current);
    if (packageName) {
      return packageName;
    }
    const parent = path.dirname(current);
    if (parent === current) {
      return null;
    }
    current = parent;
  }
}

function inspectFileRuleAtPath(absolutePath, rule, findings) {
  if (!fileExists(absolutePath)) {
    return;
  }

  if (rule.contentInspectionOnly) {
    addFinding(findings.artifactHits, {
      type: 'artifact-presence-hit',
      rule: rule.reason,
      path: normalizeForDisplay(absolutePath),
      confidence: 'low',
      message: `${rule.reason}: ${normalizeForDisplay(absolutePath)} exists and should be reviewed`,
    });
    return;
  }

  addFinding(findings.artifactHits, {
    type: 'artifact-presence-hit',
    rule: rule.reason,
    path: normalizeForDisplay(absolutePath),
    confidence: 'high',
    message: `${rule.reason}: ${normalizeForDisplay(absolutePath)}`,
  });
}

function inspectContentRule(filePath, rule, findings) {
  let text = '';
  try {
    text = readFileTextSafe(filePath);
  } catch (error) {
    addFinding(findings.errors, {
      type: 'read-error',
      path: normalizeForDisplay(filePath),
      message: `Could not read ${normalizeForDisplay(filePath)}: ${error.message}`,
    });
    return;
  }

  const allOk = !rule.matchAllNeedles || matchAllNeedles(text, rule.matchAllNeedles);
  const anyOk = !rule.matchAnyNeedles || matchNeedles(text, rule.matchAnyNeedles);
  if (!allOk || !anyOk) {
    return;
  }

  addFinding(findings.artifactHits, {
    type: 'artifact-content-hit',
    rule: rule.reason,
    path: normalizeForDisplay(filePath),
    confidence: 'high',
    message: `${rule.reason} in ${normalizeForDisplay(filePath)}`,
  });
}

function isProjectRuleCandidate(filePath, rule) {
  const normalized = normalizeSlashes(path.relative(process.cwd(), filePath));
  const endsWith = normalizeSlashes(rule.relativePath);
  return normalized.endsWith(endsWith) || normalizeSlashes(filePath).endsWith(endsWith);
}

function matchNeedles(haystack, needles) {
  return needles.some((needle) => haystack.includes(needle));
}

function matchAllNeedles(haystack, needles) {
  return needles.every((needle) => haystack.includes(needle));
}

function createWorker(task, onProgress) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const worker = new Worker(new URL('./scan-worker.mjs', import.meta.url), {
      workerData: {
        task,
      },
    });

    worker.on('message', (message) => {
      if (message?.type === 'progress') {
        onProgress?.(message.event);
        return;
      }
      if (message?.type === 'result') {
        if (!settled) {
          settled = true;
          resolve(message.result);
        }
        return;
      }
      if (!settled) {
        settled = true;
        resolve(message);
      }
    });
    worker.once('error', reject);
    worker.once('exit', (code) => {
      if (!settled && code !== 0) {
        reject(new Error(`Worker exited with code ${code}`));
      }
    });
  });
}

function reportTaskProgress(reportProgress, task, phase, details = {}) {
  reportProgress({
    phase,
    taskId: task.id,
    rootPath: task.rootPath,
    timestamp: Date.now(),
    ...details,
  });
}

function createProgressState(tasks, workerCount, preflightPlan) {
  const taskPlanById = new Map(((preflightPlan?.executionTaskPlans ?? preflightPlan?.taskPlans) ?? []).map((taskPlan) => [taskPlan.taskId, taskPlan]));
  return {
    totalTasks: tasks.length,
    workerCount,
    startedTasks: 0,
    completedTasks: 0,
    completedWorkUnits: 0,
    activeTasks: new Map(),
    startedAt: Date.now(),
    totalWorkUnits: preflightPlan?.totals?.workUnits ?? tasks.length,
    progressModel: preflightPlan?.progressModel ?? 'tasks',
    taskPlanById,
  };
}

function logTaskProgress(state, task, event) {
  const rootLabel = normalizeForDisplay(task.rootPath);
  const taskPlan = state.taskPlanById.get(task.id);

  if (event.phase === 'task-started') {
    state.startedTasks += 1;
    state.activeTasks.set(task.id, {
      rootPath: task.rootPath,
      startedAt: event.startedAt ?? event.timestamp ?? Date.now(),
      phase: event.phase,
      progressFraction: phaseToProgressFraction(event.phase),
      workUnits: taskPlan?.workUnits ?? 1,
    });
    const estimateSuffix = taskPlan?.inventory
      ? ` est_dirs=${taskPlan.inventory.directoriesVisited} est_files=${taskPlan.inventory.filesVisited} est_candidate_files=${taskPlan.inventory.candidateFilesDiscovered} est_node_modules_roots=${taskPlan.inventory.nodeModulesRootsDiscovered}`
      : '';
    console.log(`${formatOverallPrefix(state)} task ${task.id} started ${rootLabel}${estimateSuffix}`);
    return;
  }

  const activeTask = state.activeTasks.get(task.id);
  if (activeTask) {
    activeTask.phase = event.phase;
    activeTask.progressFraction = phaseToProgressFraction(event.phase);
  }

  if (event.phase === 'discovery-complete') {
    console.log(
      `${formatOverallPrefix(state)} task ${task.id} discovery ${rootLabel} dirs=${event.directoriesVisited} candidate_files=${event.candidateFilesDiscovered} node_modules_roots=${event.nodeModulesRootsDiscovered} in ${formatDuration(event.elapsedMs)}`,
    );
    return;
  }

  if (event.phase === 'project-semantic-complete') {
    console.log(
      `${formatOverallPrefix(state)} task ${task.id} project-semantic ${rootLabel} files=${event.candidateFilesProcessed} in ${formatDuration(event.elapsedMs)}`,
    );
    return;
  }

  if (event.phase === 'project-rg-started') {
    console.log(
      `${formatOverallPrefix(state)} task ${task.id} project-rg started ${rootLabel} candidate_files=${event.candidateFilesConsidered}`,
    );
    return;
  }

  if (event.phase === 'project-rg-complete') {
    console.log(
      `${formatOverallPrefix(state)} task ${task.id} project-rg ${rootLabel} matched_files=${event.matchedFiles} in ${formatDuration(event.elapsedMs)}`,
    );
    return;
  }

  if (event.phase === 'node-modules-semantic-started') {
    console.log(
      `${formatOverallPrefix(state)} task ${task.id} node-modules started ${rootLabel} node_modules_roots=${event.nodeModulesRootsDiscovered}`,
    );
    return;
  }

  if (event.phase === 'node-modules-complete') {
    console.log(
      `${formatOverallPrefix(state)} task ${task.id} node-modules ${rootLabel} installed_packages=${event.installedPackagesScanned} node_modules_dirs=${event.nodeModulesDirectoriesVisited} matched_files=${event.matchedFiles} in ${formatDuration(event.elapsedMs)}`,
    );
    return;
  }

  if (event.phase === 'task-complete') {
    state.activeTasks.delete(task.id);
    state.completedTasks += 1;
    state.completedWorkUnits += taskPlan?.workUnits ?? 1;
    console.log(
      `${formatOverallPrefix(state)} task ${task.id} done ${rootLabel} total=${formatDuration(event.elapsedMs)} dirs=${event.directoriesVisited} candidate_files=${event.candidateFilesVisited} node_modules_dirs=${event.nodeModulesDirsVisited}`,
    );
  }
}

function logOverallProgress(state, phase, details = {}) {
  if (phase === 'planned') {
    console.log(
      `${formatOverallPrefix(state)} planned mode=${details.mode} tasks=${details.totalTasks} workers=${state.workerCount} progress_model=${details.progressModel}`,
    );
    return;
  }
  if (phase === 'heartbeat') {
    console.log(
      `${formatOverallPrefix(state)} heartbeat ${details.summary}`,
    );
  }
}

function formatOverallPrefix(state) {
  const completedUnits = state.completedWorkUnits + getActiveWorkUnits(state);
  const percent = state.totalWorkUnits === 0
    ? 100
    : Math.min(100, Math.floor((completedUnits / state.totalWorkUnits) * 100));
  return `[scan][${state.completedTasks}/${state.totalTasks} tasks][${String(percent).padStart(3, ' ')}% overall][active ${state.activeTasks.size}/${state.workerCount}][+${formatDuration(Date.now() - state.startedAt)}]`;
}

function formatDuration(durationMs) {
  const safeDurationMs = Math.max(0, durationMs);
  const totalSeconds = Math.floor(safeDurationMs / 1000);
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  const milliseconds = safeDurationMs % 1000;
  return `${[hours, minutes, seconds].map((value) => String(value).padStart(2, '0')).join(':')}.${String(milliseconds).padStart(3, '0')}`;
}

function getActiveWorkUnits(state) {
  let activeUnits = 0;
  for (const activeTask of state.activeTasks.values()) {
    activeUnits += (activeTask.workUnits ?? 1) * (activeTask.progressFraction ?? 0);
  }
  return activeUnits;
}

function phaseToProgressFraction(phase) {
  switch (phase) {
    case 'task-started':
      return 0.01;
    case 'discovery-complete':
      return 0.35;
    case 'project-semantic-complete':
      return 0.45;
    case 'project-rg-started':
      return 0.50;
    case 'project-rg-complete':
      return 0.72;
    case 'node-modules-semantic-started':
      return 0.78;
    case 'node-modules-complete':
    case 'task-complete':
      return 1;
    default:
      return 0;
  }
}

function startScanHeartbeat(state, options) {
  if (!options.verbose || !options.heartbeatMs || options.heartbeatMs < 1) {
    return null;
  }
  const heartbeatMs = Math.max(1_000, options.heartbeatMs ?? 10_000);
  return setInterval(() => {
    if (state.activeTasks.size === 0) {
      return;
    }
    const activeSummaries = [...state.activeTasks.entries()]
      .map(([taskId, taskState]) => ({
        taskId,
        elapsedMs: Date.now() - taskState.startedAt,
        phase: taskState.phase,
        rootPath: normalizeForDisplay(taskState.rootPath),
      }))
      .sort((left, right) => right.elapsedMs - left.elapsedMs)
      .slice(0, 3)
      .map((entry) =>
        `task=${entry.taskId} phase=${entry.phase} path=${entry.rootPath} running=${formatDuration(entry.elapsedMs)}`,
      )
      .join(' | ');

    logOverallProgress(state, 'heartbeat', {
      summary: activeSummaries || 'scan is still running',
    });
  }, heartbeatMs);
}

function stopScanHeartbeat(timer) {
  if (timer) {
    clearInterval(timer);
  }
}
