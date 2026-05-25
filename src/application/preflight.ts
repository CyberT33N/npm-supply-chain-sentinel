import fs from 'node:fs';
import path from 'node:path';

import {
  SCAN_CANDIDATE_BASENAMES,
  shouldSkipDirectory,
} from '../domain/policy';
import {
  direntIsDirectory,
  direntIsFile,
  normalizeForDisplay,
} from '../infrastructure/fs-utils';

export const PREFLIGHT_MODE_FAST = 'fast';
export const PREFLIGHT_MODE_DEEP = 'deep';
const SPLIT_DIRECTORIES_THRESHOLD = 10_000;
const SPLIT_FILES_THRESHOLD = 50_000;
const SPLIT_CANDIDATE_FILES_THRESHOLD = 500;
const SPLIT_NODE_MODULES_THRESHOLD = 250;
const SPLIT_WORK_UNITS_THRESHOLD = 15_000;

export async function buildPreflightPlan(tasks, options = {}, reportProgress = () => {}) {
  const mode = options.mode === PREFLIGHT_MODE_DEEP ? PREFLIGHT_MODE_DEEP : PREFLIGHT_MODE_FAST;
  const heartbeatMs = options.heartbeatMs && options.heartbeatMs > 0
    ? Math.max(1_000, options.heartbeatMs)
    : 0;
  const preflightStartedAt = Date.now();

  if (mode === PREFLIGHT_MODE_FAST) {
    return buildFastPreflightPlan(tasks);
  }

  reportProgress({
    phase: 'deep-preflight-started',
    totalTasks: tasks.length,
  });

  const taskPlans = [];
  const totals = {
    directoriesVisited: 0,
    filesVisited: 0,
    candidateFilesDiscovered: 0,
    nodeModulesRootsDiscovered: 0,
    workUnits: 0,
  };

  for (let index = 0; index < tasks.length; index += 1) {
    const task = tasks[index];
    const inventory = inventoryTask(task, {
      heartbeatMs,
      reportProgress,
      taskIndex: index,
      totalTasks: tasks.length,
      preflightStartedAt,
    });
    const workUnits = computeWorkUnits(inventory);
    const taskPlan = {
      taskId: task.id,
      rootPath: task.rootPath,
      mode: task.mode,
      shallow: task.shallow,
      includeTrash: task.includeTrash,
      workUnits,
      inventory,
    };
    taskPlans.push(taskPlan);

    totals.directoriesVisited += inventory.directoriesVisited;
    totals.filesVisited += inventory.filesVisited;
    totals.candidateFilesDiscovered += inventory.candidateFilesDiscovered;
    totals.nodeModulesRootsDiscovered += inventory.nodeModulesRootsDiscovered;
    totals.workUnits += workUnits;

    reportProgress({
      phase: 'deep-preflight-task-complete',
      completedTasks: index + 1,
      totalTasks: tasks.length,
      taskPlan,
    });
  }

  return withExecutionPlan({
    mode,
    totalTasks: tasks.length,
    totals,
    taskPlans,
    progressModel: 'weighted',
    heaviestTasks: [...taskPlans]
      .sort((left, right) => right.workUnits - left.workUnits)
      .slice(0, 5)
      .map((taskPlan) => ({
        taskId: taskPlan.taskId,
        rootPath: taskPlan.rootPath,
        workUnits: taskPlan.workUnits,
        inventory: taskPlan.inventory,
      })),
  });
}

function buildFastPreflightPlan(tasks) {
  return withExecutionPlan({
    mode: PREFLIGHT_MODE_FAST,
    totalTasks: tasks.length,
    totals: {
      directoriesVisited: null,
      filesVisited: null,
      candidateFilesDiscovered: null,
      nodeModulesRootsDiscovered: null,
      workUnits: tasks.length,
    },
    taskPlans: tasks.map((task) => ({
      taskId: task.id,
      rootPath: task.rootPath,
      mode: task.mode,
      shallow: task.shallow,
      includeTrash: task.includeTrash,
      workUnits: 1,
      inventory: null,
    })),
    progressModel: 'tasks',
    heaviestTasks: [],
  });
}

function inventoryTask(task, options) {
  const counts = {
    directoriesVisited: 0,
    filesVisited: 0,
    candidateFilesDiscovered: 0,
    nodeModulesRootsDiscovered: 0,
    traversalErrors: {
      EACCES: 0,
      EPERM: 0,
      ENOENT: 0,
      OTHER: 0,
    },
    immediateChildren: [],
    rootFilesVisited: 0,
    rootCandidateFilesDiscovered: 0,
    rootNodeModulesRootsDiscovered: 0,
  };

  const stack = [task.rootPath];
  const shallowRoot = Boolean(task.shallow);
  const taskStartedAt = Date.now();
  let lastHeartbeatAt = taskStartedAt;
  const immediateChildStats = new Map();

  while (stack.length > 0) {
    const currentEntry = stack.pop();
    const current = typeof currentEntry === 'string' ? currentEntry : currentEntry.path;
    const branchRoot = typeof currentEntry === 'string' ? null : currentEntry.branchRoot;
    counts.directoriesVisited += 1;

    if (branchRoot) {
      const branchStats = getImmediateChildStats(immediateChildStats, branchRoot);
      branchStats.directoriesVisited += 1;
    }

    let entries = [];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch (error) {
      recordTraversalError(counts, error);
      continue;
    }

    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);

      if (direntIsDirectory(entry, fullPath)) {
        if (entry.name === 'node_modules') {
          counts.nodeModulesRootsDiscovered += 1;
          if (current === task.rootPath) {
            counts.rootNodeModulesRootsDiscovered += 1;
          }
          if (branchRoot) {
            const branchStats = getImmediateChildStats(immediateChildStats, branchRoot);
            branchStats.nodeModulesRootsDiscovered += 1;
          }
          continue;
        }

        if (shouldSkipDirectory(entry.name, task.mode, { includeTrash: task.includeTrash })) {
          continue;
        }

        if (shallowRoot && current === task.rootPath) {
          continue;
        }

        const nextBranchRoot = current === task.rootPath ? fullPath : branchRoot;
        if (current === task.rootPath) {
          getImmediateChildStats(immediateChildStats, nextBranchRoot);
        }
        stack.push({
          path: fullPath,
          branchRoot: nextBranchRoot,
        });
        continue;
      }

      if (!direntIsFile(entry, fullPath)) {
        continue;
      }

      counts.filesVisited += 1;
      if (current === task.rootPath) {
        counts.rootFilesVisited += 1;
      }
      if (branchRoot) {
        const branchStats = getImmediateChildStats(immediateChildStats, branchRoot);
        branchStats.filesVisited += 1;
      }
      if (SCAN_CANDIDATE_BASENAMES.has(entry.name) || isWorkflowFile(fullPath, entry.name)) {
        counts.candidateFilesDiscovered += 1;
        if (current === task.rootPath) {
          counts.rootCandidateFilesDiscovered += 1;
        }
        if (branchRoot) {
          const branchStats = getImmediateChildStats(immediateChildStats, branchRoot);
          branchStats.candidateFilesDiscovered += 1;
        }
      }
    }

    const now = Date.now();
    if (options.heartbeatMs > 0 && now - lastHeartbeatAt >= options.heartbeatMs) {
      options.reportProgress({
        phase: 'deep-preflight-heartbeat',
        completedTasks: options.taskIndex,
        totalTasks: options.totalTasks,
        currentTask: {
          taskId: task.id,
          rootPath: task.rootPath,
          elapsedMs: now - taskStartedAt,
          directoriesVisited: counts.directoriesVisited,
          filesVisited: counts.filesVisited,
          candidateFilesDiscovered: counts.candidateFilesDiscovered,
          nodeModulesRootsDiscovered: counts.nodeModulesRootsDiscovered,
        },
        elapsedMs: now - options.preflightStartedAt,
      });
      lastHeartbeatAt = now;
    }
  }

  counts.immediateChildren = [...immediateChildStats.entries()]
    .map(([childPath, childStats]) => ({
      rootPath: childPath,
      workUnits: computeWorkUnits(childStats),
      inventory: childStats,
    }))
    .sort((left, right) => right.workUnits - left.workUnits);

  return counts;
}

function computeWorkUnits(inventory) {
  return Math.max(
    1,
    inventory.directoriesVisited +
      inventory.filesVisited +
      (inventory.candidateFilesDiscovered * 25) +
      (inventory.nodeModulesRootsDiscovered * 250),
  );
}

function recordTraversalError(target, error) {
  const code = typeof error?.code === 'string' ? error.code : 'OTHER';
  if (code in target.traversalErrors) {
    target.traversalErrors[code] += 1;
    return;
  }
  target.traversalErrors.OTHER += 1;
}

function isWorkflowFile(filePath, baseName = path.basename(filePath)) {
  return filePath.split(path.sep).join('/').includes('/.github/workflows/') && /\.(yml|yaml)$/i.test(baseName);
}

export function formatTaskPlanSummary(taskPlan) {
  if (!taskPlan?.inventory) {
    return normalizeForDisplay(taskPlan?.rootPath ?? '');
  }
  return `${normalizeForDisplay(taskPlan.rootPath)} work=${taskPlan.workUnits} dirs=${taskPlan.inventory.directoriesVisited} files=${taskPlan.inventory.filesVisited} candidate_files=${taskPlan.inventory.candidateFilesDiscovered} node_modules_roots=${taskPlan.inventory.nodeModulesRootsDiscovered}`;
}

function getImmediateChildStats(map, childPath) {
  const existing = map.get(childPath);
  if (existing) {
    return existing;
  }
  const next = {
    directoriesVisited: 0,
    filesVisited: 0,
    candidateFilesDiscovered: 0,
    nodeModulesRootsDiscovered: 0,
    traversalErrors: {
      EACCES: 0,
      EPERM: 0,
      ENOENT: 0,
      OTHER: 0,
    },
  };
  map.set(childPath, next);
  return next;
}

function withExecutionPlan(basePlan) {
  const executionPlan = buildExecutionPlan(basePlan);
  return {
    ...basePlan,
    executionTasks: executionPlan.executionTasks,
    executionTaskPlans: executionPlan.executionTaskPlans,
    splitSummary: executionPlan.splitSummary,
  };
}

function buildExecutionPlan(preflightPlan) {
  const executionTasks = [];
  const executionTaskPlans = [];
  let nextSyntheticId = 1;
  let splitTaskCount = 0;

  for (const taskPlan of preflightPlan.taskPlans) {
    if (!shouldSplitTaskPlan(taskPlan, preflightPlan)) {
      executionTasks.push({
        id: String(taskPlan.taskId),
        rootPath: taskPlan.rootPath,
        mode: taskPlan.mode,
        shallow: taskPlan.shallow,
        includeTrash: taskPlan.includeTrash,
      });
      executionTaskPlans.push({
        taskId: String(taskPlan.taskId),
        rootPath: taskPlan.rootPath,
        workUnits: taskPlan.workUnits,
        inventory: taskPlan.inventory,
      });
      continue;
    }

    splitTaskCount += 1;
    const rootTaskId = `${taskPlan.taskId}:root`;
    const rootInventory = {
      directoriesVisited: 1,
      filesVisited: taskPlan.inventory.rootFilesVisited,
      candidateFilesDiscovered: taskPlan.inventory.rootCandidateFilesDiscovered,
      nodeModulesRootsDiscovered: taskPlan.inventory.rootNodeModulesRootsDiscovered,
    };
    const rootWorkUnits = computeWorkUnits(rootInventory);
    executionTasks.push({
      id: rootTaskId,
      rootPath: taskPlan.rootPath,
      mode: taskPlan.mode,
      shallow: true,
      includeTrash: taskPlan.includeTrash,
    });
    executionTaskPlans.push({
      taskId: rootTaskId,
      rootPath: taskPlan.rootPath,
      workUnits: rootWorkUnits,
      inventory: rootInventory,
    });

    for (const childPlan of taskPlan.inventory.immediateChildren) {
      const childTaskId = `${taskPlan.taskId}:split:${nextSyntheticId}`;
      nextSyntheticId += 1;
      executionTasks.push({
        id: childTaskId,
        rootPath: childPlan.rootPath,
        mode: taskPlan.mode,
        shallow: false,
        includeTrash: taskPlan.includeTrash,
      });
      executionTaskPlans.push({
        taskId: childTaskId,
        rootPath: childPlan.rootPath,
        workUnits: childPlan.workUnits,
        inventory: childPlan.inventory,
      });
    }
  }

  return {
    executionTasks,
    executionTaskPlans,
    splitSummary: {
      sourceTasks: preflightPlan.taskPlans.length,
      executionTasks: executionTasks.length,
      splitTaskCount,
    },
  };
}

function shouldSplitTaskPlan(taskPlan, preflightPlan) {
  if (preflightPlan.mode !== PREFLIGHT_MODE_DEEP) {
    return false;
  }
  if (taskPlan.shallow) {
    return false;
  }
  if (!taskPlan.inventory || taskPlan.inventory.immediateChildren.length < 2) {
    return false;
  }

  const inventory = taskPlan.inventory;
  return (
    inventory.directoriesVisited >= SPLIT_DIRECTORIES_THRESHOLD ||
    inventory.filesVisited >= SPLIT_FILES_THRESHOLD ||
    inventory.candidateFilesDiscovered >= SPLIT_CANDIDATE_FILES_THRESHOLD ||
    inventory.nodeModulesRootsDiscovered >= SPLIT_NODE_MODULES_THRESHOLD ||
    taskPlan.workUnits >= SPLIT_WORK_UNITS_THRESHOLD
  );
}
