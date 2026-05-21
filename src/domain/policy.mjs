import os from 'node:os';

import { dataset } from '../data/supply-chain-campaigns-2026.mjs';

export { dataset };

export const TEXT_ENCODINGS = ['utf8', 'latin1'];
export const PACKAGE_JSON_NAME = 'package.json';
export const LOCKFILE_NAMES = new Set([
  'package-lock.json',
  'pnpm-lock.yaml',
  'yarn.lock',
  'bun.lock',
  'bun.lockb',
]);
export const IGNORED_DIR_NAMES = new Set([
  '.git',
  '.hg',
  '.svn',
  '.next',
  '.nuxt',
  '.turbo',
  '.cache',
  '.parcel-cache',
  '.pnpm-store',
  'coverage',
  'dist',
  'build',
  'out',
  'tmp',
  'temp',
  'vendor',
]);
export const ALWAYS_SKIPPED_DIR_NAMES = new Set(['.git', '.hg', '.svn']);
export const MACHINE_MODE_SKIPPED_DIR_NAMES = new Set(['$Recycle.Bin']);
export const PROJECT_MODE_SKIPPED_DIR_NAMES = new Set([
  '.next',
  '.nuxt',
  '.turbo',
  '.cache',
  '.parcel-cache',
  '.pnpm-store',
  'coverage',
  'dist',
  'build',
  'out',
  'tmp',
  'temp',
  'vendor',
]);
export const PROJECT_FILE_BASENAMES = new Set([
  'settings.json',
  'tasks.json',
  '.bashrc',
  '.zshrc',
  'codeql_analysis.yml',
  'codeql_analysis.yaml',
  'format-check.yml',
  'format-check.yaml',
  PACKAGE_JSON_NAME,
  ...LOCKFILE_NAMES,
]);
export const EXTRA_SCAN_FILE_BASENAMES = new Set([
  'setup.mjs',
  'setup.js',
  'execution.js',
  'router_runtime.js',
  'router_init.js',
  'bw_setup.js',
  'bw1.js',
  '6202033.vbs',
  '6202033.ps1',
  'ld.py',
  'transformers.pyz',
  'pglog',
  'gh-token-monitor.sh',
  'gh-token-monitor.service',
  'com.user.gh-token-monitor.plist',
  'com.apple.act.mond',
]);
export const SCAN_CANDIDATE_BASENAMES = new Set([
  ...PROJECT_FILE_BASENAMES,
  ...EXTRA_SCAN_FILE_BASENAMES,
]);
export const HOSTS_BEGIN_MARKER = '# >>> CyberT33N supply-chain 2026 blocklist >>>';
export const HOSTS_END_MARKER = '# <<< CyberT33N supply-chain 2026 blocklist <<<';
export const MACOS_PF_ANCHOR_NAME = 'cybert33n_supply_chain_2026';
export const MACOS_PF_ANCHOR_PATH = `/etc/pf.anchors/${MACOS_PF_ANCHOR_NAME}`;
export const RIPGREP_BINARY = 'rg';
export const SCAN_MODE_PROJECT = 'project';
export const SCAN_MODE_MACHINE = 'machine-wide';
export const WORKER_TASK_TYPE = 'scan-subtree';
export const DEFAULT_WORKER_COUNT = Math.max(
  1,
  Math.min(32, Math.max(1, (typeof os.availableParallelism === 'function'
    ? os.availableParallelism()
    : os.cpus().length) - 1)),
);

export const STATUS_OK_SYMBOL = '✓';
export const STATUS_WARN_SYMBOL = '⚠';
export const STATUS_ERROR_SYMBOL = '✗';
export const ANSI_COLORS = {
  green: '\u001b[32m',
  yellow: '\u001b[33m',
  red: '\u001b[31m',
  reset: '\u001b[0m',
};

export const exactRulesByName = buildExactRuleCandidatesByName();
export const suspiciousPresenceBasenameRules = buildSuspiciousPresenceBasenameRules();
export const suspiciousPackageFileRulesByBasename = buildSuspiciousPackageFileRulesByBasename();
export const broadContentIndicators = [
  ...dataset.contentMarkers,
  ...dataset.networkIndicators.hostsBlocklistDomains,
  ...dataset.networkIndicators.firewallIpBlocklist,
  ...dataset.networkIndicators.urls,
  ...dataset.suspiciousPackageManifestNeedles.map((rule) => rule.needle),
];
export const workflowSupportIndicators = new Set([
  ...dataset.networkIndicators.hostsBlocklistDomains,
  'createCommitOnBranch',
  'claude@users.noreply.github.com',
]);
export const ripgrepLiteralPatterns = buildRipgrepLiteralPatterns();

function buildExactRuleCandidatesByName() {
  const map = new Map();
  for (const rule of dataset.exactPackageVersionRules) {
    const list = map.get(rule.name) ?? [];
    list.push(rule);
    map.set(rule.name, list);
  }
  return map;
}

function buildSuspiciousPresenceBasenameRules() {
  const map = new Map();
  const register = (basename, reason) => {
    if (!basename) {
      return;
    }
    const list = map.get(basename) ?? [];
    list.push(reason);
    map.set(basename, list);
  };

  for (const rule of dataset.suspiciousAbsolutePathRules) {
    const parts = rule.path.split('/');
    register(parts[parts.length - 1], rule.reason);
  }
  for (const rule of dataset.suspiciousHomePathPresenceRules) {
    const parts = rule.path.split('/');
    register(parts[parts.length - 1], rule.reason);
  }
  for (const rule of dataset.suspiciousWindowsPathRules) {
    const parts = rule.suffix.split(/[\\/]/u);
    register(parts[parts.length - 1], rule.reason);
  }

  return map;
}

function buildSuspiciousPackageFileRulesByBasename() {
  const map = new Map();
  for (const rule of dataset.suspiciousPackageFileRules) {
    const parts = rule.relativePath.split('/');
    const basename = parts[parts.length - 1];
    const list = map.get(basename) ?? [];
    list.push(rule);
    map.set(basename, list);
  }
  return map;
}

function buildRipgrepLiteralPatterns() {
  const patterns = new Set();

  for (const indicator of broadContentIndicators) {
    patterns.add(indicator);
  }
  patterns.add('toJSON(secrets)');
  patterns.add('createCommitOnBranch');

  for (const rule of dataset.suspiciousProjectFileContentRules) {
    for (const needle of rule.matchAllNeedles ?? []) {
      patterns.add(needle);
    }
    for (const needle of rule.matchAnyNeedles ?? []) {
      patterns.add(needle);
    }
  }

  for (const rule of dataset.suspiciousPackageFileRules) {
    for (const needle of rule.matchAnyNeedles ?? []) {
      patterns.add(needle);
    }
  }

  return [...patterns];
}

export function shouldSkipDirectory(dirName, mode, options = {}) {
  if (ALWAYS_SKIPPED_DIR_NAMES.has(dirName)) {
    return true;
  }
  if (mode === SCAN_MODE_MACHINE && !options.includeTrash && MACHINE_MODE_SKIPPED_DIR_NAMES.has(dirName)) {
    return true;
  }
  if (mode === SCAN_MODE_PROJECT && PROJECT_MODE_SKIPPED_DIR_NAMES.has(dirName)) {
    return true;
  }
  return false;
}

export function buildManagedHostsEntries() {
  const entries = [];
  for (const domain of dataset.networkIndicators.hostsBlocklistDomains) {
    entries.push({
      address: '0.0.0.0',
      domain,
      line: `0.0.0.0 ${domain}`,
    });
    entries.push({
      address: '::1',
      domain,
      line: `::1 ${domain}`,
    });
  }
  return entries;
}
