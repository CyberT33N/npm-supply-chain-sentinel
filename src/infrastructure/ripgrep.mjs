import path from 'node:path';

import { RIPGREP_BINARY } from '../domain/policy.mjs';
import { runCommand } from './process-utils.mjs';

export function ensureRipgrepInstalled() {
  const result = runCommand(RIPGREP_BINARY, ['--version']);
  if (result.error || result.status !== 0) {
    const detail =
      result.error?.message ||
      result.stderr?.trim() ||
      'rg could not be executed';
    throw new Error(
      `ripgrep (rg) is required as a runtime dependency. Install it first and make sure "rg" is available on PATH. ${detail}`,
    );
  }
  return (result.stdout ?? '').split(/\r?\n/u)[0]?.trim() ?? 'rg';
}

export function runRipgrepLiteralScan(options) {
  const args = [
    '--json',
    '--fixed-strings',
    '--hidden',
    '--no-ignore',
    '--no-messages',
    '--color',
    'never',
    '--threads',
    String(options.threads ?? 1),
  ];

  if (options.maxDepth != null) {
    args.push('--max-depth', String(options.maxDepth));
  }

  for (const glob of options.includeGlobs ?? []) {
    args.push('--glob', glob);
  }
  for (const glob of options.excludeGlobs ?? []) {
    args.push('--glob', glob);
  }
  for (const pattern of options.patterns) {
    args.push('-e', pattern);
  }

  args.push(options.rootPath);
  const result = runCommand(RIPGREP_BINARY, args);

  if (result.error) {
    throw result.error;
  }
  if (![0, 1].includes(result.status ?? 0)) {
    throw new Error(result.stderr?.trim() || `rg exited with code ${result.status}`);
  }

  const matchesByFile = new Map();
  const lines = (result.stdout ?? '').split(/\r?\n/u).filter(Boolean);
  for (const line of lines) {
    let record;
    try {
      record = JSON.parse(line);
    } catch {
      continue;
    }
    if (record.type !== 'match') {
      continue;
    }

    const fileText = record.data?.path?.text;
    if (typeof fileText !== 'string') {
      continue;
    }

    const resolvedPath = path.isAbsolute(fileText)
      ? path.resolve(fileText)
      : path.resolve(options.rootPath, fileText);
    const current = matchesByFile.get(resolvedPath) ?? new Set();
    for (const submatch of record.data?.submatches ?? []) {
      const matchText = submatch?.match?.text;
      if (typeof matchText === 'string') {
        current.add(matchText);
      }
    }
    matchesByFile.set(resolvedPath, current);
  }

  return matchesByFile;
}
