import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

import { LOCKFILE_NAMES, PACKAGE_JSON_NAME, TEXT_ENCODINGS } from '../domain/policy.mjs';

export function readFileTextSafe(filePath) {
  for (const encoding of TEXT_ENCODINGS) {
    try {
      return fs.readFileSync(filePath, encoding);
    } catch (error) {
      if (encoding === TEXT_ENCODINGS[TEXT_ENCODINGS.length - 1]) {
        throw error;
      }
    }
  }
  return '';
}

export function fileExists(filePath) {
  try {
    fs.accessSync(filePath, fs.constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

export function statSafe(filePath) {
  try {
    return fs.statSync(filePath);
  } catch {
    return null;
  }
}

export function readJsonSafe(filePath) {
  try {
    const text = readFileTextSafe(filePath);
    return {
      rawText: text,
      value: JSON.parse(text),
    };
  } catch {
    return {
      rawText: null,
      value: null,
    };
  }
}

export function normalizeForDisplay(filePath) {
  const resolved = path.resolve(filePath);
  const cwd = path.resolve(process.cwd());
  if (resolved.startsWith(cwd + path.sep)) {
    return path.relative(cwd, resolved);
  }
  return resolved;
}

export function normalizeSlashes(input) {
  return input.split(path.sep).join('/');
}

export function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function direntIsDirectory(entry, fullPath) {
  if (entry.isDirectory()) {
    return true;
  }
  if (!entry.isSymbolicLink()) {
    return false;
  }
  return Boolean(statSafe(fullPath)?.isDirectory());
}

export function direntIsFile(entry, fullPath) {
  if (entry.isFile()) {
    return true;
  }
  if (!entry.isSymbolicLink()) {
    return false;
  }
  return Boolean(statSafe(fullPath)?.isFile());
}

export function detectProjectRoot(startDir) {
  let current = path.resolve(startDir);

  while (true) {
    const hasGit = fileExists(path.join(current, '.git'));
    const hasPackageJson = fileExists(path.join(current, PACKAGE_JSON_NAME));
    const hasLockfile = [...LOCKFILE_NAMES].some((fileName) =>
      fileExists(path.join(current, fileName)),
    );

    if (hasGit || hasPackageJson || hasLockfile) {
      return current;
    }

    const parent = path.dirname(current);
    if (parent === current) {
      return path.resolve(process.cwd());
    }
    current = parent;
  }
}

export function detectLineEnding(text) {
  return text.includes('\r\n') ? '\r\n' : '\n';
}

export function platformMatches(platforms) {
  return !platforms || platforms.includes(process.platform);
}

export function toAbsolutePath(inputPath) {
  return path.resolve(process.cwd(), inputPath);
}
