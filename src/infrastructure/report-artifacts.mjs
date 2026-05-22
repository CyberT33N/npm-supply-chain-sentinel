import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';

export const GENERATED_REPORTS_DIRNAME = 'generated';
export const LATEST_FULL_SCAN_REPORT_BASENAME = 'latest-scan.json';
export const LATEST_PNPM_GOVERNANCE_REPORT_BASENAME = 'latest-pnpm-governance-scan.json';

export function resolveGeneratedReportPath(reportBasename, cwd = process.cwd()) {
  return path.resolve(cwd, GENERATED_REPORTS_DIRNAME, reportBasename);
}

export function writeJsonArtifacts(options) {
  const latestPath = options.latestPath;
  const exportPath = options.exportPath ?? null;
  const payload = options.payload;
  const writtenPaths = [];

  writeJsonArtifact(latestPath, payload);
  writtenPaths.push(latestPath);

  if (!exportPath) {
    return writtenPaths;
  }

  if (exportPath === '-') {
    writeJsonArtifact(exportPath, payload);
    writtenPaths.push(exportPath);
    return writtenPaths;
  }

  if (path.resolve(exportPath) === path.resolve(latestPath)) {
    return writtenPaths;
  }

  writeJsonArtifact(exportPath, payload);
  writtenPaths.push(exportPath);
  return writtenPaths;
}

function writeJsonArtifact(targetPath, payload) {
  const text = `${JSON.stringify(payload, null, 2)}${os.EOL}`;
  if (targetPath === '-') {
    process.stdout.write(text);
    return;
  }

  fs.mkdirSync(path.dirname(targetPath), { recursive: true });
  fs.writeFileSync(targetPath, text, 'utf8');
}
