import { spawnSync } from 'node:child_process';

export function runCommand(command, args, options = {}) {
  return spawnSync(command, args, {
    encoding: 'utf8',
    windowsHide: true,
    ...options,
  });
}

export function commandExists(command, args = ['--version']) {
  const result = runCommand(command, args);
  return !(result.error && result.error.code === 'ENOENT');
}
