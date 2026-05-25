import {
  spawnSync,
  type SpawnSyncOptionsWithStringEncoding,
  type SpawnSyncReturns,
} from 'node:child_process';

export type CommandResult = SpawnSyncReturns<string>;

export function runCommand(
  command: string,
  args: readonly string[],
  options: SpawnSyncOptionsWithStringEncoding = {},
): CommandResult {
  return spawnSync(command, args, {
    encoding: 'utf8',
    windowsHide: true,
    ...options,
  });
}

export function commandExists(command: string, args: readonly string[] = ['--version']): boolean {
  const result = runCommand(command, args);
  return !(result.error && result.error.code === 'ENOENT');
}
