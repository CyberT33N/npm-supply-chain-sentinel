import {
  spawnSync,
  type SpawnSyncOptions,
  type SpawnSyncReturns,
} from 'node:child_process';

export type CommandResult = SpawnSyncReturns<string>;

export function runCommand(
  command: string,
  args: readonly string[],
  options: SpawnSyncOptions = {},
): CommandResult {
  return spawnSync(command, args, {
    ...options,
    encoding: 'utf8',
    windowsHide: true,
  });
}

export function commandExists(command: string, args: readonly string[] = ['--version']): boolean {
  const result = runCommand(command, args);
  return !(
    result.error
    && typeof result.error === 'object'
    && result.error !== null
    && 'code' in result.error
    && result.error['code'] === 'ENOENT'
  );
}
