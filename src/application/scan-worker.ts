import process from 'node:process';
import { parentPort, workerData } from 'node:worker_threads';
import { register, tsImport } from 'tsx/esm/api';
import type { TaskProgressEvent } from './scanner';

if (!parentPort || !workerData?.task) {
  process.exit(2);
}

const port = parentPort;
if (!port) {
  throw new Error('Worker messaging port is unavailable.');
}
const unregister = register();

const { runScanTask } = await tsImport('./scanner.ts', import.meta.url);

const result = runScanTask(workerData.task, (event: TaskProgressEvent) => {
  port.postMessage({
    type: 'progress',
    event,
  });
});

port.postMessage({
  type: 'result',
  result,
});

await unregister();
