import process from 'node:process';
import { parentPort, workerData } from 'node:worker_threads';
import { register, tsImport } from 'tsx/esm/api';

if (!parentPort || !workerData?.task) {
  process.exit(2);
}

const unregister = register();

const { runScanTask } = await tsImport('./scanner.ts', import.meta.url);

const result = runScanTask(workerData.task, (event) => {
  parentPort.postMessage({
    type: 'progress',
    event,
  });
});

parentPort.postMessage({
  type: 'result',
  result,
});

await unregister();
