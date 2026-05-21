import process from 'node:process';
import { parentPort, workerData } from 'node:worker_threads';

import { runScanTask } from './scanner.mjs';

if (!parentPort || !workerData?.task) {
  process.exit(2);
}

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
