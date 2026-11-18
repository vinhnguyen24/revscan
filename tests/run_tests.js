'use strict';

const { spawnSync } = require('node:child_process');
const path = require('node:path');

const py = process.env.PYTHON || (process.platform === 'win32' ? 'python' : 'python3');
const node = process.execPath;
const ROOT = path.resolve(__dirname, '..');

const suites = [
  [py, [path.join(ROOT, 'tests', 'test_scan.py')]],
  [py, [path.join(ROOT, 'tests', 'test_crack_sim.py')]],
  [py, [path.join(ROOT, 'tests', 'test_decoy_kit.py')]],
  [py, [path.join(ROOT, 'tests', 'test_calibrate.py')]],
  [py, [path.join(ROOT, 'tests', 'test_protect.py')]],
  [py, [path.join(ROOT, 'tests', 'test_compare.py')]],
  [py, [path.join(ROOT, 'tests', 'test_disasm.py')]],
  [py, [path.join(ROOT, 'tests', 'test_benchmark.py')]],
  [node, [path.join(ROOT, 'tests', 'test_web_views.js')]],
  [node, [path.join(ROOT, 'tests', 'test_web.js')]],
  [node, [path.join(ROOT, 'server', 'test', 'flow.test.js')]],
];

for (const [cmd, args] of suites) {
  const res = spawnSync(cmd, args, { stdio: 'inherit', cwd: ROOT });
  if (res.status !== 0) {
    process.exit(res.status || 1);
  }
}
