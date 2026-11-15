'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');

const config = require('./config');

/**
 * Runs the Python engine as a subprocess.
 *
 * Isolation is deliberate: a malformed PE must not take the web process down,
 * and the timeout must be enforceable (SIGKILL).
 */
let activeEngines = 0;

function runEngine(filePath, { mode = 'static', timeoutMs = config.scanTimeoutMs } = {}) {
  // A queue would just move the pile-up into memory. Refuse with a retryable
  // error so the client backs off; the credit/quota refunds run in the route.
  if (activeEngines >= config.maxConcurrentScans) {
    return Promise.reject(Object.assign(new Error('server busy'), { code: 'BUSY' }));
  }
  activeEngines += 1;
  return new Promise((resolve, reject) => {
    const args = [config.engine, filePath, '--json'];
    if (mode === 'ai') args.push('--ai');

    const child = spawn(config.python, args, {
      cwd: config.root,
      timeout: timeoutMs,
      killSignal: 'SIGKILL',
      env: { ...process.env, PYTHONUNBUFFERED: '1' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let out = '';
    let err = '';
    child.stdout.on('data', (chunk) => {
      out += chunk;
      if (out.length > 8 * 1024 * 1024) child.kill('SIGKILL');
    });
    child.stderr.on('data', (chunk) => {
      err += chunk;
      if (err.length > 64 * 1024) err = err.slice(-64 * 1024);
    });

    child.on('error', (e) => reject(Object.assign(new Error(`engine failed: ${e.message}`), { code: 'ENGINE' })));
    child.on('close', (code, signal) => {
      if (signal === 'SIGKILL') {
        return reject(Object.assign(new Error('scan timed out'), { code: 'TIMEOUT' }));
      }

      // `scan.py --json` writes a structured error envelope to stdout when the
      // AI provider refuses a request. Parse it before the exit code so an
      // exhausted quota is not reported as a broken upload.
      let parsed = null;
      try {
        parsed = JSON.parse(out);
      } catch {
        /* not JSON: fall through to the exit-code/stderr path */
      }
      if (parsed && parsed.ok === false && parsed.error) {
        return reject(
          Object.assign(new Error(parsed.error.message || 'AI provider error'), {
            code: parsed.error.code || 'AI_ERROR',
            retryAfter: parsed.error.retry_after ?? null,
            exitCode: code,
          })
        );
      }
      if (code !== 0) {
        return reject(Object.assign(new Error(err.trim() || `engine exit ${code}`), { code: 'ENGINE' }));
      }
      if (!parsed) {
        return reject(Object.assign(new Error('engine returned invalid JSON'), { code: 'ENGINE' }));
      }
      resolve(parsed);
    });
  }).finally(() => {
    activeEngines -= 1;
  });
}

/**
 * Diffs two `scan.py --json` reports. The web never runs protect itself: the
 * customer protects locally and uploads only the JSON reports, so no binary
 * leaves their machine for this feature.
 */
function runCompareReports(beforePath, afterPath, timeoutMs = config.compareTimeoutMs) {
  if (activeEngines >= config.maxConcurrentScans) {
    return Promise.reject(Object.assign(new Error('server busy'), { code: 'BUSY' }));
  }
  activeEngines += 1;

  const cli = path.join(config.root, 'cli', 'trapkey.py');
  return new Promise((resolve, reject) => {
    const child = spawn(config.python, [cli, 'compare-reports', beforePath, afterPath, '--json'], {
      cwd: config.root,
      timeout: timeoutMs,
      killSignal: 'SIGKILL',
      env: { ...process.env, PYTHONUNBUFFERED: '1' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let out = '';
    let err = '';
    let outputTooLarge = false;
    child.stdout.on('data', (chunk) => {
      out += chunk;
      if (out.length > 2 * 1024 * 1024) {
        outputTooLarge = true;
        child.kill('SIGKILL');
      }
    });
    child.stderr.on('data', (chunk) => {
      err += chunk;
      if (err.length > 64 * 1024) err = err.slice(-64 * 1024);
    });

    child.on('error', (e) =>
      reject(Object.assign(new Error(`compare failed: ${e.message}`), { code: 'COMPARE' }))
    );
    child.on('close', (code, signal) => {
      if (signal === 'SIGKILL' && outputTooLarge) {
        return reject(
          Object.assign(new Error('compare output exceeded the size limit'), { code: 'OUTPUT' })
        );
      }
      if (signal === 'SIGKILL') {
        return reject(Object.assign(new Error('compare timed out'), { code: 'TIMEOUT' }));
      }
      if (code !== 0) {
        return reject(
          Object.assign(new Error(err.trim() || `compare exit ${code}`), { code: 'COMPARE' })
        );
      }
      try {
        resolve(JSON.parse(out));
      } catch {
        reject(Object.assign(new Error('compare returned invalid JSON'), { code: 'COMPARE' }));
      }
    });
  }).finally(() => {
    activeEngines -= 1;
  });
}

/** Streams a request body to disk, enforcing the size cap before anything is parsed. */
function receiveUpload(req, destDir = config.uploadsDir) {
  fs.mkdirSync(destDir, { recursive: true });
  const dest = path.join(destDir, `upload_${crypto.randomBytes(8).toString('hex')}.bin`);

  return new Promise((resolve, reject) => {
    const stream = fs.createWriteStream(dest, { mode: 0o600 });
    let size = 0;
    let aborted = false;

    const cleanup = () => {
      fs.rm(dest, { force: true }, () => {});
    };

    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > config.maxUpload && !aborted) {
        aborted = true;
        stream.destroy();
        cleanup();
        req.destroy();
        reject(Object.assign(new Error('file too large'), { code: 'TOO_LARGE' }));
      }
    });

    req.on('error', (err) => {
      cleanup();
      reject(Object.assign(err, { code: 'UPLOAD' }));
    });

    stream.on('error', (err) => {
      cleanup();
      reject(Object.assign(err, { code: 'UPLOAD' }));
    });

    stream.on('finish', () => {
      if (aborted) return;
      if (size === 0) {
        cleanup();
        return reject(Object.assign(new Error('empty upload'), { code: 'EMPTY' }));
      }
      resolve({ path: dest, size, sha256: null, cleanup });
    });

    req.pipe(stream);
  });
}

function sha256File(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('error', reject);
    stream.on('end', () => resolve(hash.digest('hex')));
  });
}

module.exports = { runEngine, runCompareReports, receiveUpload, sha256File };
