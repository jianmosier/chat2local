import { execFileSync } from 'node:child_process';
import fs from 'node:fs/promises';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const directory = path.dirname(fileURLToPath(import.meta.url));
const executable = process.env.WORKER_BUILD_BIN || 'worker-build';
const version = execFileSync(executable, ['--version'], { cwd: directory, encoding: 'utf8', windowsHide: true }).trim();
if (version !== '0.8.7') throw new Error('This probe requires worker-build 0.8.7.');
const inputs = ['Cargo.toml', 'Cargo.lock', 'src/lib.rs'];
async function hashes(files) {
  return Object.fromEntries(await Promise.all(files.map(async file => [file,
    createHash('sha256').update(await fs.readFile(path.join(directory, file))).digest('hex')])));
}
const before = await hashes(inputs);
await fs.rm(path.join(directory, 'build/probe-manifest.json'), { force: true });
execFileSync(executable, ['--release', '--locked'], { cwd: directory, stdio: 'inherit', windowsHide: true, timeout: 600000 });
const after = await hashes(inputs);
if (JSON.stringify(before) !== JSON.stringify(after)) throw new Error('Probe sources changed during build.');
const artifacts = await hashes(['build/index.js', 'build/index_bg.wasm', 'build/worker/shim.mjs']);
await fs.writeFile(path.join(directory, 'build/probe-manifest.json'), JSON.stringify({ version, inputs: after, artifacts }, null, 2) + '\n');
console.log('Rust worker probe build and source hashes recorded.');
