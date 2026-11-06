import { spawnSync } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const root = fileURLToPath(new URL('..', import.meta.url)), args = process.argv.slice(2);
if (args.length && (args.length !== 2 || args[0] !== '--target-dir')) throw Error('Usage: build-rust-lifecycle.mjs [--target-dir DIRECTORY]');
const target = args.length ? path.resolve(args[1]) : path.join(root, 'target');
const result = spawnSync('cargo', ['rustc', '--locked', '--release', '--target', 'wasm32-unknown-unknown', '--target-dir', target,
  '-p', 'chat2local-agent-lifecycle-wasm', '--', '-C', 'link-arg=--max-memory=16777216'], { cwd: root, stdio: 'inherit', shell: false, windowsHide: true });
if (result.error || result.status !== 0) throw Error('Required Rust lifecycle WASM build failed.');
const modulePath = path.join(target, 'wasm32-unknown-unknown/release/chat2local_agent_lifecycle_wasm.wasm');
// A caller selecting a fresh target directory receives an isolated artifact only.
if (!args.length) {
  await fs.mkdir(path.join(root, 'runtime'), { recursive: true });
  await fs.copyFile(modulePath, path.join(root, 'runtime/chat2local-agent-lifecycle.wasm'));
}
console.log(`Development lifecycle WASM built: ${modulePath}`);
