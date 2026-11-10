import { spawnSync } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
if (process.platform !== 'win32') throw new Error('This readonly runtime currently supports Windows only.');
if (process.argv.length !== 2) throw new Error('Usage: node scripts/build-rust-readonly.mjs');
const result = spawnSync('cargo', ['build', '--locked', '--release', '-p', 'chat2local-readonly'], {
  cwd: root, stdio: 'inherit', windowsHide: true, shell: false,
});
if (result.error || result.status !== 0) throw new Error('Rust readonly build failed.');
await fs.mkdir(path.join(root, 'runtime'), { recursive: true });
await fs.copyFile(path.join(root, 'target', 'release', 'chat2local-readonly.exe'), path.join(root, 'runtime', 'chat2local-readonly.exe'));
console.log('Built runtime/chat2local-readonly.exe. Enable explicitly with CHAT2LOCAL_READ_BACKEND=rust.');
