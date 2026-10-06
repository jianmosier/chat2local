import fs from 'node:fs/promises';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

async function collect(directory) {
  const result = [];
  for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
    const name = path.join(directory, entry.name);
    if (entry.isDirectory()) result.push(...await collect(name));
    else if (/\.(mjs|js)$/.test(name)) result.push(name);
  }
  return result;
}
const files = [...await collect('src'), ...await collect('tests'), ...await collect('scripts')];
for (const file of files) {
  const result = spawnSync(process.execPath, ['--check', file], { stdio: 'inherit', windowsHide: true });
  if (result.status !== 0) process.exit(result.status || 1);
}
console.log(`Syntax checks passed for ${files.length} JavaScript modules. This is not a runtime or browser compatibility test.`);
