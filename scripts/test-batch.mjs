import fs from 'node:fs/promises';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { VERSION } from '../src/shared/protocol.mjs';

const group = Number(process.argv[2]), groups = 3;
if (!Number.isInteger(group) || group < 1 || group > groups) throw Error('Usage: test-batch.mjs 1|2|3');
const all = (await fs.readdir('tests')).filter(name => name.endsWith('.test.mjs')).sort();
const files = all.filter((_name, i) => i % groups === group - 1).map(name => 'tests/' + name);
console.log(`Test batch ${group}/${groups}: ${files.length} files.`);
const child = spawn(process.execPath, ['--test', '--test-concurrency=1', '--test-reporter=spec', ...files], { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
let output = '';
const collect = bytes => { output += bytes; if (output.length > 4 * 1024 * 1024) child.kill(); };
child.stdout.on('data', collect); child.stderr.on('data', collect);
// This cap covers an entire batch of browser/HTTP fixtures, not one test.
// Keep individual test assertions/timeouts unchanged; a busy Windows desktop
// must not truncate an otherwise progressing batch at the old tool-call limit.
let timedOut = false;
const timer = setTimeout(() => { timedOut = true; child.kill(); }, 600000);
const result = await new Promise((resolve, reject) => { child.once('error', reject); child.once('close', (code, signal) => resolve({ code, signal })); });
clearTimeout(timer);
const directory = path.join('.artifacts', 'verification-' + VERSION); await fs.mkdir(directory, { recursive: true });
await fs.writeFile(path.join(directory, `batch-${group}.log`), output);
await fs.writeFile(path.join(directory, `batch-${group}.json`), JSON.stringify({ group, groups, files, ...result, timedOut, checkedAt: new Date().toISOString() }, null, 2));
console.log(output.slice(result.code === 0 ? -2400 : -7000));
if (timedOut) console.error('Test batch timed out before completion; no successful verification is recorded.');
if (result.code !== 0 || timedOut) process.exitCode = 1;
