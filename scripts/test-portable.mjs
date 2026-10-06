import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';
import { Store, powershell } from '../src/agent/store.mjs';
import { DEFAULT_PORT } from '../src/agent/main.mjs';

const repo = fileURLToPath(new URL('..', import.meta.url));
const base = await fs.mkdtemp(path.join(os.tmpdir(), 'chat2local-portable-'));
let session; let browser; let passed = 0;
const check = (value, label) => { assert.ok(value, label); passed++; console.log(`PASS: ${label}`); };
async function vacant(port) {
  const probe = net.createServer();
  await new Promise((resolve, reject) => { probe.once('error', reject); probe.listen(port, '127.0.0.1', resolve); });
  await new Promise(resolve => probe.close(resolve));
}
function runLauncher(cwd, stateDir) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.env.ComSpec || 'C:\\Windows\\System32\\cmd.exe', ['/d', '/c', 'start-chat2local.cmd'], {
      cwd, windowsHide: true,
      env: { ...process.env, PATH: `${process.env.SystemRoot}\\System32;${process.env.SystemRoot}\\System32\\WindowsPowerShell\\v1.0`, CHAT2LOCAL_STATE_DIR: stateDir, CHAT2LOCAL_NO_BROWSER: '1' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let output = ''; const timer = setTimeout(() => { child.kill(); reject(new Error('Test-owned launcher timed out.')); }, 30000);
    child.stdout.on('data', data => { output += data; }); child.stderr.on('data', data => { output += data; });
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('exit', code => { clearTimeout(timer); code === 0 ? resolve(output) : reject(new Error(`Launcher failed (${code}): ${output}`)); });
  });
}
async function api(route, body) {
  return fetch(`${session.origin}/api/${route}`, { method: body === undefined ? 'GET' : 'POST', headers: { Origin: session.origin, 'X-Chat2Local-Token': session.token, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }), signal: AbortSignal.timeout(3000) });
}
try {
  await vacant(DEFAULT_PORT); check(true, 'test port is free; no existing process is stopped');
  const zip = path.join(repo, 'dist', 'Chat2Local-Windows-x64.zip');
  const extracted = path.join(base, '中文 空格 & 路径');
  await powershell("$ErrorActionPreference='Stop'; $c=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Console]::In.ReadToEnd()))|ConvertFrom-Json; Expand-Archive -LiteralPath $c.zip -DestinationPath $c.target", Buffer.from(JSON.stringify({ zip, target: extracted })).toString('base64'), 120000);
  const cwd = path.join(extracted, 'Chat2Local-Windows-x64');
  const manifest = JSON.parse(await fs.readFile(path.join(cwd, 'BUILD-MANIFEST.json'), 'utf8'));
  for (const [relative, expected] of Object.entries(manifest.files)) {
    assert.equal(createHash('sha256').update(await fs.readFile(path.join(cwd, relative))).digest('hex'), expected, relative);
    assert.ok(!/(?:node_modules|vault\.json|session\.json|settings\.json|\.dev\.vars|\.git\/)/.test(relative));
  }
  check(true, 'all packaged file hashes match and no private-state/dependency files are included');
  const stateDir = path.join(base, 'private');
  const first = await runLauncher(cwd, stateDir);
  session = await new Store(stateDir).readSession();
  check(session.origin === `http://127.0.0.1:${DEFAULT_PORT}` && /started/.test(first), 'actual CMD starts bundled runtime with no Node or npm in PATH');
  let response = await api('status'); assert.equal(response.status, 200); let state = await response.json();
  check(state.instanceId === session.instanceId && state.roots.length === 0, 'fresh install starts without any authorized folders');
  check(state.startup === false && state.bridge === 'not-configured', 'no startup registration or public enrollment happens automatically');
  const second = await runLauncher(cwd, stateDir); response = await api('status');
  check((await response.json()).instanceId === state.instanceId && /existing verified/.test(second), 'double-clicking twice reuses exactly the verified instance');
  browser = await chromium.launch({ channel: 'msedge', headless: true });
  const page = await browser.newPage(); await page.goto(`${session.origin}/#${session.token}`);
  await page.waitForFunction(() => document.querySelector('#status').textContent.includes('本地已就绪'));
  check(new URL(page.url()).hash === '', 'packaged browser panel boots and removes the bootstrap secret');
  await page.locator('#demo').click(); await page.getByRole('button', { name: '确认写入', exact: true }).waitFor();
  const proposal = await page.getByLabel('建议写入的完整内容').inputValue();
  const demo = path.join(base, 'Chat2LocalDemo', 'hello-chat2local.txt');
  check((await fs.readFile(demo, 'utf8')) !== proposal, 'packaged demo never writes a proposed change before approval');
  await page.getByRole('button', { name: '确认写入', exact: true }).click();
  await page.waitForFunction(() => document.querySelector('#notice').textContent.includes('已写入'));
  check((await fs.readFile(demo, 'utf8')) === proposal, 'packaged UI approval changes only its isolated sample file');
  check((await page.locator('#clientBadge').textContent()) === '尚未验证', 'local sample does not claim real web-AI connectivity');
  response = await api('shutdown', {}); assert.equal(response.status, 200);
  await new Promise(resolve => setTimeout(resolve, 1200));
  await assert.rejects(() => api('status')); check(true, 'authenticated exit stops the actual packaged process listener');
  // Relaunch exercises retained config and real process restoration, not a computer reboot.
  await runLauncher(cwd, stateDir); const oldInstance = session.instanceId; session = await new Store(stateDir).readSession();
  state = await (await api('status')).json();
  check(session.instanceId !== oldInstance && state.roots.length === 1 && state.pending.length === 0, 'fresh process restores saved permissions without replaying pending operations');
  for (const [relative, expected] of Object.entries(manifest.files)) assert.equal(createHash('sha256').update(await fs.readFile(path.join(cwd, relative))).digest('hex'), expected);
  check(true, 'runtime state never modifies program package files');
  console.log(`ALL ${passed} PORTABLE ASSERTIONS PASSED. No real project, cloud service, or OS startup was changed.`);
} finally {
  await browser?.close();
  if (session) await api('shutdown', {}).catch(() => {});
  await new Promise(resolve => setTimeout(resolve, 1500));
  await fs.rm(base, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
}
