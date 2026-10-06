import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { Store, openBrowser } from '../src/agent/store.mjs';
import { DEFAULT_PORT } from '../src/agent/main.mjs';
import { VERSION } from '../src/shared/protocol.mjs';
import { childNetworkEnvironment, localNetworkOnly } from '../src/agent/network.mjs';

const entry = fileURLToPath(new URL('../src/agent/main.mjs', import.meta.url));
const store = new Store();
async function verifiedSession() {
  try {
    const session = await store.readSession();
    if (session.origin !== `http://127.0.0.1:${DEFAULT_PORT}` || !/^[a-f0-9]{64}$/.test(session.token)) return null;
    const response = await fetch(`${session.origin}/api/status`, { headers: { 'X-Chat2Local-Token': session.token }, signal: AbortSignal.timeout(800), redirect: 'error' });
    const state = response.ok ? await response.json() : null;
    return state?.name === 'chat2local' && state.instanceId === session.instanceId ? { ...session, appVersion: state.version, hasShares: Boolean(state.roots?.length || state.accountRoots?.length) } : null;
  } catch { return null; }
}
async function launch() {
  if (process.argv.slice(2).some(arg => !['--no-browser','--manage'].includes(arg))) throw new Error('Unknown launcher argument.');
  const showBrowser = !process.argv.includes('--no-browser') && process.env.CHAT2LOCAL_NO_BROWSER !== '1';
  const major = Number(process.versions.node.split('.')[0]);
  if (major < 24 || major >= 27) throw new Error('This development preview requires Node.js 24–26.');
  localNetworkOnly();
  const existing = await verifiedSession();
  if (existing && existing.appVersion !== VERSION) throw new Error('旧版 Chat2Local 仍在运行。请在旧面板点击“完全退出”，再双击新版；不会强行停止旧进程。');
  if (existing) { if (showBrowser) await openBrowser(`${existing.origin}${process.argv.includes('--manage') || existing.hasShares ? '/folders' : '/'}#${existing.token}`); console.log('Opened the existing verified Chat2Local panel.'); return; }
  await fs.mkdir(store.directory, { recursive: true, mode: 0o700 });
  const logPath = path.join(store.directory, 'launcher.log');
  try { if ((await fs.stat(logPath)).size > 1024 * 1024) await fs.rename(logPath, `${logPath}.previous`); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  const log = await fs.open(logPath, 'a', 0o600);
  let child;
  try { child = spawn(process.execPath, [entry, '--background'], { detached: true, windowsHide: true, stdio: ['ignore', log.fd, log.fd], cwd: path.dirname(entry), env: childNetworkEnvironment() }); }
  finally { await log.close(); }
  let exited = false; let spawnError;
  child.once('error', error => { spawnError = error; });
  child.once('exit', () => { exited = true; }); child.unref();
  const deadline = Date.now() + 12_000;
  while (Date.now() < deadline) {
    if (spawnError) throw spawnError;
    const ready = await verifiedSession();
    if (ready) { if (showBrowser) await openBrowser(`${ready.origin}${process.argv.includes('--manage') || ready.hasShares ? '/folders' : '/'}#${ready.token}`); console.log('Chat2Local started. Closing the browser does not pause AI access; use Pause or Exit in the panel.'); return; }
    if (exited) break;
    await new Promise(resolve => setTimeout(resolve, 150));
  }
  throw new Error(`Startup was not confirmed. No existing process was stopped. See ${logPath}`);
}
launch().catch(error => { console.error(`Chat2Local: ${error.message}`); process.exitCode = 1; });
