import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { Store } from '../src/agent/store.mjs';
export async function freePort() { const s = net.createServer(); s.listen(0, '127.0.0.1'); await once(s, 'listening'); const port = s.address().port; await new Promise(resolve => s.close(resolve)); return port; }
export async function nativeFixture(t, executable, { before, directory, port, publicationDelay = 0, whileStarting } = {}) {
  const own = !directory; directory ||= await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-native-controller-')); port ||= await freePort();
  await fs.writeFile(path.join(directory, '.chat2local-synthetic-fixture'), 'synthetic-only\n');
  const store = new Store(directory); if (before) await before(store);
  const child = spawn(executable, ['--synthetic-state', directory, '--port', String(port), '--fixture-only'], { env: { SystemRoot: process.env.SystemRoot, CHAT2LOCAL_CONTROLLER_FIXTURE_PUBLICATION_DELAY_MS: String(publicationDelay), PATH: path.join(process.env.SystemRoot, 'System32') }, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  let stderr = ''; child.stderr.on('data', data => stderr += data);
  const exited = once(child, 'exit');
  const readyPromise = new Promise((resolve, reject) => { let text = ''; const timer = setTimeout(() => reject(Error('Native startup timed out: ' + stderr)), 10000); child.stdout.on('data', data => { text += data; if (text.includes('\n')) { clearTimeout(timer); try { resolve(JSON.parse(text.slice(0, text.indexOf('\n')))); } catch (e) { reject(e); } } }); child.once('exit', code => { clearTimeout(timer); reject(Error(`Native startup failed ${code}: ${stderr}`)); }); child.once('error', reject); });
  let ready;
  try { await whileStarting?.({ port, directory, store }); ready = await readyPromise; }
  catch (error) { readyPromise.catch(() => {}); if(child.exitCode === null) child.kill(); await exited; if(own) await fs.rm(directory,{recursive:true,force:true}); throw error; }
  const session = await store.readSession();
  const api = (route, body, headers = {}) => fetch(`${ready.origin}${route}`, { method: body === undefined ? 'GET' : 'POST', headers: { 'X-Chat2Local-Token': session.token, Origin: ready.origin, 'Content-Type': 'application/json', ...headers }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  let stopped = false;
  const close = async () => { if (stopped) return; stopped = true; if (child.exitCode === null) { await api('/api/shutdown', {}).catch(() => {}); try { await Promise.race([exited, new Promise((_, reject) => { const timer = setTimeout(() => reject(Error('Native close timed out: ' + stderr)), 18000); timer.unref(); })]); } catch (error) { child.kill(); await exited; throw error; } } };
  t.after(async () => { await close(); if (own) await fs.rm(directory, { recursive: true, force: true }); });
  return { child, exited, ready, session, store, directory, port, api, close };
}
export async function raw(port, bytes, { fragments = false, timeout = 20000 } = {}) {
  return new Promise((resolve, reject) => { const socket = net.connect(port, '127.0.0.1'); const chunks = []; socket.setTimeout(timeout, () => { socket.destroy(); reject(Error('Raw HTTP timeout')); }); socket.on('error', reject); socket.on('data', data => chunks.push(data)); socket.on('end', () => resolve(Buffer.concat(chunks).toString())); socket.on('connect', async () => { if (fragments) { for (let i = 0; i < bytes.length; i += 7) { socket.write(bytes.slice(i, i + 7)); await new Promise(resolve => setImmediate(resolve)); } } else socket.write(bytes); }); });
}
export function request(f, target = '/api/status', { method = 'GET', headers = '', body = '', close = true } = {}) { return `${method} ${target} HTTP/1.1\r\nHost: 127.0.0.1:${f.port}\r\nOrigin: ${f.ready.origin}\r\nX-Chat2Local-Token: ${f.session.token}\r\n${close ? 'Connection: close\r\n' : ''}${headers}\r\n${body}`; }
