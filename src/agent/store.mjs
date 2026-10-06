import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existingStateDirectory } from './platform.mjs';
import { setPosixStartup } from './startup.mjs';

export const defaultStateDir = () => existingStateDirectory();
export const startupAvailable = stateDir => ['win32', 'darwin', 'linux'].includes(process.platform) && !process.env.CHAT2LOCAL_STATE_DIR && path.resolve(stateDir) === path.resolve(defaultStateDir());

export function powershell(script, input = '', timeout = 30_000, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn('powershell.exe', ['-NoLogo', '-NoProfile', ...(options.sta ? ['-STA'] : []), ...(options.interactive ? [] : ['-NonInteractive']), '-Command', script], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'], ...(options.signal ? { signal: options.signal } : {}) });
    options.onSpawn?.(child); // Optional test observer; never exposed through control APIs.
    let output = ''; let errors = '';
    const timer = setTimeout(() => { child.kill(); reject(new Error('Windows operation timed out.')); }, timeout);
    child.stdout.on('data', data => { output += data; });
    child.stderr.on('data', data => { errors += data; });
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('close', code => { clearTimeout(timer); code === 0 ? resolve(output.trim()) : reject(new Error(`Windows operation failed (${code}). ${errors.slice(0, 300)}`)); });
    child.stdin.on('error', () => {}); // A cancelled picker may close stdin before input is consumed.
    child.stdin.end(input);
  });
}

export async function atomicJson(file, value) {
  await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  const temporary = `${file}.${randomUUID()}.tmp`;
  try { await fs.writeFile(temporary, JSON.stringify(value, null, 2), { mode: 0o600, flag: 'wx' }); await fs.rename(temporary, file); }
  finally { await fs.unlink(temporary).catch(() => {}); }
}

async function seal(data) {
  const raw = Buffer.from(JSON.stringify(data)).toString('base64');
  if (process.platform !== 'win32') return { format: 'posix-permissions-only', data: raw };
  const script = "Add-Type -AssemblyName System.Security; $b=[Convert]::FromBase64String([Console]::In.ReadToEnd()); [Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect($b,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser))";
  return { format: 'windows-dpapi-v1', data: await powershell(script, raw) };
}
async function unseal(envelope) {
  if (envelope.format === 'windows-dpapi-v1') {
    if (process.platform !== 'win32') throw new Error('This vault belongs to a Windows user.');
    const script = "Add-Type -AssemblyName System.Security; $b=[Convert]::FromBase64String([Console]::In.ReadToEnd()); [Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Unprotect($b,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser))";
    return JSON.parse(Buffer.from(await powershell(script, envelope.data), 'base64').toString('utf8'));
  }
  if (envelope.format === 'posix-permissions-only' && process.platform !== 'win32') return JSON.parse(Buffer.from(envelope.data, 'base64').toString('utf8'));
  throw new Error('Unsupported credential vault.');
}

export class Store {
  constructor(directory = defaultStateDir()) { this.directory = directory; }
  async load() {
    await fs.mkdir(this.directory, { recursive: true, mode: 0o700 });
    let config = { version: 1, roots: [], paused: false, startup: false, relay: '' };
    try { config = JSON.parse(await fs.readFile(path.join(this.directory, 'settings.json'), 'utf8')); } catch (error) { if (error.code !== 'ENOENT') throw new Error('Settings are invalid; refusing to reset permissions silently.'); }
    if (config.version !== 1 || !Array.isArray(config.roots) || typeof config.paused !== 'boolean') throw new Error('Unsupported settings format.');
    let secrets = {};
    try { secrets = await unseal(JSON.parse(await fs.readFile(path.join(this.directory, 'vault.json'), 'utf8'))); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    return { config, secrets };
  }
  async saveConfig(config) { await atomicJson(path.join(this.directory, 'settings.json'), config); }
  async saveSecrets(secrets) { await atomicJson(path.join(this.directory, 'vault.json'), await seal(secrets)); }
  async saveSession(session) { await atomicJson(path.join(this.directory, 'session.json'), await seal(session)); }
  async readSession() { return unseal(JSON.parse(await fs.readFile(path.join(this.directory, 'session.json'), 'utf8'))); }
  privateRecordPath(key) {
    if (key === 'management-sessions') return path.join(this.directory, 'management', 'sessions.json');
    if (/^terminal-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(key)) return path.join(this.directory, 'terminal', key + '.json');
    if (!/^onboarding-(flow|intent)-[a-f0-9]{32}$/.test(key)) throw new Error('Invalid private onboarding record.');
    return path.join(this.directory, 'onboarding', key + '.json');
  }
  async readPrivateRecord(key) {
    const file = this.privateRecordPath(key);
    try {
      if ((await fs.lstat(path.dirname(file))).isSymbolicLink()) throw new Error('Private onboarding storage cannot be a link.');
      const stat = await fs.lstat(file);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > (key.startsWith('terminal-') ? 1024 : 256) * 1024) throw new Error('Unsafe private onboarding record.');
      return await unseal(JSON.parse(await fs.readFile(file, 'utf8')));
    } catch (error) { if (error.code === 'ENOENT') return null; throw error; }
  }
  async savePrivateRecord(key, value) {
    const file = this.privateRecordPath(key), directory = path.dirname(file);
    await fs.mkdir(directory, { recursive: true, mode: 0o700 });
    if ((await fs.lstat(directory)).isSymbolicLink()) throw new Error('Private onboarding storage cannot be a link.');
    if (key.startsWith('terminal-')) {
      // Keep launch reservations; deleting them implicitly would allow replay.
      // A bounded history fails closed instead of silently expiring request IDs.
      if ((await fs.readdir(directory)).length >= 2048 && !await this.readPrivateRecord(key)) throw new Error('Terminal journal capacity reached; no new command was started.');
      if (Buffer.byteLength(JSON.stringify(value)) > 512 * 1024) throw new Error('Terminal record is too large.');
      await atomicJson(file, await seal(value)); return;
    }
    const entries = await fs.readdir(directory, { withFileTypes: true });
    const owned = entries.filter(e => e.isFile() && /^onboarding-(flow|intent)-[a-f0-9]{32}\.json$/.test(e.name));
    if (owned.length >= 64) for (const entry of owned) {
      const target = path.join(directory, entry.name), info = await fs.lstat(target);
      if (target !== file && info.isFile() && info.nlink === 1 && Date.now() - info.mtimeMs > 48 * 3600000) await fs.unlink(target);
    }
    if ((await fs.readdir(directory)).length >= 128 && !await this.readPrivateRecord(key)) throw new Error('Too many recent onboarding attempts.');
    if (JSON.stringify(value).length > 64 * 1024) throw new Error('Onboarding record is too large.');
    await atomicJson(file, await seal(value));
  }
}

export async function pickFolder({ signal, onSpawn } = {}) {
  if (process.platform !== 'win32') throw new Error('The native picker is Windows-only. Enter a path instead.');
  // An owned, topmost dialog prevents the background agent's picker from being
  // lost behind the browser. Only this child is cancelled; no process-name kill.
  // Static script: no user-controlled shell interpolation.
  const script = "$ErrorActionPreference='Stop'; Add-Type -AssemblyName System.Windows.Forms; $owner=New-Object System.Windows.Forms.Form; $d=New-Object System.Windows.Forms.FolderBrowserDialog; try {$owner.Text='Chat2Local - Select folder'; $owner.TopMost=$true; $owner.ShowInTaskbar=$false; $owner.StartPosition='CenterScreen'; $owner.Width=1; $owner.Height=1; $owner.Opacity=0; $owner.Show(); $owner.Activate(); $d.Description='Chat2Local: select a folder. Sharing requires confirmation on the next page.'; $d.ShowNewFolderButton=$false; if($d.ShowDialog($owner) -eq [System.Windows.Forms.DialogResult]::OK){[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($d.SelectedPath))}} finally {$d.Dispose(); $owner.Close(); $owner.Dispose()}";
  const encoded = await powershell(script, '', 120_000, { sta: true, interactive: true, signal, onSpawn });
  return encoded ? Buffer.from(encoded, 'base64').toString('utf8') : null;
}

export async function openBrowser(url) {
  if (process.platform === 'win32') {
    const script = "$u=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Console]::In.ReadToEnd())); Start-Process -FilePath $u";
    await powershell(script, Buffer.from(url).toString('base64'));
  } else {
    await new Promise((resolve, reject) => {
      const child = spawn(process.platform === 'darwin' ? 'open' : 'xdg-open', [url], { stdio: 'ignore' });
      const timer = setTimeout(() => { child.kill(); reject(new Error('无法确认浏览器已打开，请在有桌面环境的用户会话中启动 Chat2Local。')); }, 15000);
      child.once('error', error => { clearTimeout(timer); reject(error); });
      child.once('close', code => { clearTimeout(timer); code === 0 ? resolve() : reject(new Error('系统未能打开浏览器；没有标记连接成功。')); });
    });
  }
}

export async function setStartup(enabled, entryFile, stateDir = defaultStateDir(), options = {}) {
  if (typeof enabled !== 'boolean') throw new Error('Startup requires an explicit boolean.');
  if (!startupAvailable(stateDir)) throw new Error('Login startup is unavailable for a custom development state directory or unsupported system.');
  if (process.platform !== 'win32') {
    const launcher = path.resolve(path.dirname(entryFile), '..', '..', 'scripts', 'launch.mjs');
    return setPosixStartup(enabled, launcher, { node: options.node || process.execPath });
  }
  const input = Buffer.from(JSON.stringify({ enabled, node: options.node || process.execPath, entry: path.resolve(entryFile) })).toString('base64');
  // Launch Node directly: no generated shell command or command-line secret.
  const script = String.raw`$ErrorActionPreference='Stop'; $c=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Console]::In.ReadToEnd()))|ConvertFrom-Json; $p=Join-Path ([Environment]::GetFolderPath('Startup')) 'Chat2Local.lnk'; $s=New-Object -ComObject WScript.Shell; if(Test-Path -LiteralPath $p){$old=$s.CreateShortcut($p); if($old.Description -ne 'Chat2Local managed startup'){throw 'Existing shortcut is not owned by Chat2Local'}}; if(-not $c.enabled){if(Test-Path -LiteralPath $p){Remove-Item -LiteralPath $p}; exit}; if($c.entry.Contains('"')){throw 'Invalid entry path'}; $l=$s.CreateShortcut($p); $l.TargetPath=$c.node; $l.Arguments='"'+$c.entry+'" --background'; $l.WorkingDirectory=Split-Path -Parent $c.entry; $l.WindowStyle=7; $l.Description='Chat2Local managed startup'; $l.Save()`;
  await powershell(script, input);
}
