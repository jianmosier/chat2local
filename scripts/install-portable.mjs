import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { VERSION } from '../src/shared/protocol.mjs';
import { prepareUpgrade } from './upgrade-session.mjs';
import { Store, setStartup, startupAvailable } from '../src/agent/store.mjs';
import { assertWriteFenceClear } from '../src/agent/files/write-fence.mjs';
import { verifyNativePackage, runNative, NATIVE_EXECUTABLE } from './native-package.mjs';
import { prepareNativeStartup } from './native-startup.mjs';

const hash = value => createHash('sha256').update(value).digest('hex');
const execute = promisify(execFile);
export function installationDirectory({ platform = process.platform, env = process.env, home = os.homedir() } = {}) {
  if (platform === 'win32') return path.win32.join(env.LOCALAPPDATA || path.win32.join(home, 'AppData', 'Local'), 'Chat2Local', 'apps');
  if (platform === 'darwin') return path.posix.join(home, 'Library', 'Application Support', 'Chat2Local', 'apps');
  if (platform === 'linux') return path.posix.join(env.XDG_DATA_HOME || path.posix.join(home, '.local', 'share'), 'chat2local', 'apps');
  throw new Error('Unsupported installation platform.');
}
async function filesIn(directory, prefix = '') {
  const output = [];
  for (const item of await fs.readdir(directory, { withFileTypes: true })) {
    if (item.isSymbolicLink()) throw new Error('Installation files cannot contain links.');
    const relative = prefix + item.name;
    if (item.isDirectory()) output.push(...await filesIn(path.join(directory, item.name), relative + '/'));
    else if (item.isFile()) output.push(relative);
    else throw new Error('Installation contains a non-regular file.');
    if (output.length > 1000) throw new Error('Installation contains too many files.');
  }
  return output.sort();
}
export async function verifyPackage(directory, { expectedManifestHash, target = `${process.platform}-${process.arch}`, allowOtherVersion = false } = {}) {
  const stat = await fs.lstat(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('Choose a real package directory.');
  const manifestFile = path.join(directory, 'BUILD-MANIFEST.json');
  const manifestStat = await fs.lstat(manifestFile);
  if (!manifestStat.isFile() || manifestStat.isSymbolicLink() || manifestStat.nlink !== 1 || manifestStat.size > 256 * 1024) throw new Error('Invalid package manifest file.');
  const raw = await fs.readFile(manifestFile); const manifestHash = hash(raw);
  if (expectedManifestHash && manifestHash !== expectedManifestHash) throw new Error('The installed manifest differs from the verified download. Existing files were retained.');
  const manifest = JSON.parse(raw.toString('utf8'));
  if (manifest.product !== 'Chat2Local' || !(allowOtherVersion ? /^\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?$/.test(manifest.version || '') : manifest.version === VERSION) || manifest.platform !== target || !manifest.files || typeof manifest.files !== 'object' || Array.isArray(manifest.files)) throw new Error('Package identity, version or architecture does not match this installer.');
  if (manifest.runtimeKind !== undefined && !['rust-native', 'node-legacy'].includes(manifest.runtimeKind)) throw Error('Unknown package runtime kind. No fallback is allowed.');
  const native = manifest.runtimeKind === 'rust-native';
  const names = Object.keys(manifest.files).sort();
  if (!names.length || names.length > 1000 || !names.includes('scripts/launch.mjs') || !names.includes(target.startsWith('win32-') ? 'runtime/node.exe' : 'runtime/node')) throw new Error('Incomplete package.');
  if (native && (target !== 'win32-x64' || ![NATIVE_EXECUTABLE, 'native/chat2local-terminal-runner.exe', 'native/manifest.json', 'scripts/native-package.mjs'].every(name => names.includes(name)))) throw Error('Incomplete native package or unsupported native platform.');
  for (const name of names) {
    if (name.startsWith('/') || name.includes('\\') || /[\x00-\x1f\x7f:]/.test(name) || name.split('/').some(part => !part || part === '.' || part === '..') || !/^[a-f0-9]{64}$/.test(manifest.files[name])) throw new Error('Unsafe package manifest entry.');
  }
  const actual = (await filesIn(directory)).filter(name => name !== 'BUILD-MANIFEST.json');
  if (JSON.stringify(names) !== JSON.stringify(actual)) throw new Error('Package files do not exactly match its manifest.');
  let total = 0;
  for (const name of names) {
    const file = path.join(directory, name); const info = await fs.lstat(file);
    total += info.size;
    if (!info.isFile() || info.nlink !== 1 || info.size > 128 * 1024 * 1024 || total > 256 * 1024 * 1024) throw new Error('Package contains an invalid or oversized file.');
    if (hash(await fs.readFile(file)) !== manifest.files[name]) throw new Error(`Package integrity check failed: ${name}. No downloaded executable was launched by this installer.`);
  }
  if (native) await verifyNativePackage(directory, { version: manifest.version, target });
  return { manifest, manifestHash, files: ['BUILD-MANIFEST.json', ...names] };
}

export function managementEntryContent(directory, { platform = process.platform, native = false, entryDirectory = path.dirname(path.dirname(directory)), port = 47631 } = {}) {
  const marker = 'chat2local-managed-entry-v1';
  const quote = value => "'" + value.replaceAll("'", "'\\''") + "'";
  const cmd = value => value.replaceAll('%', '%%');
  const release = path.basename(directory);
  if (native && (platform !== 'win32' || path.resolve(path.dirname(directory)) !== path.resolve(entryDirectory, 'apps') || !/^[a-zA-Z0-9._-]{1,160}$/.test(release) || ['.', '..'].includes(release) || !Number.isInteger(port) || port < 1 || port > 65535)) throw Error('Native management entry requires an ASCII release in its managed apps directory.');
  return platform === 'win32'
    ? `@echo off\r\nrem ${marker}\r\nsetlocal DisableDelayedExpansion\r\n${native ? `"%~dp0apps\\${release}\\native\\chat2local-native-agent.exe" --launch --state-dir "%~dp0." --port ${port}` : `"${cmd(path.join(directory, 'runtime', 'node.exe'))}" "${cmd(path.join(directory, 'scripts', 'launch.mjs'))}" --manage`}\r\nif errorlevel 1 pause\r\n`
    : `#!/bin/sh\n# ${marker}\nexec ${quote(path.join(directory, 'runtime', 'node'))} ${quote(path.join(directory, 'scripts', 'launch.mjs'))} --manage\n`;
}

export async function installManagementEntry(directory, { entryDirectory, platform = process.platform, home = os.homedir() } = {}) {
  const parent = entryDirectory || (platform === 'darwin' ? path.join(home, 'Applications') : path.dirname(path.dirname(directory)));
  await fs.mkdir(parent, { recursive: true, mode: 0o700 });
  if ((await fs.lstat(parent)).isSymbolicLink()) throw new Error('Management shortcut directory cannot be a link.');
  const file = path.join(parent, platform === 'win32' ? 'Chat2Local.cmd' : 'Chat2Local.command');
  const marker = 'chat2local-managed-entry-v1';
  const content = managementEntryContent(directory, { platform });
  try {
    const info = await fs.lstat(file);
    if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.size > 16384 || !(await fs.readFile(file, 'utf8')).includes(marker)) throw new Error('An unrelated management shortcut already exists; it was not overwritten.');
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
  await fs.writeFile(file, content, { mode: 0o700 }); await fs.chmod(file, 0o700);
  return file;
}

/** Retarget ONLY an already enabled login entry to this verified installation.
 * Do not enable a previously disabled preference or touch custom test stores. */
export async function refreshInstalledStartup(directory, { store = new Store(), apply = setStartup, available = startupAvailable, platform = process.platform } = {}) {
  const { config } = await store.load();
  if (config.startup !== true) return { enabled: false, updated: false };
  if (!available(store.directory)) throw new Error('Enabled login startup could not be updated for this state location.');
  const entry = path.join(directory, 'src', 'agent', 'main.mjs');
  const node = path.join(directory, 'runtime', platform === 'win32' ? 'node.exe' : 'node');
  await apply(true, entry, store.directory, { node });
  return { enabled: true, updated: true };
}

/** Install app files only. Never change user roots, device keys, OAuth scopes,
 * network settings or startup preferences. Releases are immutable and coexist.
 */
export async function installPortable(source, options = {}) {
  const target = options.target || `${process.platform}-${process.arch}`;
  const verified = await verifyPackage(source, { target, allowOtherVersion: options.rollback === true });
  const native = verified.manifest.runtimeKind === 'rust-native';
  const installRoot = options.installRoot || installationDirectory();
  await fs.mkdir(installRoot, { recursive: true, mode: 0o700 });
  if ((await fs.lstat(installRoot)).isSymbolicLink()) throw new Error('Installation directory must not be a link.');
  const lock = path.join(installRoot, '.install-lock');
  try { await fs.mkdir(lock, { mode: 0o700 }); }
  catch (error) { if (error.code === 'EEXIST') throw new Error('Another installation is active, or an interrupted installation lock needs review. No existing process was stopped.'); throw error; }
  let staging; let reused = false;
  const release = `${verified.manifest.version}-${verified.manifest.platform}-${verified.manifestHash.slice(0, 12)}`;
  const destination = path.join(installRoot, release);
  try {
    if (options.rollback && (!native || path.resolve(source) !== path.resolve(destination))) throw Error('Rollback requires a verified retained native installation in this apps directory. User state is never restored.');
    let exists = false;
    try { await fs.lstat(destination); exists = true; } catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (exists) { await verifyPackage(destination, { expectedManifestHash: verified.manifestHash, target, allowOtherVersion: options.rollback === true }); reused = true; }
    else {
      staging = await fs.mkdtemp(path.join(installRoot, '.staging-'));
      for (const relative of verified.files) {
        const bytes = await fs.readFile(path.join(source, relative));
        const expected = relative === 'BUILD-MANIFEST.json' ? verified.manifestHash : verified.manifest.files[relative];
        if (hash(bytes) !== expected) throw new Error('Source package changed during installation.');
        const file = path.join(staging, relative); await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
        await fs.writeFile(file, bytes, { flag: 'wx', mode: relative === 'runtime/node' || relative === 'start-chat2local.sh' ? 0o755 : 0o600 });
      }
      await verifyPackage(staging, { expectedManifestHash: verified.manifestHash, target });
      await fs.rename(staging, destination); staging = undefined;
    }
    if (native) {
      // A no-launch install stages immutable files only. A stopped preflight that
      // releases its port cannot authorize changing the current entry.
      if (options.launch === false) return { installed: true, reused, directory: destination, runtimeKind: 'rust-native', launched: false, stagedOnly: true, startup: { updated: false }, websiteClientVerified: false };
      const store = options.store || new Store();
      const parent = options.entryDirectory || path.dirname(installRoot);
      if (path.resolve(store.directory) !== path.resolve(parent)) throw Error('Native management entry must be in the original state directory. Choose its apps directory as installRoot; no controller was started or stopped.');
      await assertWriteFenceClear(store.directory);
      const invoke = options.nativeRun || runNative;
      const operation = { stateDirectory: store.directory, version: verified.manifest.version, target, port: options.port };
      const startup = options.installRoot && !options.store ? { enabled: false, updated: false, commit: async () => ({ updated: false }) }
        : await prepareNativeStartup(destination, { store, verify: verifyPackage, ...options.nativeStartup });
      const prior = await invoke(destination, ['--preflight'], operation);
      const managementEntry = path.join(parent, 'Chat2Local.cmd');
      if (prior.running === true) {
        if (!reused) throw Error('A live controller must Quit normally before switching packages.');
        let entry;
        try { const info = await fs.lstat(managementEntry); if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.size > 16384) throw Error(); entry = await fs.readFile(managementEntry, 'utf8'); } catch { throw Error('The running package has no exact managed entry. Quit normally before installing it.'); }
        if (entry !== managementEntryContent(destination, { platform: 'win32', native: true, entryDirectory: parent, port: options.port || 47631 })) throw Error('Management entry differs from this running package. Quit normally before switching it.');
        const receipt = await invoke(destination, ['--launch', ...(options.noBrowser ? ['--no-browser'] : [])], operation);
        if (receipt.reused !== true) throw Error('Same-package reuse was not confirmed. Existing entry was retained.');
        return { installed: true, reused: true, directory: destination, runtimeKind: 'rust-native', managementEntry, startup: { enabled: startup.enabled, updated: false }, launched: true, websiteClientVerified: false };
      }
      if (prior.stopped !== true) throw Error('Stopped controller preflight was not confirmed.');
      await invoke(destination, ['--launch', ...(options.noBrowser ? ['--no-browser'] : [])], operation);
      await fs.mkdir(parent, { recursive: true, mode: 0o700 });
      // This operation independently verifies/holds the new ProcessOwner and
      // session while replacing the entry atomically and retaining its old bytes.
      const activation = await invoke(destination, ['--activate-entry', parent], operation);
      if (activation.entryActivated !== true || path.resolve(activation.managementEntry || '') !== path.resolve(managementEntry)) throw Error('Management entry activation was not confirmed. No automatic fallback was started.');
      return { installed: true, reused, directory: destination, runtimeKind: 'rust-native', managementEntry, startup: await startup.commit(), launched: true, websiteClientVerified: false };
    }
    if (options.launch !== false) {
      const upgrade = await prepareUpgrade(VERSION);
      const executable = path.join(destination, 'runtime', process.platform === 'win32' ? 'node.exe' : 'node');
      // Uses the installed runtime, never the temporary download or a global Node/npm.
      const result = await execute(executable, [path.join(destination, 'scripts', 'launch.mjs'), ...(options.noBrowser ? ['--no-browser'] : [])], { timeout: 45000, windowsHide: true, maxBuffer: 65536 });
      if (result.stdout) process.stdout.write(result.stdout);
      await upgrade.verify();
    }
    const managementEntry = await installManagementEntry(destination, { entryDirectory: options.installRoot ? path.dirname(installRoot) : undefined });
    const startup = options.launch !== false && !options.installRoot ? await refreshInstalledStartup(destination) : { updated: false };
    return { installed: true, reused, directory: destination, managementEntry, startup, launched: options.launch !== false, websiteClientVerified: false };
  } finally {
    if (staging) await fs.rm(staging, { recursive: true, force: true });
    await fs.rmdir(lock);
  }
}
if (import.meta.main) {
  const args = process.argv.slice(2);
  let rollback;
  if (args[0] === '--rollback' && args[1] && path.isAbsolute(args[1])) { rollback = args[1]; args.splice(0, 2); }
  if (args.some(arg => arg !== '--no-browser')) { console.error('Usage: install-portable.mjs [--rollback ABSOLUTE_RETAINED_INSTALLATION] [--no-browser]'); process.exitCode = 1; }
  else if (typeof process.getuid === 'function' && process.getuid() === 0) { console.error('Run Chat2Local as your normal desktop user, not with sudo/root.'); process.exitCode = 1; }
  else installPortable(rollback || fileURLToPath(new URL('..', import.meta.url)), { noBrowser: args.includes('--no-browser'), rollback: Boolean(rollback) }).then(result => console.log(JSON.stringify(result, null, 2))).catch(error => { console.error(`Chat2Local install: ${error.message}`); process.exitCode = 1; });
}
