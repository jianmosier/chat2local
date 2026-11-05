import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { VERSION } from '../src/shared/protocol.mjs';

export const NATIVE_EXECUTABLE = 'native/chat2local-native-agent.exe';
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const execute = promisify(execFile);

/** Installed packages do not contain the build checkout. Verify only the sealed
 * runtime contract and its two images; source provenance is checked at build time. */
export async function verifyNativePackage(directory, { version = VERSION, target = `${process.platform}-${process.arch}` } = {}) {
  if (target !== 'win32-x64') throw Error('The native package requires Windows x64; no runtime fallback is allowed.');
  const native = path.join(directory, 'native');
  const info = await fs.lstat(native);
  if (!info.isDirectory() || info.isSymbolicLink()) throw Error('Unsafe native package directory.');
  async function bytes(name, maximum) {
    const file = path.join(native, name), stat = await fs.lstat(file);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > maximum) throw Error('Unsafe native package file.');
    return fs.readFile(file);
  }
  const manifest = JSON.parse((await bytes('manifest.json', 1024 * 1024)).toString('utf8'));
  const cap = manifest.capabilities;
  if (manifest.v !== 1 || manifest.platform !== 'win32' || manifest.architecture !== 'x64'
      || manifest.fixtureOnly !== false || manifest.fullAgent !== false || manifest.upgradeReady !== false
      || manifest.executable !== 'chat2local-native-agent.exe' || manifest.opensslVersion !== '3.5.8'
      || JSON.stringify(manifest.features) !== '[]' || cap?.name !== 'chat2local-native-agent'
      || cap.version !== version || cap.fixtureOnly !== false || cap.fullAgent !== false || cap.upgradeReady !== false
      || cap.localPanel !== true || cap.terminalAvailable !== true || !cap.openssl?.startsWith('OpenSSL 3.5.8 ')
      || !Array.isArray(cap.routes) || !['/api/status', '/api/shutdown', '/api/instance/import-invitation'].every(route => cap.routes.includes(route))
      || manifest.terminalRunner?.fixtureOnly !== false || manifest.terminalRunner.executable !== 'chat2local-terminal-runner.exe'
      || !/^[a-f0-9]{64}$/.test(manifest.sha256 || '') || !/^[a-f0-9]{64}$/.test(manifest.terminalRunner.sha256 || '')) throw Error('Native runtime contract mismatch.');
  if (digest(await bytes(manifest.executable, 128 * 1024 * 1024)) !== manifest.sha256
      || digest(await bytes(manifest.terminalRunner.executable, 128 * 1024 * 1024)) !== manifest.terminalRunner.sha256) throw Error('Native runtime image integrity check failed.');
  if (manifest.runtimeDependencies !== undefined && (!manifest.runtimeDependencies || typeof manifest.runtimeDependencies !== 'object' || Array.isArray(manifest.runtimeDependencies))) throw Error('Invalid native runtime dependency manifest.');
  for (const [name, expected] of Object.entries(manifest.runtimeDependencies || {})) {
    if (name !== 'vcruntime140.dll' || !/^[a-f0-9]{64}$/.test(expected) || digest(await bytes(name, 4 * 1024 * 1024)) !== expected) throw Error('Native runtime dependency integrity check failed.');
  }
  if (manifest.noticesSha256 !== undefined && (!/^[a-f0-9]{64}$/.test(manifest.noticesSha256) || digest(await bytes('THIRD-PARTY-NOTICES.txt', 4 * 1024 * 1024)) !== manifest.noticesSha256)) throw Error('Native third-party notices integrity check failed.');
  return manifest;
}

export async function runNative(directory, args, { stateDirectory, port, version, target, run = execute } = {}) {
  await verifyNativePackage(directory, { version, target });
  let result;
  try { result = await run(path.join(directory, NATIVE_EXECUTABLE), [...args, ...(stateDirectory ? ['--state-dir', stateDirectory] : []), ...(port ? ['--port', String(port)] : [])], { timeout: 45000, windowsHide: true, maxBuffer: 65536 }); }
  catch { throw Error('Native package or controller ownership was not confirmed. Use normal Quit in the original panel, then rerun. No automatic stop, fallback or retry was attempted.'); }
  let receipt;
  try { receipt = JSON.parse(result.stdout); } catch { throw Error('Native operation did not produce a verified receipt. No retry was attempted.'); }
  if (receipt.name !== 'chat2local-native-agent' || receipt.fixtureOnly !== false || receipt.fullAgent !== false || receipt.upgradeReady !== false) throw Error('Native operation receipt mismatch.');
  return receipt;
}
