import fs from 'node:fs/promises';
import path from 'node:path';
import { powershell, startupAvailable } from '../src/agent/store.mjs';
import { NATIVE_EXECUTABLE } from './native-package.mjs';
const input = value => Buffer.from(JSON.stringify(value)).toString('base64');
const prefix = "$ErrorActionPreference='Stop';$c=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Console]::In.ReadToEnd()))|ConvertFrom-Json;";
export async function inspectNativeStartup() {
  return JSON.parse(await powershell(prefix + "$d=[Environment]::GetFolderPath('Startup');$p=Join-Path $d 'Chat2Local Native.lnk';$legacy=Join-Path $d 'Chat2Local.lnk';$v=$null;if(Test-Path -LiteralPath $p){$s=New-Object -ComObject WScript.Shell;$l=$s.CreateShortcut($p);$v=@{path=$p;target=$l.TargetPath;arguments=$l.Arguments;working=$l.WorkingDirectory;description=$l.Description}};@{legacy=(Test-Path -LiteralPath $legacy);native=$v}|ConvertTo-Json -Compress", input({})));
}

/** Preserve the preference. A legacy/unknown entry needs its original launcher's
 * explicit disable action. No settings or vault bytes are written here. */
export async function prepareNativeStartup(directory, { store, verify, inspect = inspectNativeStartup, available = startupAvailable } = {}) {
  let config = { startup: false };
  try { config = JSON.parse(await fs.readFile(path.join(store.directory, 'settings.json'), 'utf8')); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  if (!available(store.directory)) {
    if (config.startup === true) throw Error('Enabled startup is unavailable for this state location. Disable it in the original launcher before switching.');
    return { enabled: false, updated: false, commit: async () => ({ enabled: false, updated: false }) };
  }
  const snapshot = await inspect();
  if (snapshot.legacy) throw Error('Legacy Chat2Local login startup is present. Disable login startup in the original panel, quit normally, then rerun the installer. No startup entry was changed.');
  const old = snapshot.native;
  if (!old && config.startup === true || old && config.startup !== true) throw Error('Login startup and its saved preference differ. Review startup in the original panel before switching.');
  if (!old) return { enabled: false, updated: false, commit: async () => ({ enabled: false, updated: false }) };
  if (old.description !== 'Chat2Local managed startup' || old.arguments !== '--background'
      || !path.isAbsolute(old.target) || path.basename(old.target) !== 'chat2local-native-agent.exe'
      || old.working !== path.dirname(old.target) || path.basename(path.dirname(old.target)) !== 'native') throw Error('Unknown native startup entry was retained. Review it in its original launcher.');
  await verify(path.dirname(path.dirname(old.target)), { allowOtherVersion: true });
  const file = await fs.lstat(old.path);
  if (!file.isFile() || file.isSymbolicLink() || file.nlink !== 1 || file.size > 65536) throw Error('Unsafe native startup entry was retained.');
  const target = path.join(directory, NATIVE_EXECUTABLE);
  if (path.resolve(old.target) !== path.resolve(target)) throw Error('Enabled native login startup still targets the previous package. Disable login startup in its original panel, quit normally, rerun this installer, then enable startup in the new panel. The preference and old shortcut were retained.');
  return { enabled: true, updated: false, commit: async () => ({ enabled: true, updated: false }) };
}
