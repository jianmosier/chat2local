import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs/promises';
import { lstatSync } from 'node:fs';

const systems = { win32: 'Windows', darwin: 'macOS', linux: 'Linux' };

/** Product metadata only: never use a hostname or OS name as an authorization identity. */
export function platformInfo({ platform = process.platform, arch = process.arch, hostname = os.hostname() } = {}) {
  return { platform, arch, system: systems[platform] || platform, name: hostname };
}

export function stateDirectory({ env = process.env, platform = process.platform, home = os.homedir() } = {}) {
  if (env.CHAT2LOCAL_STATE_DIR) return env.CHAT2LOCAL_STATE_DIR;
  if (platform === 'win32') return path.win32.join(env.LOCALAPPDATA || path.win32.join(home, 'AppData', 'Local'), 'Chat2Local');
  if (platform === 'darwin') return path.posix.join(home, 'Library', 'Application Support', 'Chat2Local');
  return path.posix.join(env.XDG_STATE_HOME || path.posix.join(home, '.local', 'state'), 'chat2local');
}

/** Preserve the pre-alpha.7 POSIX location when it contains existing user state.
 * Never silently start with empty permissions/identity merely because defaults changed.
 */
export function existingStateDirectory(options = {}) {
  const env = options.env || process.env;
  const preferred = stateDirectory(options);
  if (env.CHAT2LOCAL_STATE_DIR || (options.platform || process.platform) === 'win32') return preferred;
  const home = options.home || os.homedir();
  const legacy = path.join(home, '.local', 'share', 'Chat2Local');
  const hasState = dir => {
    for (const file of ['settings.json', 'vault.json', 'session.json']) {
      try { lstatSync(path.join(dir, file)); return true; } catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
    return false;
  };
  const current = hasState(preferred); const previous = hasState(legacy);
  if (current && previous && preferred !== legacy) throw new Error('发现两套 Chat2Local 配置。请指定原有状态目录；没有合并或重置授权。');
  return previous ? legacy : preferred;
}

/** Compare the actual directories, including case-sensitive APFS/ext4 volumes.
 * realpath normalizes links; dev/ino also identifies case aliases on Windows/macOS.
 */
export async function sameDirectory(first, second) {
  const [a, b] = await Promise.all([fs.realpath(first), fs.realpath(second)]);
  if (a === b) return true;
  const [sa, sb] = await Promise.all([fs.stat(a, { bigint: true }), fs.stat(b, { bigint: true })]);
  return sa.isDirectory() && sb.isDirectory() && sa.ino !== 0n && sa.dev === sb.dev && sa.ino === sb.ino;
}
