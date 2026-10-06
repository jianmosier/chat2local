import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { randomUUID } from 'node:crypto';

const marker = 'Chat2Local managed startup v1';
const xml = value => value.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&apos;');
function argument(value) {
  if (typeof value !== 'string' || !path.posix.isAbsolute(value) || /[\x00-\x1f\x7f]/.test(value)) throw new Error('Startup requires an absolute, single-line executable path.');
  return value;
}
// freedesktop Exec field escaping, NOT shell quoting. Percent is a field code.
const desktopArgument = value => '"' + value.replaceAll('\\', '\\\\').replaceAll('"', '\\"').replaceAll('`', '\\`').replaceAll('$', '\\$').replaceAll('%', '%%') + '"';

/** These entries invoke the verified launcher once at login. They do not grant
 * directories, re-enroll devices, or restart an agent that the user explicitly exits.
 */
export function posixStartupPlan({ platform = process.platform, home = os.homedir(), env = process.env, node = process.execPath, launcher } = {}) {
  argument(home); argument(node); argument(launcher);
  if (platform === 'darwin') {
    return {
      file: path.posix.join(home, 'Library', 'LaunchAgents', 'io.chat2local.agent.plist'),
      marker,
      content: `<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<!-- ${marker} -->\n<plist version="1.0"><dict>\n<key>Label</key><string>io.chat2local.agent</string>\n<key>ProgramArguments</key><array><string>${xml(node)}</string><string>${xml(launcher)}</string><string>--no-browser</string></array>\n<key>RunAtLoad</key><true/>\n<key>ProcessType</key><string>Background</string>\n</dict></plist>\n`,
    };
  }
  if (platform === 'linux') {
    const configHome = argument(env.XDG_CONFIG_HOME || path.posix.join(home, '.config'));
    return {
      file: path.posix.join(configHome, 'autostart', 'chat2local.desktop'), marker,
      content: `[Desktop Entry]\n# ${marker}\nType=Application\nName=Chat2Local\nComment=Reconnect authorized folders after desktop login\nExec=${desktopArgument(node)} ${desktopArgument(launcher)} --no-browser\nTerminal=false\nX-GNOME-Autostart-enabled=true\n`,
    };
  }
  throw new Error('Unsupported desktop startup platform.');
}

export async function setPosixStartup(enabled, launcher, options = {}) {
  if (typeof enabled !== 'boolean') throw new Error('Startup requires an explicit boolean.');
  const plan = posixStartupPlan({ ...options, launcher });
  let previous;
  try {
    const stat = await fs.lstat(plan.file);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) throw new Error('Startup entry is not a regular, owned file.');
    previous = await fs.readFile(plan.file, 'utf8');
    if (!previous.includes(plan.marker)) throw new Error('Existing startup entry is not owned by Chat2Local.');
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
  if (!enabled) { if (previous !== undefined) await fs.unlink(plan.file); return; }
  await fs.mkdir(path.dirname(plan.file), { recursive: true, mode: 0o700 });
  const temporary = `${plan.file}.${randomUUID()}.tmp`;
  try {
    await fs.writeFile(temporary, plan.content, { mode: 0o600, flag: 'wx' });
    await fs.rename(temporary, plan.file);
  } finally { await fs.unlink(temporary).catch(() => {}); }
}
