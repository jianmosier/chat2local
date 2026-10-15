import fs from 'node:fs/promises';
import path from 'node:path';
import { spawn } from 'node:child_process';

/** Pass only the existing allowlisted environment, not credentials or profiles. */
export function terminalEnvironment(env = process.env) {
  const result = {};
  const names = [
    'PATH', 'Path', 'PATHEXT', 'SystemRoot', 'SYSTEMROOT', 'WINDIR', 'COMSPEC',
    'TEMP', 'TMP', 'TMPDIR', 'HOME', 'USERPROFILE', 'HOMEDRIVE', 'HOMEPATH',
    'LANG', 'LC_ALL', 'NUMBER_OF_PROCESSORS',
  ];
  for (const name of names) if (typeof env[name] === 'string') result[name] = env[name];
  result.NO_COLOR = '1';
  return result;
}

export function terminalShell(command, shell = 'auto', platform = process.platform, env = process.env) {
  const selected = shell === 'auto' ? platform === 'win32' ? 'powershell' : 'sh' : shell;
  if (platform === 'win32' && selected === 'powershell') {
    const file = path.win32.join(env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
    return {
      shell: selected, file,
      args: ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
        `[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false); $global:LASTEXITCODE = 0; & { ${command}\n}; if (-not $?) { exit 1 }; exit $LASTEXITCODE`],
    };
  }
  if (platform !== 'win32' && selected === 'sh') return { shell: selected, file: '/bin/sh', args: ['-c', command] };
  throw new Error('Unsupported shell on this computer; use auto, PowerShell on Windows, or sh on macOS/Linux.');
}

/** Validate the initial working directory, not every subsequent command effect. */
export async function terminalCwd(root, relative = '.') {
  if (typeof relative !== 'string' || relative.length > 2048 || path.isAbsolute(relative)
    || /[\x00-\x1f:]/.test(relative) || relative.split(/[\\/]/).some(part => part === '..')) {
    throw new Error('cwd must be a relative directory inside the selected root.');
  }
  const base = await fs.realpath(root);
  let cursor = root;
  for (const part of relative.split(/[\\/]/).filter(item => item && item !== '.')) {
    cursor = path.join(cursor, part);
    if ((await fs.lstat(cursor)).isSymbolicLink()) throw new Error('A linked working directory is not permitted.');
  }
  const current = await fs.realpath(cursor);
  const rel = path.relative(base, current);
  if (rel.startsWith('..' + path.sep) || rel === '..' || path.isAbsolute(rel) || !(await fs.stat(current)).isDirectory()) {
    throw new Error('Working directory is not inside the selected root.');
  }
  return current;
}

/** Request termination of the attached process tree; detached descendants may survive. */
export function terminateProcessTree(child, record) {
  try {
    if (process.platform === 'win32') {
      const file = path.win32.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'taskkill.exe');
      const killer = spawn(file, ['/PID', String(child.pid), '/T', '/F'], {
        shell: false, windowsHide: true, stdio: 'ignore',
      });
      killer.once('error', () => { record.terminationConfirmed = false; });
      killer.once('close', code => { record.terminationConfirmed = code === 0; });
    } else {
      process.kill(-child.pid, 'SIGKILL');
      record.terminationConfirmed = true;
    }
  } catch {
    record.terminationConfirmed = false;
  }
}
