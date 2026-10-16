import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { randomUUID } from 'node:crypto';
import { sameDirectory } from '../platform.mjs';

const within = (root, candidate) => {
  const relative = path.relative(root, candidate);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
};

export const forbiddenName = name =>
  /^(\.env(?:\..*)?|\.dev\.vars(?:\..*)?|\.git|\.ssh|\.aws|\.azure|\.kube|\.gnupg|\.npmrc|\.netrc|\.gitconfig|node_modules|id_rsa.*|id_ed25519.*|credentials(?:\..*)?|auth\.json|\.chat2local-.*)$/i.test(name)
  || /\.(pem|key|p12|pfx)$/i.test(name);

export function relativeParts(input, allowRoot = false) {
  if (allowRoot && (input === '.' || input === '')) return [];
  if (typeof input !== 'string' || input.length > 1024 || /^[\\/]/.test(input) || /[:\x00-\x1f\x7f]/.test(input)) {
    throw new Error('Only a safe relative path is allowed.');
  }
  const parts = input.replaceAll('\\', '/').split('/');
  if (parts.some(part => !part || part === '.' || part === '..' || /[. ]$/.test(part)
    || /[<>"|?*]/.test(part) || /^(con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/i.test(part) || forbiddenName(part))) {
    throw new Error('Path traversal, reserved names, and sensitive files are blocked.');
  }
  return parts;
}

/** Validate a locally selected share; does not persist or grant access. */
export async function approveRoot(input, stateDir, write = false) {
  if (typeof input !== 'string' || !path.isAbsolute(input) || /^\\\\/.test(input)) {
    throw new Error('Choose an absolute local folder.');
  }
  const selected = await fs.lstat(input);
  if (!selected.isDirectory() || selected.isSymbolicLink()) throw new Error('Select a real directory, not a link.');
  const canonical = await fs.realpath(input);
  const home = await fs.realpath(os.homedir());
  if (canonical === path.parse(canonical).root || await sameDirectory(canonical, home)) {
    throw new Error('Do not authorize an entire drive or user profile.');
  }
  // Resolve macOS /var and /tmp aliases on both sides of the comparison.
  const privateState = stateDir ? await fs.realpath(stateDir).catch(error => {
    if (error.code === 'ENOENT') return path.resolve(stateDir);
    throw error;
  }) : null;
  if (privateState && (within(canonical, privateState) || within(privateState, canonical))) {
    throw new Error('The Chat2Local private state folder cannot be authorized.');
  }
  const systemPaths = process.platform === 'win32'
    ? [process.env.WINDIR, process.env.ProgramFiles, process.env['ProgramFiles(x86)']].filter(Boolean)
    : ['/System', '/Library', '/bin', '/sbin', '/usr', '/etc', '/private/etc', '/boot', '/proc', '/sys', '/dev'];
  for (const protectedPath of systemPaths) {
    if (within(path.resolve(protectedPath), canonical) || within(canonical, path.resolve(protectedPath))) {
      throw new Error('System and application directories are not allowed.');
    }
  }
  return { id: randomUUID(), label: path.basename(canonical), path: canonical, write: write === true };
}

/** Resolve a file-tool path after the caller checks the current share policy. */
export async function resolveFilePath(root, relative, { directory = false, mayCreate = false } = {}) {
  const parts = relativeParts(relative, directory);
  if (await fs.realpath(root.path) !== root.path) throw new Error('The authorized root changed. Select it again.');
  let current = root.path;
  for (let index = 0; index < parts.length; index++) {
    current = path.join(current, parts[index]);
    let stat;
    try {
      stat = await fs.lstat(current);
    } catch (error) {
      if (error.code === 'ENOENT' && mayCreate && index === parts.length - 1) return { root, target: current };
      throw error;
    }
    if (stat.isSymbolicLink()) throw new Error('Symbolic links and junctions are blocked.');
    if (index < parts.length - 1 && !stat.isDirectory()) throw new Error('Parent is not a directory.');
    if (!within(root.path, await fs.realpath(current))) throw new Error('Path leaves the authorized folder.');
    if (index === parts.length - 1 && !directory && (!stat.isFile() || stat.nlink !== 1)) {
      throw new Error('Only regular, single-link files are allowed.');
    }
  }
  if (directory && !(await fs.stat(current)).isDirectory()) throw new Error('Not a directory.');
  return { root, target: current };
}
