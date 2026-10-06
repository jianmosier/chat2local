// One target contract shared by the packager, installer and release checks.
export const NODE_VERSION = 'v24.21.0';
export const RELEASE_TARGETS = Object.freeze({
  'win32-x64': { system: 'Windows', nodePlatform: 'win', arch: 'x64', extension: 'zip', executable: 'node.exe' },
  'win32-arm64': { system: 'Windows', nodePlatform: 'win', arch: 'arm64', extension: 'zip', executable: 'node.exe' },
  'darwin-x64': { system: 'macOS', nodePlatform: 'darwin', arch: 'x64', extension: 'tar.gz', executable: 'bin/node' },
  'darwin-arm64': { system: 'macOS', nodePlatform: 'darwin', arch: 'arm64', extension: 'tar.gz', executable: 'bin/node' },
  'linux-x64': { system: 'Linux', nodePlatform: 'linux', arch: 'x64', extension: 'tar.gz', executable: 'bin/node' },
  'linux-arm64': { system: 'Linux', nodePlatform: 'linux', arch: 'arm64', extension: 'tar.gz', executable: 'bin/node' },
});
export function releaseTarget(key = `${process.platform}-${process.arch}`) {
  const target = RELEASE_TARGETS[key];
  if (!target) throw new Error(`Unsupported release target: ${key}. No fallback executable will be used.`);
  return { ...target, key, prefix: `Chat2Local-${target.system}-${target.arch}`, runtimeFolder: `node-${NODE_VERSION}-${target.nodePlatform}-${target.arch}`, archiveName: `node-${NODE_VERSION}-${target.nodePlatform}-${target.arch}.${target.extension}` };
}
export function packageNameFor(key, name) {
  const target = releaseTarget(key);
  const chosen = name || target.prefix;
  if (!new RegExp(`^${target.prefix}(?:-[a-z0-9-]+)?$`).test(chosen)) throw new Error('Package name does not match its target platform.');
  return chosen;
}
