// Public, non-secret UI instructions. Never accept credentials or shell input
// as an instance address; commands contain only a canonical HTTPS origin.
export function installationOrigin(value) {
  if (typeof value !== 'string') throw new Error('An HTTPS instance address is required.');
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash
      || url.pathname !== '/' || !/^[a-z0-9.-]+$/.test(url.hostname)
      || (value !== url.origin && value !== url.origin + '/')) {
    throw new Error('Use the HTTPS instance root, without /mcp or credentials.');
  }
  return url.origin;
}

export function installationInstructions(value, platform) {
  const origin = installationOrigin(value);
  if (!['win32', 'darwin'].includes(platform)) {
    throw new Error('Packaged installation instructions are available for Windows and macOS.');
  }
  return Object.freeze({
    origin,
    page: origin + '/install',
    mcp: origin + '/mcp',
    command: platform === 'win32'
      ? `irm ${origin}/install.ps1 | iex`
      : `curl -fsS --proto '=https' ${origin}/install.sh | sh`,
    dailyEntry: platform === 'win32'
      ? '%LOCALAPPDATA%\\Chat2Local\\Chat2Local.cmd'
      : 'open "$HOME/Applications/Chat2Local.command"',
  });
}
