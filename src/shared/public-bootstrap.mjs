import { installationOrigin } from './installation.mjs';

function checkedBootstrap(origin, source) {
  if (installationOrigin(origin) !== origin) {
    throw new Error('Canonical private HTTPS instance required.');
  }
  if (typeof source !== 'string'
      || !/^https:\/\/raw\.githubusercontent\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/v0\.1\.0-alpha\.[0-9]+\/install\.sh$/.test(source)) {
    throw new Error('An explicit version-pinned public bootstrap is required.');
  }
}

export function publicBootstrap(origin, source) {
  checkedBootstrap(origin, source);
  return `#!/bin/sh
set -eu
umask 077
file=$(mktemp -t chat2local-bootstrap.XXXXXXXX)
trap 'rm -f "$file"' EXIT HUP INT TERM
curl --fail --show-error --proto '=https' --connect-timeout 20 --max-time 60 --max-filesize 131072 '${source}' --output "$file"
test -s "$file" || { echo 'Empty bootstrap; stopped.' >&2; exit 1; }
sh "$file" --instance '${origin}'
`;
}

export function publicPowerShellBootstrap(origin, source) {
  checkedBootstrap(origin, source);
  const windowsSource = source.replace(/install\.sh$/, 'install.ps1');
  return `$ErrorActionPreference = 'Stop'
# The entire pinned bootstrap is downloaded before it is executed.
$Bootstrap = Invoke-RestMethod -Uri '${windowsSource}' -MaximumRedirection 0 -TimeoutSec 60
if ($Bootstrap -isnot [string] -or [string]::IsNullOrWhiteSpace($Bootstrap) -or $Bootstrap.Length -gt 131072) {
    throw 'Invalid bootstrap. No downloaded program was launched.'
}
& ([scriptblock]::Create($Bootstrap)) -Instance '${origin}'
`;
}
