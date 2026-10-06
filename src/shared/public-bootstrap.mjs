export function publicBootstrap(origin, source) {
  const url = new URL(origin);
  if (url.protocol !== 'https:' || url.origin !== origin || !/^[a-z0-9.-]+$/.test(url.hostname)) throw new Error('Canonical private HTTPS instance required.');
  if (typeof source !== 'string' || !/^https:\/\/raw\.githubusercontent\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/v0\.1\.0-alpha\.[0-9]+\/install\.sh$/.test(source)) throw new Error('An explicit version-pinned public bootstrap is required.');
  return `#!/bin/sh\nset -eu\numask 077\nfile=$(mktemp -t chat2local-bootstrap.XXXXXXXX)\ntrap 'rm -f "$file"' EXIT HUP INT TERM\ncurl --fail --show-error --proto '=https' --connect-timeout 20 --max-time 60 --max-filesize 131072 '${source}' --output "$file"\ntest -s "$file" || { echo 'Empty bootstrap; stopped.' >&2; exit 1; }\nsh "$file" --instance '${origin}'\n`;
}
