import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { VERSION } from '../src/shared/protocol.mjs';
import { releaseTarget, packageNameFor, RELEASE_TARGETS } from './release-targets.mjs';

function releaseBase(value) {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || !/^[a-z0-9.-]+$/i.test(url.hostname) || !/^[a-z0-9/._~-]*$/i.test(url.pathname) || url.hostname.endsWith('.invalid') || url.hostname === 'localhost') throw new Error('Provide the real public HTTPS release directory, without credentials, query, or fragment.');
  return url.href.replace(/\/$/, '');
}
export function installerArtifacts(records) {
  const seen = new Set();
  return records.map(record => {
    const target = releaseTarget(record.target); const folder = packageNameFor(record.target, record.packageName);
    if (seen.has(record.target) || record.version !== VERSION || !/^[a-f0-9]{64}$/.test(record.sha256) || record.file !== `${folder}.${target.extension}`) throw new Error('Invalid, duplicate or mismatched release metadata.');
    seen.add(record.target);
    return { target: record.target, folder, file: record.file, sha256: record.sha256 };
  });
}
export function renderPosixInstaller(baseValue, records) {
  const base = releaseBase(baseValue); const artifacts = installerArtifacts(records).filter(item => !item.target.startsWith('win32-'));
  if (!artifacts.length) throw new Error('No POSIX release artifacts.');
  const cases = artifacts.map(item => `  ${item.target}) file='${item.file}'; folder='${item.folder}'; expected='${item.sha256}' ;;`).join('\n');
  return `#!/bin/sh
# Generated, version-pinned Chat2Local installer. No Node.js/npm/Git prerequisite.
set -eu
umask 077
echo '[chat2local ${VERSION}] Checking this computer...'
if [ "$(id -u)" = 0 ]; then echo 'Run as your normal desktop user, without sudo/root.' >&2; exit 1; fi
case "$(uname -s)" in Darwin) platform=darwin ;; Linux) platform=linux ;; *) echo 'Unsupported operating system.' >&2; exit 1 ;; esac
case "$(uname -m)" in arm64|aarch64) arch=arm64 ;; x86_64|amd64) arch=x64 ;; *) echo 'Unsupported CPU; no emulated fallback will be installed.' >&2; exit 1 ;; esac
if [ "$platform" = darwin ] && [ "$(sysctl -n hw.optional.arm64 2>/dev/null || true)" = 1 ]; then arch=arm64; fi
# Minimums for the pinned Node v24 runtime; checked before any download.
command -v awk >/dev/null 2>&1 || { echo 'The system version-check tool awk is required.' >&2; exit 1; }
version_at_least() {
  awk -v actual="$1" -v minimum="$2" 'BEGIN { if (actual !~ /^[0-9]+[.][0-9]+([.][0-9]+)*$/) exit 1; split(actual,a,"."); split(minimum,b,"."); exit !(a[1]+0>b[1]+0 || (a[1]+0==b[1]+0 && a[2]+0>=b[2]+0)) }'
}
if [ "$platform" = darwin ]; then
  version=$(sw_vers -productVersion)
  version_at_least "$version" '13.5' || { echo 'This release requires macOS 13.5 or newer. No package was installed.' >&2; exit 1; }
else
  libc=$(getconf GNU_LIBC_VERSION 2>/dev/null || true)
  case "$libc" in 'glibc '*) version=\${libc#glibc } ;; *) echo 'This release needs GNU/Linux glibc; musl/Alpine is not a supported binary target.' >&2; exit 1 ;; esac
  version_at_least "$version" '2.28' || { echo 'This release requires glibc 2.28 or newer.' >&2; exit 1; }
  kernel=$(uname -r); kernel=\${kernel%%-*}; kernel=\${kernel%%+*}
  version_at_least "$kernel" '4.18' || { echo 'This release requires Linux kernel 4.18 or newer.' >&2; exit 1; }
fi
case "$platform-$arch" in
${cases}
  *) echo 'This release has no verified package for your system yet.' >&2; exit 1 ;;
esac
command -v curl >/dev/null 2>&1 || { echo 'The system download tool curl is required.' >&2; exit 1; }
command -v tar >/dev/null 2>&1 || { echo 'The system archive tool tar is required.' >&2; exit 1; }
if command -v shasum >/dev/null 2>&1; then checksum=shasum; elif command -v sha256sum >/dev/null 2>&1; then checksum=sha256sum; else echo 'A system SHA-256 tool is required.' >&2; exit 1; fi
stage=$(mktemp -d "\${TMPDIR:-/tmp}/chat2local-install.XXXXXXXX")
# macOS /var and /tmp may be aliases. Execute only from the physical staging path.
stage=$(CDPATH= cd -P "$stage" && pwd -P)
trap 'rm -rf "$stage"' EXIT HUP INT TERM
archive="$stage/release.tar.gz"
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 5 --connect-timeout 20 --max-time 240 --max-filesize 134217728 '${base}/'"$file" --output "$archive"
echo '[chat2local] Checking complete package SHA-256...'
if [ "$checksum" = shasum ]; then result=$(shasum -a 256 "$archive"); else result=$(sha256sum "$archive"); fi
actual=\${result%% *}
if [ "$actual" != "$expected" ]; then echo 'SHA-256 mismatch. The package was not extracted or launched.' >&2; exit 1; fi
echo '[chat2local] Extracting verified package and starting installer...'
tar -xzf "$archive" -C "$stage"
"$stage/$folder/runtime/node" "$stage/$folder/scripts/install-portable.mjs"
`;
}
export function renderWindowsInstaller(baseValue, records) {
  const base = releaseBase(baseValue); const artifacts = installerArtifacts(records).filter(item => item.target.startsWith('win32-'));
  if (!artifacts.length) throw new Error('No Windows release artifacts.');
  const table = artifacts.map(item => `  '${item.target}' = @{ File='${item.file}'; Folder='${item.folder}'; Sha256='${item.sha256}' }`).join('\n');
  return `# Generated, version-pinned Chat2Local installer. No Node.js/npm/Git prerequisite.
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Use the macOS/Linux installer on this system.' }
if ([Environment]::OSVersion.Version.Major -lt 10) { throw 'This release requires Windows 10 / Server 2016 or newer. No package was downloaded.' }
if ($PSVersionTable.PSVersion.Major -lt 5) { throw 'Windows PowerShell 5.1 or newer is required.' }
$nativeArch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
$arch = switch ($nativeArch.ToUpperInvariant()) { 'AMD64' { 'x64' }; 'ARM64' { 'arm64' }; default { throw 'Unsupported CPU; no fallback will be installed.' } }
$releases = @{
${table}
}
$release = $releases['win32-' + $arch]
if (-not $release) { throw 'This release has no verified package for your system yet.' }
Add-Type -AssemblyName System.Net.Http
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$handler = New-Object System.Net.Http.HttpClientHandler
$handler.AllowAutoRedirect = $false
$client = New-Object System.Net.Http.HttpClient($handler)
$client.Timeout = [TimeSpan]::FromSeconds(240)
$stage = Join-Path ([IO.Path]::GetTempPath()) ('chat2local-install-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($stage) | Out-Null
$archive = Join-Path $stage 'release.zip'
$response = $null
try {
  $uri = [Uri]('${base}/' + $release.File)
  for ($redirects = 0; ; $redirects++) {
    if ($uri.Scheme -ne 'https' -or $redirects -gt 5) { throw 'Unsafe or excessive release redirects.' }
    $response = $client.GetAsync($uri, [Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
    if ([int]$response.StatusCode -ge 300 -and [int]$response.StatusCode -lt 400) {
      if (-not $response.Headers.Location) { throw 'Release redirect has no location.' }
      $next = [Uri]::new($uri, $response.Headers.Location)
      $response.Dispose(); $response = $null; $uri = $next; continue
    }
    $response.EnsureSuccessStatusCode() | Out-Null
    break
  }
  $inputStream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
  $outputStream = [IO.File]::Open($archive, [IO.FileMode]::CreateNew)
  try {
    $buffer = New-Object byte[] 65536; $total = 0L
    while (($count = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
      $total += $count
      if ($total -gt 134217728) { throw 'Release download exceeds the size limit.' }
      $outputStream.Write($buffer, 0, $count)
    }
  } finally { $outputStream.Dispose(); $inputStream.Dispose() }
  if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $release.Sha256) { throw 'SHA-256 mismatch. The package was not extracted or launched.' }
  Expand-Archive -LiteralPath $archive -DestinationPath $stage
  $package = Join-Path $stage $release.Folder
  & (Join-Path $package 'runtime\\node.exe') (Join-Path $package 'scripts\\install-portable.mjs')
  if ($LASTEXITCODE -ne 0) { throw 'The local installer did not complete. Existing configuration was retained.' }
} finally {
  if ($response) { $response.Dispose() }
  $client.Dispose(); $handler.Dispose()
  Remove-Item -LiteralPath $stage -Recurse -Force
}
`;
}
export async function buildInstallers(base, metadataFiles, { partial = false, output = 'dist/installers' } = {}) {
  releaseBase(base); const records = [];
  for (const file of metadataFiles) {
    const record = JSON.parse(await fs.readFile(file, 'utf8'));
    installerArtifacts([record]);
    const archive = path.join(path.dirname(path.resolve(file)), record.file);
    if (createHash('sha256').update(await fs.readFile(archive)).digest('hex') !== record.sha256) throw new Error('Release metadata does not match the actual archive.');
    records.push(record);
  }
  const checked = installerArtifacts(records);
  if (!partial && Object.keys(RELEASE_TARGETS).some(target => !checked.some(item => item.target === target))) throw new Error('A full release requires all six verified target packages. --partial is for an explicitly labelled preview.');
  if (!checked.length) throw new Error('No release artifacts.');
  await fs.mkdir(output, { recursive: true });
  if (checked.some(item => !item.target.startsWith('win32-'))) await fs.writeFile(path.join(output, 'install.sh'), renderPosixInstaller(base, records), { flag: 'wx', mode: 0o755 });
  if (checked.some(item => item.target.startsWith('win32-'))) await fs.writeFile(path.join(output, 'install.ps1'), renderWindowsInstaller(base, records), { flag: 'wx' });
  const manifest = { product: 'Chat2Local', version: VERSION, baseUrl: releaseBase(base), preview: partial, targets: checked, published: false };
  await fs.writeFile(path.join(output, 'release.json'), JSON.stringify(manifest, null, 2), { flag: 'wx' });
  return manifest;
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2); const index = args.indexOf('--base-url');
  const base = index >= 0 ? args.splice(index, 2)[1] : undefined;
  const partialIndex = args.indexOf('--partial'); const partial = partialIndex >= 0;
  if (partial) args.splice(partialIndex, 1);
  if (!base || !args.length) { console.error('Usage: build-installers.mjs --base-url REAL_HTTPS_RELEASE_DIRECTORY [--partial] package.release.json ...'); process.exitCode = 1; }
  else buildInstallers(base, args, { partial }).then(result => console.log(JSON.stringify(result, null, 2))).catch(error => { console.error(error.message); process.exitCode = 1; });
}
