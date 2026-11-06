import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { powershell } from '../src/agent/store.mjs';
import { VERSION } from '../src/shared/protocol.mjs';
import { SOURCE_REPOSITORY } from '../src/shared/distribution.mjs';
import { verifyPackage } from './install-portable.mjs';

const extractRelease = String.raw`
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem
$c=[Console]::In.ReadToEnd()|ConvertFrom-Json
$z=[IO.Compression.ZipFile]::OpenRead($c.archive)
try {
  $maxFile=128MB; $maxTotal=256MB; [long]$declared=0
  if($z.Entries.Count -gt 1001){throw 'Too many release files'}
  foreach($e in $z.Entries){
    $n=$e.FullName.Replace('\','/')
    if(-not $n.StartsWith($c.folder+'/') -or $n -match '(^|/)(\.\.?)(/|$)|[:\x00-\x1f]' -or (($e.ExternalAttributes -shr 16) -band 61440) -eq 40960){throw 'Unsafe release entry'}
    if($e.Length -gt $maxFile -or $e.Length -gt $maxTotal-$declared){throw 'Release expanded size exceeds limit'}
    if($n.EndsWith('/') -and $e.Length -ne 0){throw 'Invalid release directory length'}
    $declared+=$e.Length
  }
  $stageRoot=[IO.Path]::GetFullPath($c.stage)+[IO.Path]::DirectorySeparatorChar
  $buffer=New-Object byte[] 65536; [long]$actual=0
  foreach($e in $z.Entries){
    $n=$e.FullName.Replace('\','/')
    $target=[IO.Path]::GetFullPath([IO.Path]::Combine($c.stage,$n))
    if(-not $target.StartsWith($stageRoot,[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe release target'}
    if($n.EndsWith('/')){[IO.Directory]::CreateDirectory($target)|Out-Null;continue}
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))|Out-Null
    $memberStream=$null; $fileStream=$null; [long]$written=0
    try {
      $memberStream=$e.Open()
      $fileStream=[IO.File]::Open($target,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
      while(($count=$memberStream.Read($buffer,0,$buffer.Length)) -gt 0){
        if($count -gt $e.Length-$written -or $count -gt $maxFile-$written -or $count -gt $maxTotal-$actual){throw 'Release entry byte length mismatch or expansion limit exceeded'}
        $fileStream.Write($buffer,0,$count); $written+=$count; $actual+=$count
      }
      if($written -ne $e.Length){throw 'Release entry byte length mismatch'}
    } finally {if($fileStream){$fileStream.Dispose()};if($memberStream){$memberStream.Dispose()}}
  }
} finally {$z.Dispose()}
`;

export function windowsReleaseIdentity(target = `${process.platform}-${process.arch}`) {
  if (target !== 'win32-x64') throw Error('This native release supports Windows x64 only; no architecture fallback is allowed.');
  const folder = 'Chat2Local-Windows-x64-' + VERSION.replaceAll('.', '-');
  return { folder, file: folder + '.zip', base: `https://github.com/${SOURCE_REPOSITORY}/releases/download/v${VERSION}` };
}
export function releaseChecksum(text, file) {
  const match = /^([a-f0-9]{64})  ([A-Za-z0-9.-]+)\s*$/.exec(text);
  if (!match || match[2] !== file) throw Error('Release checksum identity mismatch.');
  return match[1];
}
export async function downloadWindowsRelease(project) {
  const release = windowsReleaseIdentity(), output = path.join(project, 'dist');
  await fs.mkdir(output, { recursive: true });
  const destination = path.join(output, release.folder);
  // Always fetch the current pinned release digest before reusing a local copy.
  async function download(url, maximum) {
    for (let count = 0; count <= 5; count++) {
      const parsed = new URL(url);
      if (parsed.protocol !== 'https:' || parsed.username || parsed.password || !['github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com'].includes(parsed.hostname)) throw Error('Unsafe release download URL.');
      const response = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(180000) });
      if (response.status >= 300 && response.status < 400) {
        const next = response.headers.get('location'); await response.body?.cancel();
        if (!next) throw Error('Missing release redirect.'); url = new URL(next, url).href; continue;
      }
      if (!response.ok) throw Error('Pinned release download failed (' + response.status + ').');
      const parts = []; let size = 0;
      for await (const part of response.body) { size += part.length; if (size > maximum) throw Error('Release download exceeds limit.'); parts.push(part); }
      return Buffer.concat(parts);
    }
    throw Error('Too many release redirects.');
  }
  const expected = releaseChecksum((await download(`${release.base}/${release.file}.sha256`, 1024)).toString('utf8'), release.file);
  const bytes = await download(`${release.base}/${release.file}`, 128 * 1024 * 1024);
  if (createHash('sha256').update(bytes).digest('hex') !== expected) throw Error('Release archive checksum mismatch; nothing was extracted.');
  const stage = await fs.mkdtemp(path.join(output, '.native-download-'));
  try {
    const archive = path.join(stage, 'release.zip'); await fs.writeFile(archive, bytes, { flag: 'wx' });
    // Refuse oversized declarations before writing, then bound actual streamed
    // bytes as well: malformed ZIP headers must not turn staging into a bomb.
    await powershell(extractRelease, JSON.stringify({ archive, folder: release.folder, stage }), 120000);
    const unpacked = path.join(stage, release.folder), fresh = await verifyPackage(unpacked, { target: 'win32-x64' });
    if (fresh.manifest.runtimeKind !== 'rust-native') throw Error('Pinned Windows release is not native.');
    try { await fs.lstat(destination); }
    catch (error) { if (error.code !== 'ENOENT') throw error; await fs.rename(unpacked, destination); return destination; }
    await verifyPackage(destination, { expectedManifestHash: fresh.manifestHash, target: 'win32-x64' });
    return destination;
  } finally { await fs.rm(stage, { recursive: true, force: true }); }
}
