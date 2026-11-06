import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { powershell } from '../src/agent/store.mjs';
import { VERSION } from '../src/shared/protocol.mjs';
import { NODE_VERSION, releaseTarget, packageNameFor } from './release-targets.mjs';
import { packageEntries, writeTarGz } from './archive.mjs';
import { readNativeAgentArtifact } from './native-agent-artifact.mjs';
export { NODE_VERSION } from './release-targets.mjs';

// Packaging only: no deployment, startup registration, enrollment, or credential access.
const root = fileURLToPath(new URL('..', import.meta.url));
const distribution = `https://nodejs.org/dist/${NODE_VERSION}/`;
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const run = promisify(execFile);
async function download(url, maximum) {
  const response = await fetch(url, { redirect: 'error', signal: AbortSignal.timeout(180000) });
  if (!response.ok) throw new Error(`Download failed (${response.status}): ${url}`);
  const parts = []; let size = 0;
  for await (const part of response.body) { size += part.length; if (size > maximum) throw new Error('Download exceeds its size limit.'); parts.push(part); }
  return Buffer.concat(parts);
}
async function absent(file) {
  try { await fs.lstat(file); throw new Error(`Existing build is retained: ${path.basename(file)}. Choose another package name.`); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
}
export async function buildPortable(name, targetKey = `${process.platform}-${process.arch}`, { nativeAgent } = {}) {
  const target = releaseTarget(targetKey); const packageName = packageNameFor(targetKey, name);
  const native = targetKey === 'win32-x64';
  if (native && !nativeAgent) throw Error('Windows x64 release requires --native-agent with a verified formal native package; no Node Agent fallback is allowed.');
  if (nativeAgent && !native) throw Error('A formal native Agent can only be packaged for Windows x64.');
  const nativeManifest = native ? await readNativeAgentArtifact(path.resolve(nativeAgent)) : null;
  const output = path.join(root, 'dist', packageName);
  const archiveOutput = `${output}.${target.extension}`;
  await absent(output); await absent(archiveOutput);
  const cache = path.join(root, '.artifacts', 'runtime-cache');
  await fs.mkdir(cache, { recursive: true });
  const checksums = (await download(`${distribution}SHASUMS256.txt`, 100000)).toString('utf8');
  const record = checksums.split(/\r?\n/).find(line => line.trim().split(/\s+/)[1] === target.archiveName);
  const expected = record?.trim().split(/\s+/)[0];
  if (!/^[a-f0-9]{64}$/.test(expected || '')) throw new Error('Official checksum for this target was not found; no architecture fallback is allowed.');
  const archive = path.join(cache, target.archiveName);
  let bytes;
  try { bytes = await fs.readFile(archive); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  if (!bytes) { console.log(`Downloading official Node ${NODE_VERSION} for ${targetKey}...`); bytes = await download(distribution + target.archiveName, 100 * 1024 * 1024); }
  if (digest(bytes) !== expected) throw new Error('Runtime SHA-256 mismatch. No executable was unpacked or started.');
  await fs.writeFile(archive, bytes);
  console.log('Official HTTPS checksum matched; not a GPG signature audit or application signing.');
  const staging = await fs.mkdtemp(path.join(cache, 'extract-'));
  try {
    if (target.extension === 'zip' && process.platform === 'win32') {
      await powershell("$ErrorActionPreference='Stop'; $c=[Console]::In.ReadToEnd()|ConvertFrom-Json; Expand-Archive -LiteralPath $c.archive -DestinationPath $c.destination", JSON.stringify({ archive, destination: staging }), 120000);
    } else if (target.extension === 'zip') {
      await run('unzip', ['-q', archive, `${target.runtimeFolder}/node.exe`, `${target.runtimeFolder}/LICENSE`, '-d', staging], { timeout: 120000 });
    } else {
      // Only the verified executable and license are unpacked; not npm or archive links.
      const tar = process.platform === 'win32' ? path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'tar.exe') : 'tar';
      await run(tar, ['-xzf', archive, '-C', staging, `${target.runtimeFolder}/${target.executable}`, `${target.runtimeFolder}/LICENSE`], { timeout: 120000 });
    }
    const runtime = path.join(staging, target.runtimeFolder);
    const executable = await fs.readFile(path.join(runtime, target.executable));
    const runtimeLicense = await fs.readFile(path.join(runtime, 'LICENSE'));
    const sourceFiles = [
      target.nodePlatform === 'win' ? 'start-chat2local.cmd' : 'start-chat2local.sh',
      'scripts/launch.mjs', 'scripts/install-portable.mjs', 'scripts/native-package.mjs', 'scripts/native-startup.mjs', 'scripts/upgrade-session.mjs', 'scripts/join-instance.mjs', 'scripts/install-from-instance.mjs', 'LICENSE',
      ...await packageEntries(path.join(root, 'src', 'agent'), 'src/agent/'),
      ...await packageEntries(path.join(root, 'src', 'shared'), 'src/shared/'),
    ];
    // Explicit allowlist: never package deployment configs, secrets, user state or node_modules.
    await fs.mkdir(output, { recursive: true });
    for (const relative of sourceFiles) {
      const destination = path.join(output, relative); await fs.mkdir(path.dirname(destination), { recursive: true });
      await fs.copyFile(path.join(root, relative), destination);
    }
    await fs.mkdir(path.join(output, 'runtime'));
    const executablePath = path.join(output, 'runtime', target.nodePlatform === 'win' ? 'node.exe' : 'node');
    await fs.writeFile(executablePath, executable, { mode: 0o755 });
    await fs.writeFile(path.join(output, 'runtime', 'LICENSE.txt'), runtimeLicense);
    if (target.nodePlatform !== 'win') await fs.chmod(path.join(output, 'start-chat2local.sh'), 0o755);
    await fs.copyFile(path.join(root, 'README.md'), path.join(output, 'README.md'));
    if (native) {
      await fs.mkdir(path.join(output, 'native'));
      for (const file of ['chat2local-native-agent.exe', 'chat2local-terminal-runner.exe', 'manifest.json', ...(nativeManifest.noticesSha256 ? ['THIRD-PARTY-NOTICES.txt'] : []), ...Object.keys(nativeManifest.runtimeDependencies || {})]) {
        if (!['chat2local-native-agent.exe', 'chat2local-terminal-runner.exe', 'manifest.json', 'vcruntime140.dll', 'THIRD-PARTY-NOTICES.txt'].includes(file)) throw Error('Unapproved native runtime dependency.');
        await fs.copyFile(path.join(path.dirname(path.resolve(nativeAgent)), file), path.join(output, 'native', file));
      }
      // Recheck the provenance after copying, then verify the independent payload.
      await readNativeAgentArtifact(path.resolve(nativeAgent));
      const { verifyNativePackage } = await import('./native-package.mjs');
      await verifyNativePackage(output, { target: targetKey });
    }
    const manifest = { product: 'Chat2Local', version: VERSION, platform: targetKey, runtimeKind: native ? 'rust-native' : 'node-legacy', runtime: NODE_VERSION, runtimeSource: distribution + target.archiveName, runtimeArchiveSha256: expected, files: {} };
    for (const relative of await packageEntries(output)) manifest.files[relative] = digest(await fs.readFile(path.join(output, relative)));
    await fs.writeFile(path.join(output, 'BUILD-MANIFEST.json'), JSON.stringify(manifest, null, 2));
    if (target.extension === 'zip') {
      if (process.platform === 'win32') await powershell("$ErrorActionPreference='Stop'; $c=[Console]::In.ReadToEnd()|ConvertFrom-Json; Compress-Archive -LiteralPath $c.source -DestinationPath $c.destination -CompressionLevel Optimal", JSON.stringify({ source: output, destination: archiveOutput }), 120000);
      else await run('zip', ['-q', '-r', archiveOutput, packageName], { cwd: path.dirname(output), timeout: 120000 });
    } else await writeTarGz(output, archiveOutput);
    const sha256 = digest(await fs.readFile(archiveOutput));
    const result = { output, archive: archiveOutput, zip: target.extension === 'zip' ? archiveOutput : undefined, target: targetKey, packageName, version: VERSION, bytes: (await fs.stat(archiveOutput)).size, sha256, runtime: NODE_VERSION, runtimeKind: manifest.runtimeKind, nativeRuntimeTested: false };
    await fs.writeFile(`${archiveOutput}.sha256`, `${sha256}  ${path.basename(archiveOutput)}\n`);
    await fs.writeFile(`${archiveOutput}.release.json`, JSON.stringify({ target: targetKey, packageName, file: path.basename(archiveOutput), version: VERSION, bytes: result.bytes, sha256, runtime: NODE_VERSION, runtimeKind: manifest.runtimeKind }, null, 2));
    console.log(JSON.stringify(result, null, 2)); return result;
  } finally { await fs.rm(staging, { recursive: true, force: true }); }
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2); let target = `${process.platform}-${process.arch}`; let name; let nativeAgent;
  try {
    for (let i = 0; i < args.length; i++) {
      if (args[i] === '--target' && args[i + 1]) target = args[++i];
      else if (args[i] === '--native-agent' && args[i + 1]) nativeAgent = args[++i];
      else if (!name && !args[i].startsWith('--')) name = args[i];
      else throw new Error('Usage: build-portable.mjs [package-name] [--target win32-x64|win32-arm64|darwin-x64|darwin-arm64|linux-x64|linux-arm64]');
    }
    buildPortable(name, target, { nativeAgent }).catch(error => { console.error(error.message); process.exitCode = 1; });
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
