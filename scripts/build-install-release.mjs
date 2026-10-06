import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { renderPosixInstaller, installerArtifacts } from './build-installers.mjs';
import { verifyPackage } from './install-portable.mjs';
import { VERSION } from '../src/shared/protocol.mjs';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
export const CHUNK_BYTES = 8 * 1024 * 1024;
function originOnly(value) {
  const u = new URL(value);
  if (u.protocol !== 'https:' || u.username || u.password || u.search || u.hash || u.pathname !== '/' || !/^[a-zA-Z0-9.-]+$/.test(u.hostname)) throw new Error('Use the exact private instance HTTPS origin.');
  return u.origin;
}
export function renderInstanceInstaller(origin, records) {
  origin = originOnly(origin); installerArtifacts(records);
  for (const record of records) {
    if (!['darwin-arm64','darwin-x64'].includes(record.target) || !Array.isArray(record.parts) || !record.parts.length || record.parts.length > 16) throw new Error('Invalid Mac installer target.');
    for (const part of record.parts) if (!new RegExp('^/releases/0\\.1\\.0-alpha\\.[0-9]+/' + record.target + '/[a-f0-9]{64}\\.part[0-9]{2}$').test(part.path) || !/^[a-f0-9]{64}$/.test(part.sha256) || !Number.isSafeInteger(part.bytes) || part.bytes < 1 || part.bytes > CHUNK_BYTES) throw new Error('Unsafe release part.');
  }
  let script = renderPosixInstaller(origin + '/releases', records);
  const download = script.split('\n').filter(line => line.startsWith('curl --fail'));
  if (download.length !== 1) throw new Error('Installer template changed; refusing an unreviewed substitution.');
  const cases = records.map(record => `  ${record.target})\n${record.parts.map(part => `    part '${origin}${part.path}' '${part.sha256}'`).join('\n')}\n    ;;`).join('\n');
  script = script.replace(download[0], `# Bounded static assets; every chunk and the complete archive are verified.
part_index=0
part() {
  part_index=$((part_index + 1))
  echo "[chat2local] Downloading package chunk $part_index..."
  curl --fail --silent --show-error --proto '=https' --connect-timeout 20 --max-time 180 --max-filesize ${CHUNK_BYTES} "$1" --output "$stage/part"
  if [ "$checksum" = shasum ]; then value=$(shasum -a 256 "$stage/part"); else value=$(sha256sum "$stage/part"); fi
  if [ "\${value%% *}" != "$2" ]; then echo 'Release chunk verification failed; nothing was installed.' >&2; exit 1; fi
  cat "$stage/part" >> "$archive"
}
: > "$archive"
case "$platform-$arch" in
${cases}
  *) echo 'No matching release.' >&2; exit 1 ;;
esac`);
  const original = '"$stage/$folder/runtime/node" "$stage/$folder/scripts/install-portable.mjs"';
  if (!script.includes(original)) throw new Error('Installer launch template changed.');
  return script.replace(original, `"$stage/$folder/runtime/node" "$stage/$folder/scripts/install-from-instance.mjs" --install '${origin}'`);
}

/** Dedicated PUBLIC allowlist, never point assets.directory at the repository or
 * ordinary dist (which may contain private configuration). No invitations,
 * operator credentials, signing secrets or local settings enter these assets.
 */
export async function buildInstallRelease(origin, metadataFiles, output) {
  origin = originOnly(origin);
  try { await fs.lstat(output); throw new Error('Public release directory already exists; not overwritten.'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  const records = [];
  for (const file of metadataFiles) {
    const record = JSON.parse(await fs.readFile(file, 'utf8'));
    installerArtifacts([record]);
    if (!['darwin-arm64','darwin-x64'].includes(record.target)) throw new Error('This release entry currently supports Mac only.');
    const dir = path.dirname(path.resolve(file)), archive = path.join(dir, record.file);
    const bytes = await fs.readFile(archive);
    if (sha(bytes) !== record.sha256 || bytes.length !== record.bytes) throw new Error('Archive differs from its release metadata.');
    await verifyPackage(path.join(dir, record.packageName), { target: record.target });
    records.push({ ...record, bytesBuffer: bytes, parts: [] });
  }
  installerArtifacts(records);
  if (records.length !== 2 || !records.some(r => r.target === 'darwin-arm64') || !records.some(r => r.target === 'darwin-x64')) throw new Error('Publish both actual Mac architectures, not an emulation fallback.');
  await fs.mkdir(output, { recursive: true });
  for (const record of records) {
    for (let offset = 0, index = 0; offset < record.bytesBuffer.length; offset += CHUNK_BYTES, index++) {
      const bytes = record.bytesBuffer.subarray(offset, offset + CHUNK_BYTES);
      const relative = `releases/${VERSION}/${record.target}/${record.sha256}.part${String(index).padStart(2, '0')}`;
      const file = path.join(output, relative); await fs.mkdir(path.dirname(file), { recursive: true }); await fs.writeFile(file, bytes, { flag: 'wx' });
      record.parts.push({ path: '/' + relative, sha256: sha(bytes), bytes: bytes.length });
    }
    delete record.bytesBuffer;
  }
  await fs.writeFile(path.join(output, 'install.sh'), renderInstanceInstaller(origin, records), { flag: 'wx', mode: 0o755 });
  // Non-public release evidence is a sibling, not an extra uploaded asset.
  await fs.writeFile(output + '.json', JSON.stringify({ version: VERSION, origin, targets: records }, null, 2), { flag: 'wx' });
  return { output, version: VERSION, targets: records.map(r => ({ target: r.target, bytes: r.bytes, sha256: r.sha256, chunks: r.parts.length })), secretsIncluded: false, published: false };
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [origin, output, ...files] = process.argv.slice(2);
  if (!origin || !output || !files.length) { console.error('Usage: build-install-release.mjs HTTPS_ORIGIN NEW_OUTPUT_DIRECTORY MAC_RELEASE_METADATA...'); process.exitCode = 1; }
  else buildInstallRelease(origin, files, output).then(r => console.log(JSON.stringify(r, null, 2))).catch(e => { console.error(e.message); process.exitCode = 1; });
}
