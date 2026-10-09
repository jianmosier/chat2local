import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { buildPortable } from './build-portable.mjs';
import { verifyPackage } from './install-portable.mjs';
import { VERSION } from '../src/shared/protocol.mjs';
import { releaseTarget, packageNameFor } from './release-targets.mjs';
const root = fileURLToPath(new URL('..', import.meta.url));
export const RELEASE_TARGETS = ['win32-x64','darwin-arm64','darwin-x64'];
const sha = data => createHash('sha256').update(data).digest('hex');
export const releasePackageName = target => packageNameFor(target, `${releaseTarget(target).prefix}-${VERSION.replaceAll('.', '-')}`);
export async function verifyReleaseInstaller(record, sourceDirectory) {
  if (!RELEASE_TARGETS.includes(record.target) || record.version !== VERSION) throw Error('Installer release identity differs.');
  const source = JSON.parse(await fs.readFile(path.join(sourceDirectory, 'SOURCE-SHA256.json'), 'utf8'));
  const { manifest } = await verifyPackage(record.output, { target: record.target });
  for (const [name, digest] of Object.entries(manifest.files)) {
    if (['runtime/node','runtime/node.exe','runtime/LICENSE.txt'].includes(name)) continue;
    if (source.files[name] !== digest) throw Error('Installer source is not the reviewed public snapshot: ' + name);
  }
  const archive = await fs.readFile(record.archive);
  if (archive.length !== record.bytes || sha(archive) !== record.sha256) throw Error('Installer archive changed.');
  const sidecar = (await fs.readFile(record.archive + '.sha256', 'utf8')).trim().split(/\s+/);
  if (sidecar[0] !== record.sha256 || sidecar[1] !== path.basename(record.archive)) throw Error('Installer checksum file changed.');
  return record;
}
export async function buildReleaseInstallers(sourceDirectory) {
  const records = [];
  for (const target of RELEASE_TARGETS) {
    const name = releasePackageName(target);
    const archive = path.join(root, 'dist', name + (target.startsWith('win32') ? '.zip' : '.tar.gz'));
    let record;
    try {
      const metadata = JSON.parse(await fs.readFile(archive + '.release.json', 'utf8'));
      record = { ...metadata, output: path.join(root, 'dist', name), archive };
    } catch (error) { if (error.code !== 'ENOENT') throw error; record = await buildPortable(name, target); }
    records.push(await verifyReleaseInstaller(record, sourceDirectory));
  }
  return records;
}
export function releaseAssetFiles(report) {
  return [report.archive, report.archive + '.sha256', ...(report.installers || []).flatMap(r => [r.archive, r.archive + '.sha256'])];
}
