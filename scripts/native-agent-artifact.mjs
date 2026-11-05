import fs from 'node:fs/promises';
import path from 'node:path';
import { root, hash, sourceFiles } from './controller-artifact.mjs';
export { root, hash, sourceFiles };
export async function readNativeAgentArtifact(executable, { sourceRoot = root } = {}) {
  const manifest = JSON.parse(await fs.readFile(path.join(path.dirname(executable), 'manifest.json'), 'utf8'));
  const files = await sourceFiles(sourceRoot);
  if (manifest.buildProfile !== 'release' || !/^[a-f0-9]{64}$/.test(manifest.runtimeDependencies?.['vcruntime140.dll'] || '') || Object.keys(manifest.runtimeDependencies).length !== 1 || hash(await fs.readFile(path.join(path.dirname(executable), 'vcruntime140.dll'))) !== manifest.runtimeDependencies['vcruntime140.dll'] || hash(await fs.readFile(path.join(path.dirname(executable), 'THIRD-PARTY-NOTICES.txt'))) !== manifest.noticesSha256) throw Error('Formal native release dependency or profile mismatch.');
  if (manifest.v !== 1 || manifest.fixtureOnly !== false || manifest.fullAgent !== false || manifest.upgradeReady !== false || manifest.executable !== path.basename(executable) || manifest.platform !== process.platform || manifest.architecture !== process.arch || manifest.opensslVersion !== '3.5.8' || manifest.capabilities?.name !== 'chat2local-native-agent' || JSON.stringify(manifest.features) !== '[]' || Object.keys(manifest.sources ?? {}).sort().join('\n') !== files.join('\n')) throw Error('Formal native manifest mismatch.');
  for (const file of files) if (hash(await fs.readFile(path.join(sourceRoot, file))) !== manifest.sources[file]) throw Error('Stale formal native source: ' + file);
  const helper = manifest.terminalRunner;
  if (hash(await fs.readFile(executable)) !== manifest.sha256 || helper?.fixtureOnly !== false || helper?.executable !== 'chat2local-terminal-runner.exe' || hash(await fs.readFile(path.join(path.dirname(executable), helper.executable))) !== helper.sha256) throw Error('Formal native package hash mismatch.');
  return manifest;
}
