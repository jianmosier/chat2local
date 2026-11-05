import fs from 'node:fs/promises';
import path from 'node:path';
import { optionsFor, buildEnvironment, run } from './build-rust-transport.mjs';
import { root, sourceFiles, hash, readNativeAgentArtifact } from './native-agent-artifact.mjs';
export async function buildNativeAgent(options) {
  if (process.platform !== 'win32') throw Error('Formal native Agent currently requires Windows.');
  const env = await buildEnvironment(options), sources = {};
  for (const file of await sourceFiles()) sources[file] = hash(await fs.readFile(path.join(root, file)));
  // This selected graph must never include the fixture crate or workspace feature unification.
  const features = await run('cargo', ['tree', '--locked', '-p', 'chat2local-native-agent', '-p', 'chat2local-terminal-runner', '--no-default-features', '-e', 'features'], env, { capture: true });
  if (/feature "fixture"/.test(features)) throw Error('Formal build graph includes fixture features.');
  await run('cargo', ['build', '--locked', '-p', 'chat2local-native-agent', '-p', 'chat2local-terminal-runner', '--no-default-features', '--target-dir', options.target], env);
  for (const [file, digest] of Object.entries(sources)) if (hash(await fs.readFile(path.join(root, file))) !== digest) throw Error('Formal native source changed during build.');
  await fs.mkdir(options.output, { recursive: true });
  const name = 'chat2local-native-agent.exe', helperName = 'chat2local-terminal-runner.exe';
  for (const file of [name, helperName]) await fs.copyFile(path.join(options.target, 'debug', file), path.join(options.output, file));
  const executable = path.join(options.output, name), runtime = JSON.parse(await run(executable, ['--version'], env, { capture: true }));
  if (runtime.name !== 'chat2local-native-agent' || runtime.fixtureOnly !== false || runtime.fullAgent !== false || runtime.upgradeReady !== false || !runtime.openssl.startsWith('OpenSSL 3.5.8 ')) throw Error('Formal native linked runtime mismatch.');
  await fs.writeFile(path.join(options.output, 'manifest.json'), JSON.stringify({ v: 1, fixtureOnly: false, fullAgent: false, upgradeReady: false, platform: process.platform, architecture: process.arch, features: [], featureGraphSha256: hash(features), executable: name, sha256: hash(await fs.readFile(executable)), terminalRunner: { fixtureOnly: false, executable: helperName, sha256: hash(await fs.readFile(path.join(options.output, helperName))) }, sources, opensslVersion: '3.5.8', opensslManifestSha256: options.manifestHash, capabilities: runtime }, null, 2) + '\n');
  await readNativeAgentArtifact(executable); return { executable };
}
if (import.meta.main) { const options = optionsFor(process.argv.slice(2)); if (!process.argv.includes('--out-dir')) options.output = path.join(root, '.artifacts/native-agent'); console.log(await buildNativeAgent(options)); }
