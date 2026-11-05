import fs from 'node:fs/promises';
import path from 'node:path';
import { optionsFor, buildEnvironment, run } from './build-rust-transport.mjs';
import { root, sourceFiles, hash, readControllerArtifact } from './controller-artifact.mjs';
export async function buildController(options) {
  const env = await buildEnvironment(options), sources = {};
  for (const file of await sourceFiles()) sources[file] = hash(await fs.readFile(path.join(root, file)));
  await run('cargo', ['build', '--locked', '-p', 'chat2local-agent-controller-fixture', '-p', 'chat2local-terminal-runner', '--features', 'chat2local-terminal-runner/fixture', '--target-dir', options.target], env);
  for (const [file, digest] of Object.entries(sources)) if (hash(await fs.readFile(path.join(root, file))) !== digest) throw Error('Controller source changed during build.');
  await fs.mkdir(options.output, { recursive: true });
  const name = 'chat2local-agent-controller-fixture' + (process.platform === 'win32' ? '.exe' : ''), executable = path.join(options.output, name);
  await fs.copyFile(path.join(options.target, 'debug', name), executable);
  const helperName = 'chat2local-terminal-runner' + (process.platform === 'win32' ? '.exe' : '');
  await fs.copyFile(path.join(options.target, 'debug', helperName), path.join(options.output, helperName));
  const terminalRunner = { fixtureOnly: true, executable: helperName, sha256: hash(await fs.readFile(path.join(options.output, helperName))) };
  const runtime = JSON.parse(await run(executable, ['--version'], env, { capture: true }));
  if (runtime.name !== 'chat2local-native-controller-fixture' || runtime.fixtureOnly !== true || runtime.fullAgent !== false || !runtime.openssl.startsWith('OpenSSL 3.5.8 ')) throw Error('Native controller linked runtime mismatch.');
  await fs.writeFile(path.join(options.output, 'manifest.json'), JSON.stringify({ v: 1, fixtureOnly: true, fullAgent: false, platform: process.platform, architecture: process.arch, executable: name, sha256: hash(await fs.readFile(executable)), terminalRunner, sources, opensslVersion: '3.5.8', opensslManifestSha256: options.manifestHash, capabilities: runtime }, null, 2) + '\n');
  await readControllerArtifact(executable); return { executable };
}
if (import.meta.main) { const options = optionsFor(process.argv.slice(2)); if (!process.argv.includes('--out-dir')) options.output = path.join(root, '.artifacts/rust-controller'); console.log(await buildController(options)); }
