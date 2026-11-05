import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { optionsFor, buildEnvironment, run } from './build-rust-transport.mjs';
import { root, sourceFiles, hash, readNativeAgentArtifact } from './native-agent-artifact.mjs';
async function notices(env, options) {
  const license = process.env.CHAT2LOCAL_OPENSSL_LICENSE || path.join(path.dirname(options.openssl), 'source', 'openssl-3.5.8', 'LICENSE.txt');
  const openssl = await fs.readFile(license, 'utf8');
  if (!openssl.includes('Apache License') || !openssl.includes('Version 2.0')) throw Error('Verified OpenSSL source license is required.');
  let text = 'Chat2Local native Windows distribution\n\nOpenSSL 3.5.8\nhttps://www.openssl.org/\n' + openssl + '\n\n';
  text += 'Microsoft Visual C++ runtime (vcruntime140.dll)\nCopyright Microsoft Corporation. All rights reserved.\nRedistributable runtime, supplied unchanged beside the application.\nhttps://learn.microsoft.com/visualstudio/releases/2022/redistribution\n\n';
  const tree = await run('cargo', ['tree', '--locked', '--target', 'x86_64-pc-windows-msvc', '-p', 'chat2local-native-agent', '-p', 'chat2local-terminal-runner', '--no-default-features', '--prefix', 'none', '--format', '{p}|{l}|{r}'], env, { capture: true });
  const registry = path.join(env.CARGO_HOME || path.join(os.homedir(), '.cargo'), 'registry', 'src');
  const registries = await fs.readdir(registry), seen = new Set();
  for (const line of tree.split(/\r?\n/)) {
    const match = /^([\w-]+) v([\w.+-]+)(.*?)\|([^|]*)\|(.*)$/.exec(line);
    if (!match || match[3].includes('(')) continue;
    const [, name, version, , spdx, repository] = match, key = name + '-' + version;
    if (seen.has(key)) continue;
    seen.add(key);
    let directory;
    for (const registryName of registries) {
      const candidate = path.join(registry, registryName, key);
      if (await fs.stat(candidate).then(s => s.isDirectory(), () => false)) { directory = candidate; break; }
    }
    if (!directory) throw Error('Native dependency license source missing: ' + key);
    const names = (await fs.readdir(directory)).filter(name => /^(LICENSE|LICENCE|COPYING|NOTICE|UNLICENSE)([.\-_]|$)/i.test(name));
    let count = 0;
    text += '\n===== ' + name + ' ' + version + ' (' + spdx + ') =====\n' + repository + '\n';
    for (const file of names.sort()) {
      const location = path.join(directory, file), stat = await fs.stat(location);
      if (!stat.isFile() || stat.size > 1024 * 1024) continue;
      text += '\n' + file + '\n' + await fs.readFile(location, 'utf8') + '\n'; count++;
    }
    if (!count) throw Error('Native dependency license notice missing: ' + key);
  }
  if (seen.size < 10) throw Error('Native dependency license inventory incomplete.');
  return text;
}
export async function buildNativeAgent(options) {
  if (process.platform !== 'win32' || process.arch !== 'x64') throw Error('Formal native Agent currently requires Windows x64.');
  const env = await buildEnvironment(options), sources = {};
  if (env.RUSTFLAGS || env.CARGO_ENCODED_RUSTFLAGS) throw Error('Native release requires its reviewed path-remapping flags without inherited Rust overrides.');
  env.CARGO_ENCODED_RUSTFLAGS = [`--remap-path-prefix=${root}=chat2local`, `--remap-path-prefix=${os.homedir()}=user`].join('\x1f');
  for (const file of await sourceFiles()) sources[file] = hash(await fs.readFile(path.join(root, file)));
  // This selected graph must never include the fixture crate or workspace feature unification.
  const features = await run('cargo', ['tree', '--locked', '-p', 'chat2local-native-agent', '-p', 'chat2local-terminal-runner', '--no-default-features', '-e', 'features'], env, { capture: true });
  if (/feature "fixture"/.test(features)) throw Error('Formal build graph includes fixture features.');
  await run('cargo', ['build', '--release', '--locked', '-p', 'chat2local-native-agent', '-p', 'chat2local-terminal-runner', '--no-default-features', '--target-dir', options.target], env);
  for (const [file, digest] of Object.entries(sources)) if (hash(await fs.readFile(path.join(root, file))) !== digest) throw Error('Formal native source changed during build.');
  await fs.mkdir(options.output, { recursive: true });
  const name = 'chat2local-native-agent.exe', helperName = 'chat2local-terminal-runner.exe';
  for (const file of [name, helperName]) await fs.copyFile(path.join(options.target, 'release', file), path.join(options.output, file));
  const crt = process.env.CHAT2LOCAL_MSVC_RUNTIME_DLL || (env.VCToolsRedistDir && path.join(env.VCToolsRedistDir, 'x64', 'Microsoft.VC143.CRT', 'vcruntime140.dll'));
  if (!crt || !(await fs.stat(crt)).isFile()) throw Error('A verified Microsoft VC runtime redistributable DLL is required.');
  await fs.copyFile(crt, path.join(options.output, 'vcruntime140.dll'));
  const notice = await notices(env, options);
  await fs.writeFile(path.join(options.output, 'THIRD-PARTY-NOTICES.txt'), notice);
  const executable = path.join(options.output, name), runtime = JSON.parse(await run(executable, ['--version'], env, { capture: true }));
  if (runtime.name !== 'chat2local-native-agent' || runtime.fixtureOnly !== false || runtime.fullAgent !== false || runtime.upgradeReady !== false || !runtime.openssl.startsWith('OpenSSL 3.5.8 ')) throw Error('Formal native linked runtime mismatch.');
  for (const file of [name, helperName, 'vcruntime140.dll']) {
    const bytes = await fs.readFile(path.join(options.output, file));
    for (const prefix of [root, os.homedir(), path.dirname(options.openssl)]) {
      for (const spelling of [prefix, prefix.replaceAll('\\', '/')]) {
        if (bytes.includes(Buffer.from(spelling)) || bytes.includes(Buffer.from(spelling, 'utf16le'))) throw Error('Private build path remains in native distribution: ' + file);
      }
    }
  }
  await fs.writeFile(path.join(options.output, 'manifest.json'), JSON.stringify({ v: 1, buildProfile: 'release', runtimeDependencies: { 'vcruntime140.dll': hash(await fs.readFile(path.join(options.output, 'vcruntime140.dll'))) }, noticesSha256: hash(notice), fixtureOnly: false, fullAgent: false, upgradeReady: false, platform: process.platform, architecture: process.arch, features: [], featureGraphSha256: hash(features), executable: name, sha256: hash(await fs.readFile(executable)), terminalRunner: { fixtureOnly: false, executable: helperName, sha256: hash(await fs.readFile(path.join(options.output, helperName))) }, sources, opensslVersion: '3.5.8', opensslManifestSha256: options.manifestHash, capabilities: runtime }, null, 2) + '\n');
  await readNativeAgentArtifact(executable); return { executable };
}
if (import.meta.main) { const options = optionsFor(process.argv.slice(2)); if (!process.argv.includes('--out-dir')) options.output = path.join(root, '.artifacts/native-agent'); console.log(await buildNativeAgent(options)); }
