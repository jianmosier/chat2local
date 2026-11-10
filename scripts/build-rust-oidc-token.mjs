import fs from 'node:fs/promises';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { build } from 'esbuild';
import { argumentsFor, validateModule } from './rust-relay-artifact.mjs';
import { projectRoot, hash, sourceFiles, dependencyPaths } from './oidc-token-artifact.mjs';
const args = process.argv.slice(2), parsed = argumentsFor(args);
if (!args.includes('--out-dir')) parsed.output = path.join(projectRoot, '.artifacts/rust-oidc-token');
const { target, output } = parsed;
await fs.mkdir(output, { recursive: true });
if ((await fs.readdir(output)).length) throw Error('OIDC token artifact output must be empty.');
const modules = {};
for (const [crate, prefix, pages] of [['oidc-decision', 'oidc', 256], ['oidc-token', 'oidc-token', 4096]]) {
  const result = spawnSync('cargo', ['rustc', '--locked', '--release', '--target', 'wasm32-unknown-unknown', '--target-dir', target, '-p', `chat2local-${crate}-wasm`, '--', '-C', `link-arg=--max-memory=${pages * 65536}`], { cwd: projectRoot, stdio: 'inherit', shell: false, windowsHide: true });
  if (result.error || result.status !== 0) throw Error('Required ' + crate + ' WASM build failed.');
  const bytes = await fs.readFile(path.join(target, `wasm32-unknown-unknown/release/chat2local_${crate.replaceAll('-', '_')}_wasm.wasm`));
  validateModule(bytes, pages); modules[prefix] = { bytes, file: `${prefix}-core-${hash(bytes)}.wasm` };
}
const bundle = await build({ absWorkingDir: projectRoot, stdin: { resolveDir: projectRoot, sourcefile: 'rust-oidc-token-entry.mjs', contents: `
import decisionModule from './${modules.oidc.file}';
import tokenModule from './${modules['oidc-token'].file}';
import { RustOidcDecisionCore } from './src/relay/rust-oidc.mjs';
import { RustOidcTokenVerifier } from './src/relay/rust-oidc-token.mjs';
import { createRelayWorker } from './src/relay/worker.mjs';
export { Device, Registry } from './src/relay/state.mjs';
export default createRelayWorker({ oidcDecisionFactory: () => new RustOidcDecisionCore(decisionModule), oidcTokenVerifierFactory: () => new RustOidcTokenVerifier(tokenModule) });
` }, bundle: true, write: false, metafile: true, format: 'esm', platform: 'neutral', mainFields: ['module', 'main'], external: ['cloudflare:workers', '*.wasm'] });
const entry = bundle.outputFiles[0].contents, sources = {}, dependencies = {}, artifacts = { 'worker.mjs': hash(entry) };
const inputs = new Set([...await sourceFiles(), ...Object.keys(bundle.metafile.inputs).filter(file => file !== 'rust-oidc-token-entry.mjs' && !file.startsWith('..') && !file.includes('node_modules/'))]);
for (const file of [...inputs].sort()) sources[file] = hash(await fs.readFile(path.join(projectRoot, file)));
for (const [name, file] of Object.entries(dependencyPaths)) dependencies[name] = hash(await fs.readFile(file));
await fs.writeFile(path.join(output, 'worker.mjs'), entry);
for (const { bytes, file } of Object.values(modules)) { await fs.writeFile(path.join(output, file), bytes); artifacts[file] = hash(bytes); }
await fs.writeFile(path.join(output, 'manifest.json'), JSON.stringify({ v: 1, kind: 'oidc-token-verification', profileABI: 1, platform: 'workerd-1.20260918.1', crypto: 'rsa-0.9.10-public-pkcs1v15-sha256', maxWireBytes: 16777216, maxMemoryBytes: 268435456,
  entry: 'worker.mjs', oidcWasm: modules.oidc.file, oidcTokenWasm: modules['oidc-token'].file, artifacts, sources, dependencies }, null, 2) + '\n');
console.log(`Local independent OIDC decision + token entry built: ${output}`);
