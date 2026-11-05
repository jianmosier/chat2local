import fs from 'node:fs/promises';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { build } from 'esbuild';
import { argumentsFor, validateModule } from './rust-relay-artifact.mjs';
import { projectRoot, hash, sourceFiles, dependencyPaths } from './oidc-artifact.mjs';
const args = process.argv.slice(2), parsed = argumentsFor(args);
if (!args.includes('--out-dir')) parsed.output = path.join(projectRoot, '.artifacts/rust-oidc');
const { target, output } = parsed;
await fs.mkdir(output, { recursive: true });
if ((await fs.readdir(output)).length) throw Error('OIDC artifact output must be empty.');
const result = spawnSync('cargo', ['rustc', '--locked', '--release', '--target', 'wasm32-unknown-unknown', '--target-dir', target,
  '-p', 'chat2local-oidc-decision-wasm', '--', '-C', 'link-arg=--max-memory=16777216'], { cwd: projectRoot, stdio: 'inherit', shell: false, windowsHide: true });
if (result.error || result.status !== 0) throw Error('Required OIDC WASM build failed.');
const bytes = await fs.readFile(path.join(target, 'wasm32-unknown-unknown/release/chat2local_oidc_decision_wasm.wasm'));
validateModule(bytes);
const wasm = `oidc-core-${hash(bytes)}.wasm`;
// Independent candidate: original JS OAuth, Device, Registry and token verifier.
const bundle = await build({ absWorkingDir: projectRoot, stdin: { resolveDir: projectRoot, sourcefile: 'rust-oidc-entry.mjs', contents: `
import oidcModule from './${wasm}';
import { RustOidcDecisionCore } from './src/relay/rust-oidc.mjs';
import { createRelayWorker } from './src/relay/worker.mjs';
export { Device, Registry } from './src/relay/state.mjs';
export default createRelayWorker({ oidcDecisionFactory: () => new RustOidcDecisionCore(oidcModule) });
` }, bundle: true, write: false, metafile: true, format: 'esm', platform: 'neutral', mainFields: ['module', 'main'], external: ['cloudflare:workers', '*.wasm'] });
const entry = bundle.outputFiles[0].contents, sources = {}, dependencies = {};
const inputs = new Set([...await sourceFiles(), ...Object.keys(bundle.metafile.inputs).filter(file => file !== 'rust-oidc-entry.mjs' && !file.startsWith('..') && !file.includes('node_modules/'))]);
for (const file of [...inputs].sort()) sources[file] = hash(await fs.readFile(path.join(projectRoot, file)));
for (const [name, file] of Object.entries(dependencyPaths)) dependencies[name] = hash(await fs.readFile(file));
await fs.writeFile(path.join(output, wasm), bytes); await fs.writeFile(path.join(output, 'worker.mjs'), entry);
await fs.writeFile(path.join(output, 'manifest.json'), JSON.stringify({ v: 1, kind: 'oidc-login-decisions', profileABI: 1,
  entry: 'worker.mjs', oidcWasm: wasm, artifacts: { 'worker.mjs': hash(entry), [wasm]: hash(bytes) }, sources, dependencies }, null, 2) + '\n');
console.log(`Local independent OIDC decision entry built: ${output}`);
