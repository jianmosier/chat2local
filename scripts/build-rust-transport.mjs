import fs from 'node:fs/promises';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { root, sourceFiles, hash, readTransportArtifact } from './transport-artifact.mjs';
export function optionsFor(args) {
  const options = { target: path.join(root, 'target'), output: path.join(root, '.artifacts/rust-transport'), openssl: process.env.CHAT2LOCAL_OPENSSL_DIR, manifest: process.env.CHAT2LOCAL_OPENSSL_MANIFEST, manifestHash: process.env.CHAT2LOCAL_OPENSSL_MANIFEST_SHA256 };
  const names = { '--target-dir': 'target', '--out-dir': 'output', '--openssl-dir': 'openssl', '--openssl-manifest': 'manifest', '--openssl-manifest-sha256': 'manifestHash' }, seen = new Set();
  for (let i = 0; i < args.length; i += 2) { const key = names[args[i]]; if (!key || seen.has(key) || !args[i + 1]) throw Error('Invalid transport build options. Supply explicit OpenSSL directory, manifest and SHA256.'); seen.add(key); options[key] = args[i + 1]; }
  for (const key of ['target', 'output', 'openssl', 'manifest']) { if (!options[key]) throw Error('Explicit task-local OpenSSL build inputs required.'); options[key] = path.resolve(options[key]); }
  if (!/^[a-f0-9]{64}$/.test(options.manifestHash ?? '') || !options.output.split(path.sep).includes('.artifacts')) throw Error('Transport fixture output must be under .artifacts with a pinned dependency manifest.');
  return options;
}
export function run(file, args, env = process.env, { capture = false, input } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(file, args, { cwd: root, env, stdio: [input ? 'pipe' : 'ignore', capture ? 'pipe' : 'inherit', 'inherit'], windowsHide: true, shell: false });
    let output = '', overflow = false;
    child.stdout?.on('data', data => { output += data; if (output.length > 4 * 1024 * 1024) { overflow = true; child.kill(); } });
    child.once('error', reject); child.once('close', code => code === 0 && !overflow ? resolve(output) : reject(Error('Required transport command failed.')));
    if (input) child.stdin.end(input);
  });
}
export async function buildEnvironment(options) {
  const bytes = await fs.readFile(options.manifest);
  if (hash(bytes) !== options.manifestHash) throw Error('OpenSSL dependency manifest digest mismatch.');
  const manifest = JSON.parse(bytes), base = path.dirname(options.manifest);
  if (path.resolve(base, 'install') !== options.openssl) throw Error('OpenSSL install is not bound to the accepted manifest.');
  for (const required of ['install/include/openssl/opensslv.h', 'install/lib/libssl.lib', 'install/lib/libcrypto.lib', 'install/bin/openssl.exe']) if (!manifest[required]) throw Error('OpenSSL manifest lacks required native build inputs.');
  for (const [file, digest] of Object.entries(manifest)) {
    const full = path.resolve(base, file), relative = path.relative(base, full);
    if (relative.startsWith('..') || path.isAbsolute(relative) || hash(await fs.readFile(full)) !== digest) throw Error('OpenSSL accepted dependency artifact mismatch.');
  }
  const header = await fs.readFile(path.join(options.openssl, 'include/openssl/opensslv.h'), 'utf8');
  if (!header.includes('OpenSSL 3.5.8 ')) throw Error('OpenSSL header version mismatch.');
  const expected = { OPENSSL_DIR: options.openssl, OPENSSL_LIB_DIR: path.join(options.openssl, 'lib'), OPENSSL_INCLUDE_DIR: path.join(options.openssl, 'include'), OPENSSL_STATIC: '1', OPENSSL_NO_VENDOR: '1' };
  for (const [name, value] of Object.entries(process.env)) if (/(?:^|_)OPENSSL_(?:DIR|LIB_DIR|INCLUDE_DIR|STATIC|NO_VENDOR|LIBS|CONFIG_DIR)$/.test(name) && !name.startsWith('CHAT2LOCAL_') && value !== undefined && value !== expected[name]) throw Error('Conflicting inherited OpenSSL build override.');
  const env = { ...process.env, ...expected };
  const version = await run(path.join(options.openssl, 'bin/openssl.exe'), ['version'], env, { capture: true });
  if (!version.startsWith('OpenSSL 3.5.8 ')) throw Error('OpenSSL runtime version mismatch.');
  return env;
}
export async function buildTransport(options) {
  const env = await buildEnvironment(options), sources = {};
  for (const file of await sourceFiles()) sources[file] = hash(await fs.readFile(path.join(root, file)));
  await run('cargo', ['build', '--locked', '-p', 'chat2local-agent-transport-fixture', '--target-dir', options.target], env);
  for (const [file, digest] of Object.entries(sources)) if (hash(await fs.readFile(path.join(root, file))) !== digest) throw Error('Transport source changed during build.');
  await fs.mkdir(options.output, { recursive: true }); const name = 'chat2local-agent-transport-fixture' + (process.platform === 'win32' ? '.exe' : ''), executable = path.join(options.output, name);
  await fs.copyFile(path.join(options.target, 'debug', name), executable);
  const runtime = JSON.parse(await run(executable, [], env, { capture: true, input: '{"op":"version"}\n' }));
  if (!runtime.ok || !runtime.fixtureOnly || !runtime.openssl.startsWith('OpenSSL 3.5.8 ')) throw Error('Native transport linked runtime mismatch.');
  await fs.writeFile(path.join(options.output, 'manifest.json'), JSON.stringify({ v: 1, fixtureOnly: true, executable: name, sha256: hash(await fs.readFile(executable)), sources, opensslVersion: '3.5.8', opensslManifestSha256: options.manifestHash }, null, 2) + '\n');
  await readTransportArtifact(executable); return { executable };
}
if (import.meta.main) console.log(await buildTransport(optionsFor(process.argv.slice(2))));
