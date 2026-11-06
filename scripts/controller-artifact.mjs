import fs from 'node:fs/promises';
import path from 'node:path';
import { root, hash } from './transport-artifact.mjs';
export { root, hash };
export async function sourceFiles(sourceRoot = root) {
  const workflowFiles = ['tests/native-account-fixture.mjs', 'tests/rust-account.test.mjs', 'tests/rust-account-http.test.mjs', 'crates/agent-controller/ui/recovery.js', 'src/agent/ui/account-connect.html', 'src/agent/ui/account-connect.js', 'src/agent/ui/connect.css', 'src/agent/ui/folders.html', 'src/agent/ui/folders.js', 'src/agent/ui/folders.css', 'src/agent/ui/lifecycle.js'];
  const files = ['scripts/build-native-agent.mjs', 'scripts/native-agent-artifact.mjs', 'tests/native-agent.test.mjs', 'tests/rust-consent.test.mjs', 'crates/agent-controller/ui/index.html', 'crates/agent-controller/ui/panel.js', 'crates/agent-controller/ui/panel.css', 'Cargo.toml', 'Cargo.lock', 'tests/rust-bridge.test.mjs', 'tests/rust-commands.test.mjs', 'tests/rust-network.test.mjs', 'tests/rust-platform.test.mjs', 'tests/transport-fixture.mjs', 'src/relay/worker.mjs', 'src/relay/state.mjs', 'src/relay/device-session-core.mjs', 'src/relay/socket-lease.mjs', 'tests/native-bridge-fixture.mjs', 'src/agent/bridge.mjs', 'src/agent/runtime/tool-dispatcher.mjs', 'src/agent/files.mjs', 'src/agent/files/access-policy.mjs', 'src/agent/files/operation-store.mjs', 'src/agent/connection-guide.mjs', 'src/shared/connection-access.mjs', 'src/shared/protocol.mjs', 'src/shared/terminal-permission.mjs', 'src/agent/network.mjs', 'crates/agent-transport/data/node-24.21.0-roots.pem', 'crates/agent-transport/data/node-24.21.0-policy.json', 'src/agent/main.mjs', 'src/agent/store.mjs', 'src/agent/controller-http.mjs', 'src/agent/management-session.mjs', 'src/agent/permissions.mjs', 'src/agent/files/write-fence.mjs', 'src/agent/files/path-policy.mjs', 'src/agent/runtime/agent-state.mjs', 'src/agent/runtime/controller-owner.mjs', 'src/agent/runtime/http-router.mjs', 'scripts/build-rust-controller.mjs', 'scripts/controller-artifact.mjs', 'scripts/test-rust-controller.mjs', 'scripts/build-rust-transport.mjs', 'scripts/transport-artifact.mjs', 'tests/rust-controller.test.mjs', 'tests/controller-ownership.test.mjs', 'tests/controller-fixture.mjs'];
  for (const crate of ['native-agent', 'terminal-runner', 'agent-transport', 'operation-core', 'agent-controller', 'agent-controller-fixture', 'agent-platform', 'native-store', 'js-value-compat', 'agent-lifecycle-core', 'policy', 'protocol']) {
    files.push(`crates/${crate}/Cargo.toml`);
    for (const entry of await fs.readdir(path.join(sourceRoot, `crates/${crate}`), { recursive: true, withFileTypes: true })) if (entry.isFile() && entry.name.endsWith('.rs')) files.push(path.relative(sourceRoot, path.join(entry.parentPath, entry.name)).split(path.sep).join('/'));
  }
  files.push('package.json', 'package-lock.json');
  for (const directory of ['src/agent', 'src/shared', 'src/relay']) {
    for (const entry of await fs.readdir(path.join(sourceRoot, directory), { recursive: true, withFileTypes: true })) if (entry.isFile() && entry.name.endsWith('.mjs')) files.push(path.relative(sourceRoot, path.join(entry.parentPath, entry.name)).split(path.sep).join('/'));
  }
  return [...new Set([...files,...workflowFiles])].sort();
}
export async function readControllerArtifact(executable, { sourceRoot = root } = {}) {
  const manifest = JSON.parse(await fs.readFile(path.join(path.dirname(executable), 'manifest.json'), 'utf8')), files = await sourceFiles(sourceRoot);
  if (manifest.v !== 1 || manifest.fixtureOnly !== true || manifest.fullAgent !== false || manifest.architecture !== process.arch || manifest.platform !== process.platform || manifest.executable !== path.basename(executable) || manifest.opensslVersion !== '3.5.8' || !/^[a-f0-9]{64}$/.test(manifest.opensslManifestSha256 ?? '') || Object.keys(manifest.sources ?? {}).sort().join('\n') !== files.join('\n')) throw Error('Controller fixture manifest mismatch.');
  for (const file of files) if (hash(await fs.readFile(path.join(sourceRoot, file))) !== manifest.sources[file]) throw Error('Stale controller fixture source: ' + file);
  if (hash(await fs.readFile(executable)) !== manifest.sha256) throw Error('Controller fixture binary mismatch.');
  const helper = manifest.terminalRunner, name = 'chat2local-terminal-runner' + (process.platform === 'win32' ? '.exe' : '');
  if (helper?.fixtureOnly !== true || helper?.executable !== name || hash(await fs.readFile(path.join(path.dirname(executable), name))) !== helper.sha256) throw Error('Controller terminal helper mismatch.');
  return manifest;
}

