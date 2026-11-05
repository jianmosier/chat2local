import { spawnSync } from 'node:child_process';
import { argumentsFor, projectRoot } from './rust-relay-artifact.mjs';
const { target, output } = argumentsFor(process.argv.slice(2));
const run = (file, args, env = process.env) => {
  const result = spawnSync(file, args, { cwd: projectRoot, env, stdio: 'inherit', shell: false, windowsHide: true });
  if (result.error || result.status !== 0) throw Error('Required Rust Device validation failed.');
};
run('cargo', ['test', '--locked', '-p', 'chat2local-relay-device-core', '--target-dir', target]);
run(process.execPath, ['scripts/build-rust-relay.mjs', '--target-dir', target, '--out-dir', output]);
const defaults = { ...process.env }; for(const key of ['CHAT2LOCAL_DEVICE_TEST_REQUIRED','CHAT2LOCAL_DEVICE_TEST_ARTIFACT_DIR','CHAT2LOCAL_REGISTRY_TEST_REQUIRED','CHAT2LOCAL_REGISTRY_TEST_ARTIFACT_DIR','CHAT2LOCAL_REGISTRY_TEST_DENY_LEGACY','CHAT2LOCAL_OAUTH_TEST_REQUIRED','CHAT2LOCAL_OAUTH_TEST_ARTIFACT_DIR','CHAT2LOCAL_OAUTH_TEST_DENY_LEGACY'])delete defaults[key];
console.log('Default JS Device transport regressions');
run(process.execPath, ['--test', '--test-concurrency=1', 'tests/socket-lease.test.mjs', 'tests/account-transport.test.mjs', 'tests/relay.test.mjs', 'tests/multi-device.test.mjs'], defaults);
console.log('Explicit Rust Device strict integration and transport regressions');
run(process.execPath, ['--test', '--test-concurrency=1', 'tests/rust-device.test.mjs', 'tests/socket-lease.test.mjs', 'tests/account-transport.test.mjs', 'tests/relay.test.mjs', 'tests/multi-device.test.mjs'],
  { ...defaults, CHAT2LOCAL_DEVICE_TEST_REQUIRED: '1', CHAT2LOCAL_DEVICE_TEST_ARTIFACT_DIR: output });
