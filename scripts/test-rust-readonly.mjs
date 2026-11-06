import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const root = fileURLToPath(new URL('..', import.meta.url));
const args = process.argv.slice(2);
if (args.length && (args.length !== 2 || args[0] !== '--target-dir')) throw Error('Usage: test-rust-readonly.mjs [--target-dir DIRECTORY]');
if (process.platform !== 'win32') throw Error('Native Rust readonly acceptance currently requires Windows.');
const target = args.length ? path.resolve(args[1]) : path.join(root, 'target');
const run = (executable, input, env = process.env) => {
  const result = spawnSync(executable, input, { cwd: root, env, stdio: 'inherit', shell: false, windowsHide: true });
  if (result.error || result.status !== 0) throw Error('Required Rust readonly validation failed.');
};
run('cargo', ['test', '--locked', '--target-dir', target, '--workspace']);
run('cargo', ['build', '--locked', '--target-dir', target, '-p', 'chat2local-readonly']);
run(process.execPath, ['--test', '--test-concurrency=1', 'tests/rust-readonly.test.mjs'], {
  ...process.env, CHAT2LOCAL_RUST_TEST_REQUIRED: '1', CHAT2LOCAL_RUST_TEST_EXECUTABLE: path.join(target, 'debug', 'chat2local-readonly.exe'),
});
