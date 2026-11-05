import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
const root = fileURLToPath(new URL('..', import.meta.url)), args = process.argv.slice(2);
if (args.length && (args.length !== 2 || args[0] !== '--target-dir')) throw Error('Usage: test-rust-operations.mjs [--target-dir DIRECTORY]');
if (process.platform !== 'win32') throw Error('Combined operation/native acceptance requires Windows NTFS.');
const target = args.length ? path.resolve(args[1]) : path.join(root, 'target');
function run(executable, args, env = process.env) {
  const result = spawnSync(executable, args, { cwd: root, env, stdio: 'inherit', shell: false, windowsHide: true });
  if (result.error || result.status !== 0) throw Error('Required operation state validation failed.');
}
run('cargo', ['test', '--locked', '-p', 'chat2local-operation-core', '--target-dir', target]);
run(process.execPath, ['scripts/build-rust-operations.mjs', '--target-dir', target]);
run('cargo', ['build', '--locked', '-p', 'chat2local-writer', '-p', 'chat2local-readonly', '--target-dir', target]);
run(process.execPath, ['--test', '--test-concurrency=1', 'tests/rust-operations.test.mjs'], { ...process.env,
  CHAT2LOCAL_OPERATIONS_TEST_REQUIRED: '1', CHAT2LOCAL_OPERATIONS_TEST_MODULE: path.join(target, 'wasm32-unknown-unknown/release/chat2local_operation_wasm.wasm'),
  CHAT2LOCAL_WRITER_TEST_EXECUTABLE: path.join(target, 'debug/chat2local-writer.exe'),
  CHAT2LOCAL_READONLY_TEST_EXECUTABLE: path.join(target, 'debug/chat2local-readonly.exe'),
});
