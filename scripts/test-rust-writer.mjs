import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
const root = fileURLToPath(new URL('..', import.meta.url)), args = process.argv.slice(2);
if (process.platform !== 'win32') throw Error('Native writer acceptance requires Windows NTFS.');
if (args.length && (args.length !== 2 || args[0] !== '--target-dir')) throw Error('Usage: test-rust-writer.mjs [--target-dir DIRECTORY]');
const target = args.length ? path.resolve(args[1]) : path.join(root, 'target');
const run = (executable, input, env = process.env) => {
  const result = spawnSync(executable, input, { cwd: root, env, stdio: 'inherit', shell: false, windowsHide: true });
  if (result.error || result.status !== 0) throw Error('Required Rust writer validation failed.');
};
run('cargo', ['test', '--locked', '--workspace', '--target-dir', target]);
run('cargo', ['build', '--locked', '-p', 'chat2local-writer', '--target-dir', target]);
run(process.execPath, ['--test', '--test-concurrency=1', 'tests/rust-writer.test.mjs'], {
  ...process.env, CHAT2LOCAL_WRITER_TEST_REQUIRED: '1', CHAT2LOCAL_WRITER_TEST_EXECUTABLE: path.join(target, 'debug', 'chat2local-writer.exe'),
});
