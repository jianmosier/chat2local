import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const root = fileURLToPath(new URL('..', import.meta.url)), args = process.argv.slice(2);
if (process.platform !== 'win32' || (args.length && (args.length !== 2 || args[0] !== '--target-dir'))) throw Error('Usage (Windows): test-rust-terminal.mjs [--target-dir DIRECTORY]');
const target = args.length ? path.resolve(args[1]) : path.join(root, 'target');
const run = (file, args, env = process.env) => {
  const result = spawnSync(file, args, { cwd: root, env, stdio: 'inherit', windowsHide: true, shell: false });
  if (result.error || result.status !== 0) throw Error('Required Rust terminal validation failed.');
};
run('cargo', ['test', '--locked', '-p', 'chat2local-terminal-runner', '--target-dir', target]);
run('cargo', ['build', '--locked', '-p', 'chat2local-terminal-runner', '--target-dir', target]);
run(process.execPath, ['--test', '--test-concurrency=1', 'tests/rust-terminal.test.mjs'], { ...process.env,
  CHAT2LOCAL_TERMINAL_TEST_REQUIRED: '1', CHAT2LOCAL_TERMINAL_TEST_EXECUTABLE: path.join(target, 'debug', 'chat2local-terminal-runner.exe'),
});
