import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { VERSION } from '../src/shared/protocol.mjs';
import { releaseTarget } from '../scripts/release-targets.mjs';
import { renderPosixInstaller } from '../scripts/build-installers.mjs';

const targets = ['darwin-x64', 'darwin-arm64', 'linux-x64', 'linux-arm64'].map(target => {
  const value = releaseTarget(target); const packageName = `${value.prefix}-test`;
  return { target, packageName, file: `${packageName}.${value.extension}`, version: VERSION, sha256: 'a'.repeat(64) };
});
const script = renderPosixInstaller('https://releases.example.org/test', targets);

// Execute the generated shell, but substitute OS facts and stop at the FIRST
// download attempt. This tests preflight logic, not actual Mac/Linux support.
function runPreflight({ system = 'Darwin', arch = 'x86_64', arm64 = '0', version = '13.5', libc = 'glibc 2.28', kernel = '4.18.0-test' } = {}) {
  const prefix = `
id() { printf '%s\\n' '1000'; }
uname() { case "$1" in -s) printf '%s\\n' "$TEST_SYSTEM" ;; -m) printf '%s\\n' "$TEST_ARCH" ;; -r) printf '%s\\n' "$TEST_KERNEL" ;; esac; }
sysctl() { printf '%s\\n' "$TEST_ARM64"; }
sw_vers() { printf '%s\\n' "$TEST_VERSION"; }
getconf() { printf '%s\\n' "$TEST_LIBC"; }
curl() { printf 'DOWNLOAD_WOULD_START:%s\\n' "$*" >&2; exit 77; }
`;
  return new Promise((resolve, reject) => {
    const child = spawn('sh', ['-s'], { stdio: ['pipe', 'pipe', 'pipe'], env: { ...process.env, TEST_SYSTEM: system, TEST_ARCH: arch, TEST_ARM64: arm64, TEST_VERSION: version, TEST_LIBC: libc, TEST_KERNEL: kernel } });
    let output = ''; const timer = setTimeout(() => { child.kill(); reject(new Error('Preflight fixture timed out.')); }, 10000);
    child.stdout.on('data', data => { output += data; }); child.stderr.on('data', data => { output += data; });
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('close', code => { clearTimeout(timer); resolve({ code, output }); });
    child.stdin.end(prefix + script);
  });
}

test('old or invalid macOS versions fail before any download; supported versions choose the exact architecture', async () => {
  for (const version of ['10.15.7', '12.7', '13.4.9', 'unknown', '13.5;echo injected']) {
    const result = await runPreflight({ version }); assert.equal(result.code, 1);
    assert.match(result.output, /macOS 13.5/); assert.doesNotMatch(result.output, /DOWNLOAD_WOULD_START/);
  }
  for (const version of ['13.5', '13.5.2', '14.0', '26.0']) {
    const result = await runPreflight({ version }); assert.equal(result.code, 77); assert.match(result.output, /macOS-x64-test.tar.gz/);
  }
});
test('Apple Silicon detected under an x64 shell still selects ARM64 without guessing an emulated binary', async () => {
  const result = await runPreflight({ arch: 'x86_64', arm64: '1' });
  assert.equal(result.code, 77); assert.match(result.output, /macOS-arm64-test.tar.gz/);
});
test('Linux musl, old glibc and old kernel fail before download while supported GNU/Linux passes preflight', async () => {
  const musl = await runPreflight({ system: 'Linux', libc: 'musl 1.2.5' });
  assert.equal(musl.code, 1); assert.match(musl.output, /musl\/Alpine/); assert.doesNotMatch(musl.output, /DOWNLOAD_WOULD_START/);
  const oldLibc = await runPreflight({ system: 'Linux', libc: 'glibc 2.27' });
  assert.equal(oldLibc.code, 1); assert.match(oldLibc.output, /glibc 2.28/); assert.doesNotMatch(oldLibc.output, /DOWNLOAD_WOULD_START/);
  const oldKernel = await runPreflight({ system: 'Linux', kernel: '4.17.9' });
  assert.equal(oldKernel.code, 1); assert.match(oldKernel.output, /kernel 4.18/); assert.doesNotMatch(oldKernel.output, /DOWNLOAD_WOULD_START/);
  const current = await runPreflight({ system: 'Linux', arch: 'aarch64', libc: 'glibc 2.39', kernel: '6.8.0-generic' });
  assert.equal(current.code, 77); assert.match(current.output, /Linux-arm64-test.tar.gz/);
});
test('unknown CPU and OS stop without contacting a release endpoint', async () => {
  for (const options of [{ arch: 'riscv64' }, { system: 'OtherOS' }]) {
    const result = await runPreflight(options); assert.equal(result.code, 1); assert.doesNotMatch(result.output, /DOWNLOAD_WOULD_START/);
  }
});
