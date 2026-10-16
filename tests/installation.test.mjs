import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { Script } from 'node:vm';
import { Readable } from 'node:stream';
import { chromium } from 'playwright-core';
import { installationOrigin, installationInstructions } from '../src/shared/installation.mjs';
import { SOURCE_REPOSITORY, bootstrapSource } from '../src/shared/distribution.mjs';
import { publicBootstrap, publicPowerShellBootstrap } from '../src/shared/public-bootstrap.mjs';
import { installAssetRoute } from '../src/relay/install-assets.mjs';
import { installRoute } from '../src/relay/install-http.mjs';
import { installerPage, installerScript } from '../src/relay/install-page.mjs';
import { bodyJson, matchesSecret, selectedPermission } from '../src/agent/controller-http.mjs';
import { uiAsset } from '../src/agent/ui-assets.mjs';
import { VERSION, MAX_WIRE_BYTES } from '../src/shared/protocol.mjs';

const origin = 'https://instance.example.test';
const source = 'https://raw.githubusercontent.com/owner/project/v0.1.0-alpha.27/install.sh';

test('installation commands contain only a canonical instance and reject shell input', () => {
  assert.equal(installationOrigin(origin + '/'), origin);
  assert.equal(installationInstructions(origin, 'win32').command, `irm ${origin}/install.ps1 | iex`);
  assert.equal(installationInstructions(origin, 'darwin').command, `curl -fsS --proto '=https' ${origin}/install.sh | sh`);
  for (const input of [null, '', 'http://example.test', origin + '/mcp', origin + '/?token=x', origin + '/#x',
    'https://user:pass@example.test', origin + "'; echo injected", origin + '/%27', origin + '\n',
    'https://example.test/../', 'https://example.test\\evil']) {
    assert.throws(() => installationInstructions(input, 'win32'), String(input));
  }
  assert.throws(() => installationInstructions(origin, 'linux'), /Windows and macOS/);
});

test('standalone bootstrap distribution values and package versions agree', async () => {
  const ps = await fs.readFile('install.ps1', 'utf8');
  const sh = await fs.readFile('install.sh', 'utf8');
  assert.ok(ps.includes(`$Repository = '${SOURCE_REPOSITORY}'`));
  assert.ok(sh.includes(`repository='${SOURCE_REPOSITORY}'`));
  assert.ok(ps.includes(`$Version = '${VERSION}'`));
  assert.ok(sh.includes(`version='${VERSION}'`));
  assert.equal(bootstrapSource('ps1'), `https://raw.githubusercontent.com/${SOURCE_REPOSITORY}/v${VERSION}/install.ps1`);
  assert.throws(() => bootstrapSource('exe'));
  assert.throws(() => bootstrapSource('sh', 'main'));
});

test('generated bootstraps parse without downloading or executing software', () => {
  const shell = publicBootstrap(origin, source);
  const posix = spawnSync('sh', ['-n'], { input: shell, encoding: 'utf8', timeout: 10000 });
  assert.equal(posix.status, 0, posix.stderr || String(posix.error));
  const ps = publicPowerShellBootstrap(origin, source);
  assert.ok(ps.includes(source.replace('install.sh', 'install.ps1')));
  assert.ok(ps.includes(`-Instance '${origin}'`));
  assert.ok(ps.includes('-MaximumRedirection 0'));
  assert.equal(/ExecutionPolicy|EncodedCommand|RunAs/.test(ps), false);
  if (process.platform === 'win32') {
    const parsed = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command',
      '$tokens=$null; $errors=$null; [void][System.Management.Automation.Language.Parser]::ParseInput([Console]::In.ReadToEnd(),[ref]$tokens,[ref]$errors); if($errors.Count){ $errors | Out-String | Write-Error; exit 1 }'],
    { input: ps, encoding: 'utf8', timeout: 15000, windowsHide: true });
    assert.equal(parsed.status, 0, parsed.stderr || String(parsed.error));
  }
  for (const badSource of [source.replace('v0.1.0-alpha.27', 'main'), source + '?x=y', 'https://untrusted.invalid/install.sh']) {
    assert.throws(() => publicPowerShellBootstrap(origin, badSource));
  }
});

test('installer download router preserves private/method/query and static asset boundaries', async () => {
  const env = { PRIVATE_INSTANCE: 'true', PUBLIC_BOOTSTRAP_URL: source };
  const response = installAssetRoute(new Request(origin + '/install.ps1'), env, origin);
  assert.equal(response.status, 200);
  assert.equal(await response.text(), publicPowerShellBootstrap(origin, source));
  assert.equal(response.headers.get('Cache-Control'), 'no-store');
  assert.equal(await installAssetRoute(new Request(origin + '/install.ps1', { method: 'HEAD' }), env, origin).text(), '');
  for (const request of [new Request(origin + '/install.ps1?token=x'), new Request(origin + '/install.ps1', { method: 'POST' })]) {
    assert.equal(installAssetRoute(request, env, origin).status, 404);
  }
  assert.equal(installAssetRoute(new Request(origin + '/install.ps1'), {}, origin).status, 404);
  assert.equal(installAssetRoute(new Request(origin + '/unlisted-file'), env, origin), null);
  let calls = 0;
  const assets = { fetch: request => { calls++; return new Response(request.url); } };
  const staticEnv = { ...env, ASSETS: assets };
  assert.equal(await installAssetRoute(new Request(origin + '/install.sh'), staticEnv, origin).text(), origin + '/install.sh');
  assert.equal(calls, 1);
  assert.equal(installAssetRoute(new Request(origin + '/install.ps1'), staticEnv, origin).status, 200);
  assert.equal(calls, 1, 'Windows should not require replacing existing Mac asset packs');
});

test('extracted local HTTP guards preserve explicit consent, token length and request limits', async () => {
  const token = 'a'.repeat(64);
  assert.equal(matchesSecret(token, token), true);
  for (const value of [undefined, '', 'a', 'b'.repeat(64), ['a']]) assert.equal(matchesSecret(value, token), false);
  assert.equal(matchesSecret(token, 'a'), false);
  assert.throws(() => selectedPermission({ writeMode: 'direct' }), /明确确认/);
  const request = (bytes, type = 'application/json') => Object.assign(Readable.from([bytes]), { headers: { 'content-type': type } });
  assert.deepEqual(await bodyJson(request(Buffer.from('{"ok":true}'))), { ok: true });
  await assert.rejects(bodyJson(request(Buffer.from('{}'), 'text/plain')), error => error.status === 415);
  await assert.rejects(bodyJson(request(Buffer.from([0xff]))), error => error.status === 400);
  await assert.rejects(bodyJson(request(Buffer.alloc(MAX_WIRE_BYTES + 1))), error => error.status === 413);
  assert.ok(uiAsset('/lifecycle.js'));
  assert.ok(uiAsset('/installation.js'));
  assert.equal(uiAsset('/../../secrets.json'), undefined);
});

test('installation page has escaped, platform-specific commands and a parseable script', () => {
  const page = installerPage('a'.repeat(64), origin);
  assert.ok(page.includes('Windows · PowerShell'));
  assert.ok(page.includes('macOS · 终端'));
  assert.ok(page.includes(`${origin}/install.ps1 | iex`));
  assert.equal(page.includes(SOURCE_REPOSITORY), false);
  assert.equal(installerPage('<bad>', origin).includes('value="<bad>"'), false);
  assert.doesNotThrow(() => new Script(installerScript));
});

test('real browser switches installer platform without registration or granting access', async t => {
  const browser = await chromium.launch({ channel: 'msedge', headless: true });
  t.after(() => browser.close());
  const page = await browser.newPage();
  const calls = [], errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.route('**/*', async route => {
    const url = new URL(route.request().url());
    calls.push(url.pathname);
    if (!['/install', '/install.js'].includes(url.pathname)) return route.fulfill({ status: 404, body: '' });
    const result = await installRoute(new Request(url), { PRIVATE_INSTANCE: 'true' }, origin);
    await route.fulfill({ status: result.status, headers: Object.fromEntries(result.headers), body: await result.text() });
  });
  await page.goto(origin + '/install');
  await page.locator('#platform').selectOption('win32');
  assert.equal(await page.locator('#command').innerText(), `irm ${origin}/install.ps1 | iex`);
  await page.locator('#platform').selectOption('darwin');
  assert.equal(await page.locator('#command').innerText(), `curl -fsS --proto '=https' ${origin}/install.sh | sh`);
  assert.equal(calls.some(route => /^\/install\//.test(route)), false);
  assert.deepEqual(errors, []);
});
