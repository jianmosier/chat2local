import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { publicDocuments, inspectPublicText, buildPublic } from '../scripts/build-public.mjs';
import { auditTree, auditGit, inspectAuditEntry } from '../scripts/audit-public.mjs';
import { VERSION } from '../src/shared/protocol.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
test('public documentation links and versions match the exported contract', async () => {
  const files = ['README.md', 'SECURITY.md', ...publicDocuments];
  const allowed = new Set(files);
  for (const relative of files) {
    const text = await fs.readFile(path.join(root, relative), 'utf8');
    if (relative !== 'SECURITY.md') assert.ok(text.includes(VERSION), relative + ' lacks the current version');
    for (const link of text.matchAll(/\[[^\]]*\]\(([^)]+)\)/g)) {
      const target = link[1].split('#')[0];
      if (!target || /^[a-z]+:/i.test(target)) continue;
      const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(relative), target));
      assert.ok(allowed.has(resolved), `${relative} links to an unexported document: ${resolved}`);
      assert.ok((await fs.stat(path.join(root, resolved))).isFile());
    }
  }
  const pkg = JSON.parse(await fs.readFile(path.join(root, 'package.json')));
  assert.equal(Object.keys({ ...pkg.dependencies, ...pkg.devDependencies }).some(name => /devspace/i.test(name)), false);
});
test('privacy patterns reject synthetic machine identifiers without embedding a real owner identifier', () => {
  for (const name of ['DESK' + 'TOP-1234567', 'LAP' + 'TOP-7654321', 'fixture-machine' + '.local', 'fixture-machine' + '\\.local']) {
    assert.throws(() => inspectPublicText('fixture.txt', name), /Personal/);
  }
  inspectPublicText('fixture.mjs', "const blocked = '.env.local'; const path = '.local/share'; const config = 'wrangler.local.jsonc'; this.local = local;");
  assert.throws(() => inspectPublicText('fixture.txt', 'short-secret', ['short-secret']), /Private/);
});
test('audit findings redact secrets and treat unscanned content as a failure', () => {
  const secret = 'gh' + 'p_' + 'a'.repeat(40);
  const finding = inspectAuditEntry('fixture.txt', Buffer.from(secret));
  assert.equal(finding.category, 'credential-pattern');
  assert.equal(JSON.stringify(finding).includes(secret), false);
  assert.equal(inspectAuditEntry('vault.json', Buffer.from('{}')).category, 'private-file');
  assert.equal(inspectAuditEntry('binary.bin', Buffer.from([255, 254])).category, 'non-text-unscanned');
});
test('public export includes current docs and passes its independent read-only tree audit', async t => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-public-audit-'));
  t.after(() => fs.rm(base, { recursive: true, force: true }));
  const report = await buildPublic(path.join(base, 'export'));
  const manifest = JSON.parse(await fs.readFile(path.join(report.directory, 'SOURCE-SHA256.json')));
  for (const doc of publicDocuments) assert.ok(manifest.files[doc], doc);
  assert.ok(manifest.files['src/relay/request-budget.mjs']);
  assert.equal(manifest.files['wrangler.local.jsonc'], undefined);
  const audit = await auditTree(report.directory);
  assert.equal(audit.passed, true, JSON.stringify(audit.findings));
});
test('history audit detects a deleted synthetic secret and does not change the checkout', async t => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-history-audit-'));
  t.after(() => fs.rm(base, { recursive: true, force: true }));
  const git = args => execFileSync('git', ['-C', base, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  git(['init', '-b', 'main']);
  git(['config', 'user.name', 'Fixture']); git(['config', 'user.email', 'fixture@example.test']);
  git(['config', 'core.autocrlf', 'false']);
  git(['config', 'core.hooksPath', path.join(base, 'no-hooks')]);
  const secret = 'gh' + 'p_' + 'b'.repeat(40);
  await fs.writeFile(path.join(base, 'sample.txt'), secret);
  git(['add', 'sample.txt']); git(['-c', 'commit.gpgsign=false', 'commit', '-m', 'fixture first']);
  await fs.writeFile(path.join(base, 'sample.txt'), 'sanitized fixture');
  git(['add', 'sample.txt']); git(['-c', 'commit.gpgsign=false', 'commit', '-m', 'fixture second']);
  const before = git(['rev-parse', 'HEAD']).toString();
  const result = auditGit(base);
  assert.equal(result.commits, 2); assert.equal(result.passed, false);
  assert.ok(result.findings.some(f => f.category === 'credential-pattern'));
  assert.equal(JSON.stringify(result).includes(secret), false);
  assert.equal(git(['rev-parse', 'HEAD']).toString(), before);
  assert.equal(git(['status', '--porcelain']).toString(), '');
});
test('bundled help documents current installation and terminal boundaries', async () => {
  const html = await fs.readFile(path.join(root, 'src/agent/ui/self-host.html'), 'utf8');
  assert.ok(html.includes('实例安装密码'));
  assert.ok(html.includes('终端不是操作系统沙箱'));
  assert.equal(html.includes('当前不提供任意命令行操作'), false);
  assert.equal(html.includes('docs/SELF_HOST.md'), false);
});
