import test from 'node:test';
import assert from 'node:assert/strict';
import { parseInvitation, connectionSteps, helpfulError } from '../src/agent/ui/onboarding.js';

test('invitation parsing accepts only an explicit HTTPS enrollment fragment', () => {
  const secret = 'a'.repeat(64);
  assert.deepEqual(parseInvitation(` https://example.workers.dev/#enroll=${secret} `), { origin: 'https://example.workers.dev', enrollmentToken: secret });
  for (const value of ['http://example.org/#enroll=' + secret, 'https://user:pass@example.org/#enroll=' + secret, 'https://example.org/mcp#enroll=' + secret, 'https://example.org/?enroll=' + secret, 'https://example.org/#enroll=' + secret + '&extra=1', 'javascript:alert(1)', 'x'.repeat(2400)]) assert.throws(() => parseInvitation(value));
});
test('healthy local demo or relay never masquerades as a successful remote call', () => {
  assert.deepEqual(connectionSteps({ roots: [{}], bridge: 'connected' }), { folder: true, relay: true, verified: false });
  assert.equal(connectionSteps({ roots: [{}], bridge: 'connected', lastRemoteCallAt: '2026-09-20T00:00:00Z' }).verified, true);
  assert.equal(connectionSteps({ roots: [{}], bridge: 'connected', lastRemoteCallAt: '2026-09-20T00:00:00Z', paused: true }).verified, false);
  assert.equal(connectionSteps({ roots: [{}], bridge: 'disconnected', lastRemoteCallAt: '2026-09-20T00:00:00Z' }).verified, false);
});
test('common setup errors have actionable Chinese text without hiding unknown errors', () => {
  assert.match(helpfulError('Choose an absolute local folder.'), /选择文件夹/);
  assert.match(helpfulError('Filesystem operation failed (ENOENT).'), /没有找到/);
  assert.match(helpfulError('Relay enrollment failed (401).'), /邀请/);
  assert.equal(helpfulError('Unrecognized detail'), 'Unrecognized detail');
});
