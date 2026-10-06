import test from 'node:test';
import assert from 'node:assert/strict';
import { assertIdlePreview, preservedState } from '../scripts/switch-preview.mjs';

function state() {
  return { name: 'chat2local', version: '0.1.0-alpha.6', bridge: 'connected', paused: false, pending: [], folderPickerActive: false,
    roots: [{ id: 'sample', label: 'Chat2LocalDemo', path: '/test/sample', write: true, writeMode: 'review' }], startup: false, relay: 'https://relay.example.org', mcpUrl: 'https://relay.example.org/mcp', networkSettings: { mode: 'auto' }, hasRemoteUse: true };
}
test('preview switching rejects unknown, busy, paused or non-demo instances', () => {
  assert.doesNotThrow(() => assertIdlePreview(state(), '0.1.0-alpha.6'));
  for (const changes of [ { name: 'other' }, { version: 'unknown' }, { paused: true }, { bridge: 'disconnected' }, { pending: [{}] }, { folderPickerActive: true }, { setupActive: true }, { queuedOperations: 1 }, { lastRemoteCallAt: new Date().toISOString() }, { roots: [] }, { roots: [{ label: 'BusinessProject' }] } ]) {
    assert.throws(() => assertIdlePreview({ ...state(), ...changes }, '0.1.0-alpha.6'));
  }
});
test('preview state comparison includes folder grants, network, account endpoint and startup, but not transient metadata', () => {
  const before = state(); const snapshot = preservedState(before);
  assert.equal(preservedState({ ...before, version: '0.1.0-alpha.8', device: { name: 'new metadata' }, instanceId: 'new-process' }), snapshot);
  for (const changes of [{ startup: true }, { paused: true }, { mcpUrl: 'https://other.example.org/mcp' }, { hasRemoteUse: false }, { networkSettings: { mode: 'direct' } }, { roots: [{ ...before.roots[0], writeMode: 'direct' }] }]) {
    assert.notEqual(preservedState({ ...before, ...changes }), snapshot);
  }
});
