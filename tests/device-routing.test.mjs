import test from 'node:test';
import assert from 'node:assert/strict';
import { checkedDevices, grantDevices, selectDevice, bindingSignature, deviceDescription } from '../src/shared/device-grants.mjs';
import { routeDeviceTool } from '../src/relay/device-router.mjs';
import { checkArguments } from '../src/shared/protocol.mjs';
import { setupAvailability } from '../src/shared/setup.mjs';
const a = { deviceId: 'a'.repeat(32), epoch: 'a'.repeat(64), description: { name: 'same-name', system: 'Windows' } };
const b = { deviceId: 'b'.repeat(32), epoch: 'b'.repeat(64), description: { name: 'same-name', system: 'macOS' } };
const props = { grantVersion: 2, devices: [a, b], scopes: ['files:read', 'files:write'] };

test('legacy tokens stay single-device and malformed/mixed/duplicate grants fail closed', () => {
  assert.deepEqual(grantDevices({ deviceId: a.deviceId, epoch: a.epoch, scopes: ['files:read'] }).map(item => item.deviceId), [a.deviceId]);
  for (const invalid of [{ ...props, deviceId: a.deviceId }, { ...props, epoch: a.epoch }, { ...props, grantVersion: 3 }, { ...props, devices: [] }, { ...props, devices: [a, a] }, { ...props, devices: Array(21).fill(a) }]) assert.throws(() => grantDevices(invalid));
  assert.throws(() => checkedDevices([{ ...a, epoch: 'bad' }]));
  assert.equal(bindingSignature([a, b]), bindingSignature([b, a]));
});
test('routing identity is explicit; names, order and offline status are never a selector', () => {
  assert.throws(() => selectDevice([a, b]), /More than one/);
  assert.equal(selectDevice([a]).deviceId, a.deviceId);
  assert.equal(selectDevice([a, b], b.deviceId).deviceId, b.deviceId);
  assert.throws(() => selectDevice([a], b.deviceId), /not included/);
  assert.throws(() => selectDevice([a, b], 'same-name'));
  assert.throws(() => checkArguments('read_file', { deviceId: 'same-name', rootId: 'r', path: 'f.txt' }));
});
test('parallel requests keep independent targets and do not pass routing fields to older agents', async () => {
  const requests = [];
  const invoke = async (target, name, args) => { await new Promise(resolve => setTimeout(resolve, target.deviceId === a.deviceId ? 20 : 1)); requests.push({ deviceId: target.deviceId, name, args }); return { content: target.deviceId }; };
  const results = await Promise.all([a, b].map(target => routeDeviceTool({ props, tool: 'read_file', args: { deviceId: target.deviceId, rootId: 'identical-root', path: 'same.txt' }, origin: 'https://relay.example.org', invoke })));
  assert.deepEqual(results.map(item => item.deviceId), [a.deviceId, b.deviceId]);
  assert.equal(requests.length, 2); assert.ok(requests.every(item => item.args.deviceId === undefined));
});
test('offline, unknown and ambiguous writes are never retried or routed to another device', async () => {
  const called = [];
  const invoke = async target => { called.push(target.deviceId); throw Object.assign(new Error('Computer is offline.'), { status: 503 }); };
  const run = args => routeDeviceTool({ props, tool: 'write_file', args, origin: 'https://relay.example.org', invoke });
  await assert.rejects(() => run({}), /More than one/);
  await assert.rejects(() => run({ deviceId: 'c'.repeat(32) }), /not included/);
  assert.deepEqual(called, []);
  await assert.rejects(() => run({ deviceId: b.deviceId }), /offline/); assert.deepEqual(called, [b.deviceId]);
});
test('device discovery exposes no epochs or credentials and preserves unavailable members', async () => {
  const result = await routeDeviceTool({ props, tool: 'list_devices', args: {}, describe: async target => {
    if (target.deviceId === b.deviceId) throw Object.assign(new Error('revoked'), { status: 403 });
    return { online: false, description: { name: 'A', deviceKey: 'secret', epoch: a.epoch } };
  } });
  assert.equal(result.selectionRequired, true); assert.deepEqual(result.devices.map(item => item.status), ['offline', 'revoked']);
  assert.equal(JSON.stringify(result).includes(a.epoch), false); assert.equal(JSON.stringify(result).includes('deviceKey'), false);
  assert.deepEqual(deviceDescription({ name: '<untrusted>', token: 'secret', arch: 'bad\nvalue' }), { name: '<untrusted>' });
});
test('write scope is checked before contacting any device even when a directory might allow writing', async () => {
  let invoked = false;
  await assert.rejects(() => routeDeviceTool({ props: { ...props, scopes: ['files:read'] }, tool: 'write_file', args: { deviceId: a.deviceId }, origin: 'https://relay.example.org', invoke: () => { invoked = true; } }), error => /insufficient_scope/.test(error.wwwAuthenticate));
  assert.equal(invoked, false);
});
test('custom-connector pilots do not require a listing but still require explicit enrollment enablement', () => {
  assert.equal(setupAvailability({ customConnector: true, selfService: false }).code, 'REGISTRATION_CLOSED');
  assert.equal(setupAvailability({ customConnector: true, selfService: true }).code, 'CUSTOM_READY');
  assert.equal(setupAvailability({ customConnector: 'true', selfService: true }).ready, false);
  assert.equal(setupAvailability({ selfService: true }).code, 'PUBLICATION_REQUIRED');
});
