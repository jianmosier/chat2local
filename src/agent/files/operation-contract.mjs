import { checkedAccess } from '../../shared/connection-access.mjs';

export const FRAME_BYTES = 1024 * 1024;
export const messages = Object.freeze({
  EPENDING: 'Too many pending proposals. Ask the local user to review them.',
  ECAPACITY: 'Too many active operations. Wait for existing writes to finish.',
  ENOT_PENDING: 'Proposal is no longer pending.',
  EATTEMPT: 'Operation completion does not match an active attempt.',
  EDUPLICATE: 'Operation identity is already retained.',
  EINPUT: 'Invalid operation state command.',
  EOPERATIONS: 'Operation history is unavailable. New writes are blocked; no operation was replayed.',
});
export const fail = code => Object.assign(new Error(messages[code] || messages.EINPUT), { code });
export const exact = (value, required, optional = []) => value && typeof value === 'object' && !Array.isArray(value)
  && required.every(key => Object.hasOwn(value, key)) && Object.keys(value).every(key => [...required, ...optional].includes(key));
export const text = (value, size) => typeof value === 'string' && value.length <= size;
export const id = value => typeof value === 'string' && /^[a-f0-9-]{36}$/.test(value);
export const rootId = value => typeof value === 'string' && /^[a-zA-Z0-9_-]{1,80}$/.test(value);
export const digest = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
export const modes = ['read-only', 'review', 'direct'];
export const unknown = operationId => ({ operationId, status: 'unknown', message: 'Not retained for this connection or agent restarted. Do not assume a write succeeded.' });
export const publicView = operation => Object.fromEntries(['operationId', 'status', 'path', 'message', 'sha256', 'authorization', 'backupSaved']
  .filter(key => operation[key] !== undefined).map(key => [key, operation[key]]));
export const localView = operation => ({ ...publicView(operation), ...Object.fromEntries(['rootId', 'expectedHash', 'createdAt', 'content', 'before']
  .filter(key => operation[key] !== undefined).map(key => [key, operation[key]])) });
export function registration(input, owner) {
  if (!exact(input, ['operationId', 'rootId', 'path', 'expectedHash', 'content'], ['before']) || !id(input.operationId)
      || !rootId(input.rootId) || !text(input.path, 4096) || (input.expectedHash !== null && !digest(input.expectedHash))
      || !text(input.content, 65536) || Buffer.byteLength(input.content) > 65536 || input.content.includes('\0')
      || (input.before !== undefined && (!text(input.before, 65536) || Buffer.byteLength(input.before) > 65536))) throw fail('EINPUT');
  return owner === null ? null : checkedAccess(owner);
}
export function outcome(value) {
  if (!exact(value, ['status'], ['message', 'sha256', 'backupSaved']) || !['written', 'approved', 'failed', 'unknown'].includes(value.status)
      || (value.message !== undefined && !text(value.message, 4096)) || (value.sha256 !== undefined && !digest(value.sha256))
      || (value.backupSaved !== undefined && typeof value.backupSaved !== 'boolean')
      || (['written', 'approved'].includes(value.status) && !digest(value.sha256))) throw fail('EINPUT');
}
export function eventDetails(action, details) {
  const fields = { read: ['rootId', 'path'], proposed: ['operationId', 'rootId', 'path'], rejected: ['operationId'],
    'direct-write-requested': ['operationId', 'rootId', 'path'], written: ['operationId', 'rootId', 'path', 'sha256', 'authorization'],
    'directory-consent': ['rootId', 'from', 'to', 'flow'], 'permission-changed': ['rootId', 'from', 'to'] };
  if (!fields[action] || !exact(details, fields[action]) || ('operationId' in details && !id(details.operationId))
      || ('rootId' in details && !rootId(details.rootId)) || ('path' in details && !text(details.path, 4096))
      || ('sha256' in details && !digest(details.sha256)) || ('authorization' in details && !['local-review', 'directory-direct'].includes(details.authorization))
      || ('from' in details && ![...modes, ...(action === 'directory-consent' ? ['not-authorized'] : [])].includes(details.from))
      || ('to' in details && !modes.includes(details.to))
      || (action === 'directory-consent' && (details.to !== 'direct' || details.flow !== 'connection-guide'))) throw fail('EINPUT');
}
