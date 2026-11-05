import { json } from '../shared/protocol.mjs';
/** Backend choice is explicit per aggregate. The default never loads WASM. */
export function registryTransaction(storage, runner, op, input, legacy, { now = Date.now } = {}) {
  if (runner) return runner.transaction(storage, op, input, { now });
  return storage.transaction(legacy);
}
export function registryHttp(value) {
  if (!value || !Number.isInteger(value.httpStatus) || value.httpStatus < 100 || value.httpStatus > 599 || !Object.hasOwn(value,'body') || (value.headers != null && (typeof value.headers !== 'object' || Array.isArray(value.headers)))) throw Error('Registry response unavailable.');
  return json(value.body, value.httpStatus, value.headers || {});
}
export async function registryResponse(storage, runner, op, input, legacy, options) {
  const value = await registryTransaction(storage, runner, op, input, legacy, options);
  return runner ? registryHttp(value) : value;
}
