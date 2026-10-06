// Immutable, explicitly consented device sets. A hostname is never an identity.
export const MAX_GRANT_DEVICES = 20;
export const validDeviceId = value => typeof value === 'string' && /^[a-f0-9]{32}$/.test(value);
export const validEpoch = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
export function deviceDescription(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  const result = {};
  for (const key of ['name', 'platform', 'arch', 'system']) {
    if (typeof value[key] === 'string' && value[key].length > 0 && value[key].length <= 128 && !/[\x00-\x1f\x7f]/.test(value[key])) result[key] = value[key];
  }
  return result;
}
export function checkedDevices(value) {
  if (!Array.isArray(value) || !value.length || value.length > MAX_GRANT_DEVICES) throw new Error('Invalid authorized device set.');
  const seen = new Set();
  return value.map(item => {
    if (!item || !validDeviceId(item.deviceId) || !validEpoch(item.epoch) || seen.has(item.deviceId)) throw new Error('Invalid or duplicate authorized device.');
    seen.add(item.deviceId);
    return { deviceId: item.deviceId, epoch: item.epoch, description: deviceDescription(item.description) };
  });
}
export function grantDevices(props) {
  if (!props || !Array.isArray(props.scopes)) throw new Error('Invalid device grant.');
  if (props.grantVersion === 2) {
    if (props.deviceId !== undefined || props.epoch !== undefined) throw new Error('Ambiguous device grant.');
    return checkedDevices(props.devices);
  }
  if (props.grantVersion !== undefined || props.devices !== undefined) throw new Error('Unsupported device grant version.');
  return checkedDevices([{ deviceId: props.deviceId, epoch: props.epoch }]);
}
export function selectDevice(devices, requestedId) {
  const checked = checkedDevices(devices);
  if (requestedId === undefined) {
    if (checked.length !== 1) throw new Error('More than one computer is authorized. Call list_devices, then specify deviceId; no computer was selected or contacted.');
    return checked[0];
  }
  if (!validDeviceId(requestedId)) throw new Error('Invalid target device ID.');
  const target = checked.find(item => item.deviceId === requestedId);
  if (!target) throw new Error('The requested computer is not included in this authorization.');
  return target;
}
export function bindingSignature(devices) {
  return JSON.stringify(checkedDevices(devices).map(item => [item.deviceId, item.epoch]).sort((a, b) => a[0].localeCompare(b[0])));
}
