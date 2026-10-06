import { randomUUID, createHash } from 'node:crypto';
import { rootWriteMode } from './permissions.mjs';

const uuid = value => typeof value === 'string' && /^[a-f0-9-]{36}$/.test(value);
const hash = value => createHash('sha256').update(value).digest('hex');
export function validGuide(value) {
  return value?.version === 1 && uuid(value.id) && uuid(value.rootId) && typeof value.startedAt === 'string';
}
export function newGuide(rootId, requestId = randomUUID()) {
  if (!uuid(rootId) || !uuid(requestId)) throw new Error('Invalid connection attempt.');
  return { version: 1, id: requestId, rootId, startedAt: new Date().toISOString(), evidence: {} };
}
export function guideProbe(guide) {
  if (!validGuide(guide)) return null;
  const created = `chat2local connection check\nrequest: ${guide.id}\nstage: created\n`;
  const updated = `chat2local connection check\nrequest: ${guide.id}\nstage: updated\n`;
  return { path: `chat2local-check-${guide.id}.txt`, created, updated, createdHash: hash(created), updatedHash: hash(updated) };
}

/** Called ONLY after a successful operation arriving through the device bridge.
 * Local FileService calls, proposals, UI clicks and status checks are not proof
 * that an external client can directly create, replace and read back a file.
 */
export function observeGuide(guide, name, args, result, identity, now = new Date().toISOString()) {
  if (!validGuide(guide) || !identity?.deviceId || !identity?.origin) return guide;
  const probe = guideProbe(guide);
  if (args?.rootId !== guide.rootId || args.path !== probe.path) return guide;
  const bound = guide.deviceId === identity.deviceId && guide.origin === identity.origin;
  const evidence = bound ? { ...guide.evidence } : {};
  let changed = false;
  if (name === 'write_file' && result?.status === 'written') {
    if (args.expectedHash === null && args.content === probe.created && result.sha256 === probe.createdHash) {
      evidence.createdAt = now; delete evidence.updatedAt; delete evidence.readBackAt; changed = true;
    } else if (evidence.createdAt && args.expectedHash === probe.createdHash && args.content === probe.updated && result.sha256 === probe.updatedHash && result.backupSaved === true) {
      evidence.updatedAt = now; delete evidence.readBackAt; changed = true;
    }
  }
  if (name === 'read_file' && evidence.createdAt && evidence.updatedAt && result?.sha256 === probe.updatedHash && result.content === probe.updated) {
    evidence.readBackAt = now; changed = true;
  }
  return changed ? { ...guide, evidence, deviceId: identity.deviceId, origin: identity.origin } : guide;
}

export function guideView(config, { device, bridge, setup, setupActive = false, warning = null, capabilities = null } = {}) {
  const guide = validGuide(config.connectionGuide) ? config.connectionGuide : null;
  const root = guide ? config.roots.find(item => item.id === guide.rootId) : null;
  const permitted = root && rootWriteMode(root) === 'direct';
  const bound = guide?.deviceId === device?.deviceId && guide?.origin === config.relay;
  const evidence = permitted && bound ? guide.evidence || {} : {};
  const complete = Boolean(evidence.createdAt && evidence.updatedAt && evidence.readBackAt);
  const online = bridge === 'connected';
  let stage;
  if (config.paused) stage = 'paused';
  else if (!permitted) stage = 'choose-folder';
  else if (complete) stage = online ? 'ready' : 'reconnecting';
  else if (device?.deviceId && config.remoteUseConfirmed && !online) stage = 'reconnecting';
  else if (setupActive) stage = 'connecting';
  else if (device?.deviceId && online && config.remoteUseConfirmed) stage = evidence.createdAt || capabilities?.mayAttemptWrite ? 'verify' : 'check-tools';
  else if (setup?.code === 'BROWSER_OPENED') stage = 'platform-consent';
  else stage = 'connect';
  return {
    stage, device, root: root ? { id: root.id, path: root.path, label: root.label, writeMode: rootWriteMode(root) } : null,
    attemptId: guide?.id || null, startedAt: guide?.startedAt || null,
    directoryGranted: Boolean(permitted), online, registered: Boolean(device?.deviceId),
    previousRemoteUse: config.remoteUseConfirmed === true, setupActive, setup: setup || {},
    evidence: { createdAt: evidence.createdAt || null, updatedAt: evidence.updatedAt || null, readBackAt: evidence.readBackAt || null },
    complete, warning, capabilities,
    toolCheckPrompt: permitted ? toolCheckPrompt(root, device) : '',
    // No automatic local write is used to turn this indicator green.
    verificationPrompt: permitted ? verificationPrompt(guide, root, device, evidence) : '',
  };
}
function toolCheckPrompt(root, device) {
  return `只检查现有 chat2local 的接入能力，不创建或修改文件。\n目标：${device?.name || '本机'}；deviceId：${device?.deviceId || '待核对'}；rootId：${root.id}。\n先列出当前会话实际提供的 chat2local 工具名，明确是否有 write_file、list_devices；不要把服务端声明当成当前会话已经加载。再用现有 list_roots 核对目标、目录权限和返回的 connectionDiagnostics（服务端工具目录及本次 OAuth scopes）。若未返回诊断字段，标记未知，不自行推定。分别报告服务端声明、ChatGPT连接保存/启用的工具（无法访问则未知）、当前会话工具、当前调用的 files:write 权限。保持目录授权和原插件不变，不改用 DevSpace 或 propose_write 写文件。`;
}
function verificationPrompt(guide, root, device, evidence) {
  const probe = guideProbe(guide);
  const phase = evidence.updatedAt ? '已观察到创建和修改，只需用 read_file 读回核对下面的最终内容。' : evidence.createdAt ? '已观察到创建；先读回检查当前内容，再完成修改和读回，不重复创建。' : '先用 list_roots 核对目标，再创建、修改并读回以下专用测试文件。';
  return `先确认当前会话实际提供 write_file；缺少时只报告工具缺失，不开始写入，也不更改目录授权。\n通过唯一的 chat2local 插件验证读写。\n目标电脑：${device?.name || '本机'}；deviceId：${device?.deviceId || '请从 list_devices 核对本机'}。\n目录：${root.label}；rootId：${root.id}。\n文件：${probe.path}\n${phase}\n创建内容（包含末尾换行）：\n${JSON.stringify(probe.created)}\n最终内容（包含末尾换行）：\n${JSON.stringify(probe.updated)}\n仅用 write_file（创建 expectedHash=null；修改使用 read_file 返回的当前哈希），再用 read_file 核对。仅修改上述专用文件；已存在时先读回，内容不匹配就停止，不覆盖。不要使用 DevSpace、终端或 propose_write 代替实际插件读写。不支持 write_file 或缺权限时报告原始阻塞，不重新创建插件、不改权限。`;
}
