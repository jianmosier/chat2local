import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { randomSecret, relayOrigin, readLimited } from '../shared/protocol.mjs';
import { DEFAULT_RELAY, setupAvailability, installPage } from '../shared/setup.mjs';

async function beforeDeadline(work, signal) {
  signal.throwIfAborted();
  return new Promise((resolve, reject) => {
    const abort = () => reject(signal.reason);
    signal.addEventListener('abort', abort, { once: true });
    Promise.resolve(work).then(resolve, reject).finally(() => signal.removeEventListener('abort', abort));
  });
}

/** Native setup authority. The browser never receives device/operator credentials. */
export class SetupManager {
  constructor(options) { this.options = options; this.info = { ready: false, code: 'NOT_CHECKED', message: '连接前将检查官方安装入口。' }; }
  origin() { const selected = this.options.identity()?.origin || this.options.defaultRelay || DEFAULT_RELAY; return selected ? relayOrigin(selected, this.options.allowLocal === true) : ''; }
  cancel() { this.active?.abort(Object.assign(new Error('连接已取消；已有目录权限保持不变。'), { status: 409 })); }
  async request(route, body, key, parentSignal) {
    const origin = this.origin();
    if (!origin) throw Object.assign(new Error('No private instance is configured.'), { code: 'INSTANCE_REQUIRED' });
    // The deadline includes proxy resolution, not only the later HTTP request.
    // A delayed resolver cannot send credentials after the attempt has expired.
    const timeout = AbortSignal.timeout(this.options.requestTimeoutMs ?? 16_000);
    const signal = parentSignal ? AbortSignal.any([timeout, parentSignal]) : timeout;
    signal.throwIfAborted();
    await beforeDeadline(this.options.prepareNetwork(origin), signal);
    signal.throwIfAborted();
    const response = await beforeDeadline((this.options.fetch ?? fetch)(`${origin}${route}`, { method: body === undefined ? 'GET' : 'POST', headers: { ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...(key ? { Authorization: `Bearer ${key}` } : {}) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }), redirect: 'error', signal }), signal);
    return response;
  }
  async inspect(signal) {
    try {
      if (!this.origin()) { this.info = { ready: false, code: 'INSTANCE_REQUIRED', message: '请使用自己实例提供的安装入口，或运行自托管配置向导。程序不会默认连接作者的服务。' }; return this.info; }
      const response = await this.request('/setup-info', undefined, undefined, signal);
      signal?.throwIfAborted();
      if (response.status === 404) { this.info = { ready: false, code: 'RELAY_UPDATE_REQUIRED', message: '本地程序已更新，但线上连接服务仍是旧版本。需要维护者同步部署；不用寻找或填写配对码。' }; return this.info; }
      if (!response.ok) throw new Error('unavailable');
      const info = JSON.parse(await readLimited(response, 8192));
      signal?.throwIfAborted();
      if (info.name !== 'chat2local-relay') throw new Error('wrong service');
      if (info.setupVersion !== 1 || info.browserHandoff !== true) { this.info = { ready: false, code: 'RELAY_UPDATE_REQUIRED', message: '本机与线上服务的配对协议不一致，需要维护者同步版本。没有注册设备或发送配对凭据。' }; return this.info; }
      if (info.accountConnections === true) {
        this.info = info.accountLoginConfigured === true
          ? { ready: false, code: 'ACCOUNT_SIGN_IN', message: '使用原账号连接这台电脑，选择目录后只确认一次。', accountEntryUrl: this.origin() + '/account/add' }
          : { ready: false, code: 'ACCOUNT_CONFIGURATION_REQUIRED', message: '项目的账号登录入口尚未由维护者配置。无需输入密钥或重新授权目录。' };
        return this.info;
      }
      this.info = { ...setupAvailability({ ...info, alreadyEnrolled: Boolean(this.options.identity()) }), installUrl: installPage(info.installUrl) };
    } catch (error) { signal?.throwIfAborted(); this.info = { ready: false, code: 'SERVICE_UNREACHABLE', message: '暂时无法连接服务。软件会使用已有网络配置；请稍后重试，不需要填写邀请或密钥。' }; }
    return this.info;
  }
  async start({ onHandoff, allowEnrollment = true } = {}) {
    if (!allowEnrollment && !this.options.identity()) throw Object.assign(new Error('请先通过本机主向导连接设备。此恢复入口不会注册新电脑。'), { status: 409 });
    if (this.active) throw Object.assign(new Error('连接正在处理中；不会重复注册或打开配对页。'), { status: 409 });
    const controller = new AbortController(); this.active = controller;
    try { return await this.run(controller.signal, onHandoff, allowEnrollment); }
    catch (error) {
      if (controller.signal.aborted) this.info = { ready: false, code: 'CANCELLED', message: '连接已取消；已有目录权限保持不变。' };
      throw error;
    } finally { if (this.active === controller) this.active = undefined; }
  }
  async run(signal, onHandoff, allowEnrollment = true) {
    const info = await this.inspect(signal);
    signal.throwIfAborted();
    if (!info.ready) return { ok: false, ...info, websiteClientVerified: false };
    let identity = this.options.identity();
    if (!identity) {
      if (!allowEnrollment) throw new Error('原设备身份已变化，没有注册新电脑。');
      // Persist before first enrollment: an uncertain response must not create a second device.
      identity = this.options.pending() || { origin: this.origin(), deviceId: randomUUID().replaceAll('-', ''), deviceKey: randomSecret() };
      if (identity.origin !== this.origin() || !/^[a-f0-9]{32}$/.test(identity.deviceId) || !/^[a-f0-9]{64}$/.test(identity.deviceKey)) throw new Error('待恢复的设备注册不匹配，请联系维护者；未覆盖任何凭据。');
      await this.options.savePending(identity, signal);
      signal.throwIfAborted();
      const response = await this.request('/enroll-device', { deviceId: identity.deviceId, deviceKey: identity.deviceKey }, undefined, signal);
      if (!response.ok) throw new Error(response.status === 429 ? '服务当前的新设备名额已满，请稍后重试。' : '设备注册尚未确认。已保存本机身份，再次连接不会重复创建身份。');
      const result = JSON.parse(await readLimited(response, 4096));
      if (result.ok !== true) throw new Error('设备注册响应不正确；未标记成功。');
      signal.throwIfAborted();
      await this.options.acceptIdentity(identity, signal);
    }
    signal.throwIfAborted();
    const bridge = this.options.bridge;
    if (bridge.state !== 'connected') bridge.start(identity);
    const until = Date.now() + 10_000;
    while (bridge.state !== 'connected' && Date.now() < until) await delay(80, undefined, { signal });
    signal.throwIfAborted();
    if (bridge.state !== 'connected') throw new Error('电脑正在连接服务，请稍后再次点击连接；不会重复注册。');
    const response = await this.request(`/device/${identity.deviceId}/browser-handoff`, {}, identity.deviceKey, signal);
    if (!response.ok) throw new Error('暂时无法打开授权流程，请稍后重试。');
    const handoff = JSON.parse(await readLimited(response, 4096));
    if (!/^[a-f0-9]{64}$/.test(handoff.secret) || handoff.expiresAt <= Date.now()) throw new Error('授权链接无效；未打开浏览器。');
    // Fragment, not query: no credential is sent in a URL request or referer.
    // User confirms browser binding, then the relay sends them to the real official listing.
    signal.throwIfAborted();
    await (onHandoff || this.options.openBrowser)(`${identity.origin}/link#${identity.deviceId}.${handoff.secret}`);
    signal.throwIfAborted();
    this.info = { ...this.info, code: 'BROWSER_OPENED', message: '已打开本机配对确认页。确认后回到同一浏览器中的 ChatGPT 授权页，完成权限确认。无需配对码；这一步还不是文件调用成功。' };
    return { ok: true, stage: 'browser-opened', websiteClientVerified: false, message: this.info.message };
  }
}
