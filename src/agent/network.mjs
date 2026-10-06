import http from 'node:http';
import { isIP } from 'node:net';
import { powershell } from './store.mjs';
import { relayOrigin } from '../shared/protocol.mjs';
import { selectProxyTlsProfile, installRelayTlsProfile } from './tls-profile.mjs';

const LOCAL_BYPASS = ['127.0.0.1', 'localhost', '::1', '[::1]'];
const PROXY_KEYS = ['HTTP_PROXY', 'http_proxy', 'HTTPS_PROXY', 'https_proxy', 'ALL_PROXY', 'all_proxy'];
const DIRECT = { HTTP_PROXY: '', http_proxy: '', HTTPS_PROXY: '', https_proxy: '', NO_PROXY: '*', no_proxy: '*' };
const localHost = host => ['localhost', '[::1]'].includes(host) || (isIP(host) === 4 && host.startsWith('127.'));
const envValue = (source, lower, upper) => typeof source[lower] === 'string' ? source[lower] : (source[upper] ?? '');

/** Validate without ever including a supplied proxy URL or its password in errors. */
export function proxyUrl(input, allowCredentials = false) {
  if (typeof input !== 'string' || !input || input.length > 2048) throw new Error('请输入完整的 HTTP 或 HTTPS 代理地址。');
  let url;
  try { url = new URL(input); } catch { throw new Error('代理地址格式不正确，请使用 http://主机:端口。'); }
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('当前支持 HTTP／HTTPS 代理；SOCKS 请使用代理软件提供的 HTTP 或 mixed 端口。');
  if (url.pathname !== '/' || url.search || url.hash || (!allowCredentials && (url.username || url.password))) throw new Error('代理地址不能含路径、查询参数或账号密码；认证代理可由受控环境变量配置。');
  return url.origin === 'null' ? input : url.href.replace(/\/$/, '');
}
export function networkSettings(value = { mode: 'auto' }) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => !['mode', 'proxy'].includes(key)) || !['auto', 'direct', 'proxy'].includes(value.mode)) throw new Error('请选择自动、直连或指定代理。');
  return value.mode === 'proxy' ? { mode: 'proxy', proxy: proxyUrl(value.proxy) } : { mode: value.mode };
}
function bypass(source = {}) {
  // Preserve the runtime's lowercase precedence; never shrink an explicit bypass list.
  const entries = new Set(String(envValue(source, 'no_proxy', 'NO_PROXY')).split(/[\s,]+/).filter(Boolean));
  for (const host of LOCAL_BYPASS) entries.add(host);
  return [...entries].join(',');
}
function proxyEnvironment(httpProxy, httpsProxy, noProxy) {
  return { HTTP_PROXY: httpProxy, http_proxy: httpProxy, HTTPS_PROXY: httpsProxy, https_proxy: httpsProxy, NO_PROXY: noProxy, no_proxy: noProxy };
}

/** Query the current Windows user's proxy decision for THIS relay, including
 * system bypass/PAC decisions. Never changes the registry, VPN, DNS or TLS. */
export async function windowsProxyFor(origin, options = {}) {
  if ((options.platform ?? process.platform) !== 'win32') return { proxy: '', source: 'system-direct' };
  const script = "$ErrorActionPreference='Stop'; $u=[Uri]([Console]::In.ReadToEnd()); $p=[Net.WebRequest]::GetSystemWebProxy(); $r=$p.GetProxy($u); if($null -eq $r -or $r.AbsoluteUri -eq $u.AbsoluteUri){@{proxy='';source='system-direct'}|ConvertTo-Json -Compress}else{@{proxy=$r.AbsoluteUri;source='system-proxy'}|ConvertTo-Json -Compress}";
  try {
    const result = JSON.parse(await (options.execute ?? powershell)(script, origin, 8000));
    if (typeof result.proxy !== 'string') throw new Error('Invalid proxy decision.');
    return { proxy: result.proxy ? proxyUrl(result.proxy, true) : '', source: result.proxy ? 'system-proxy' : 'system-direct' };
  } catch { throw new Error('无法读取系统代理，请检查网络设置，或在本面板选择直连／指定代理。不会静默改为直连。'); }
}

/** Resolve policy, not geographic location. The TUN/VPN routing layer is left
 * to the OS; a browser-only extension is not treated as a machine proxy. */
export async function resolveNetwork(settings, origin, options = {}) {
  settings = networkSettings(settings);
  origin = relayOrigin(origin, options.allowLocal === true);
  if (localHost(new URL(origin).hostname)) return { environment: { ...DIRECT }, source: 'loopback', mode: settings.mode };
  if (settings.mode === 'direct') return { environment: { ...DIRECT }, source: 'direct', mode: settings.mode };
  if (settings.mode === 'proxy') return { environment: proxyEnvironment(settings.proxy, settings.proxy, bypass()), source: 'manual-proxy', mode: settings.mode };
  const source = options.env ?? process.env;
  // Explicit environment configuration wins over the system; failure does not
  // automatically fall through to a different proxy or a direct connection.
  if (PROXY_KEYS.some(key => typeof source[key] === 'string' && source[key].length > 0)) {
    const all = envValue(source, 'all_proxy', 'ALL_PROXY');
    const rawHttp = envValue(source, 'http_proxy', 'HTTP_PROXY') || all;
    const rawHttps = envValue(source, 'https_proxy', 'HTTPS_PROXY') || rawHttp || all;
    // Resolve only the target protocol. An unused SOCKS ALL_PROXY must not
    // invalidate an explicit HTTPS HTTP-proxy setting for this HTTPS relay.
    const selected = new URL(origin).protocol === 'https:' ? rawHttps : rawHttp;
    const proxy = selected ? proxyUrl(selected, true) : '';
    return { environment: proxyEnvironment(proxy, proxy, bypass(source)), source: 'environment', mode: 'auto' };
  }
  const decision = await (options.systemProxy ?? windowsProxyFor)(origin);
  const proxy = decision.proxy ? proxyUrl(decision.proxy, true) : '';
  return { environment: proxy ? proxyEnvironment(proxy, proxy, bypass(source)) : { ...DIRECT }, source: proxy ? 'system-proxy' : 'system-direct', mode: 'auto' };
}

export function applyNetwork(environment) {
  if (typeof http.setGlobalProxyFromEnv !== 'function') throw new Error('网络自动适配需要 Node.js 24.14 或更新版本，请使用项目提供的免安装包。');
  // Use a dedicated explicit object, never mutate process.env or global OS settings.
  return http.setGlobalProxyFromEnv(environment);
}
export function localNetworkOnly() { return applyNetwork({ ...DIRECT }); }

/** One network manager per running desktop controller. The app has one relay.
 * Change routing only before a new connection; no mutation/request is replayed. */
export class NetworkManager {
  constructor(getSettings, options = {}) {
    this.getSettings = getSettings;
    this.options = options;
    this.state = { mode: 'auto', source: 'not-checked', error: null };
    this.applied = ''; this.checked = 0; this.revision = 0; this.closed = false;
  }
  async prepare(origin, force = false) {
    if (this.closed) throw new Error('网络管理器已关闭。');
    const settings = networkSettings(this.getSettings() ?? { mode: 'auto' });
    const key = JSON.stringify([settings, origin]);
    if (!force && this.key === key && Date.now() - this.checked < 30_000) return this.status();
    const revision = ++this.revision;
    try {
      const plan = await resolveNetwork(settings, origin, this.options);
      if (this.closed || revision !== this.revision) throw new Error('网络检测已被新设置替代，请重新连接。');
      if (JSON.stringify(networkSettings(this.getSettings() ?? { mode: 'auto' })) !== JSON.stringify(settings)) throw new Error('网络设置已变化，请重新连接。');
      const fingerprint = JSON.stringify(plan.environment);
      if (fingerprint !== this.applied) {
        // Restore the previous layer before replacement to avoid accumulating dispatchers.
        this.restore?.(); this.restore = undefined;
        this.restore = (this.options.apply ?? applyNetwork)(plan.environment);
        this.applied = fingerprint;
      }
      const tlsKey = JSON.stringify([origin, fingerprint]);
      if (this.tlsKey !== tlsKey) {
        this.restoreTls?.(); this.restoreTls = undefined; this.tlsKey = undefined;
        const usingProxy = Boolean(plan.environment.HTTPS_PROXY) && new URL(origin).protocol === 'https:';
        const profile = usingProxy ? await (this.options.selectTls ?? selectProxyTlsProfile)(origin) : 'default';
        if (this.closed || revision !== this.revision || JSON.stringify(networkSettings(this.getSettings() ?? { mode: 'auto' })) !== JSON.stringify(settings)) throw new Error('网络设置已变化，请重新连接。');
        this.restoreTls = (this.options.installTls ?? installRelayTlsProfile)(origin, profile);
        this.tlsProfile = profile; this.tlsKey = tlsKey;
      }
      this.key = key; this.checked = Date.now();
      this.state = { mode: settings.mode, source: plan.source, tlsProfile: this.tlsProfile, error: null };
      return this.status();
    } catch (error) {
      if (revision === this.revision) {
        this.key = undefined;
        this.state = { mode: settings.mode, source: 'error', error: error.message };
      }
      throw error;
    }
  }
  status() { return { ...this.state }; }
  close() { this.closed = true; this.revision++; this.restoreTls?.(); this.restoreTls = undefined; this.tlsKey = undefined; this.restore?.(); this.restore = undefined; this.applied = ''; this.key = undefined; }
}

/** Compatibility helper for subprocesses. It only inherits configured proxies;
 * Windows proxy resolution takes place inside the controller, not at install. */
export function childNetworkEnvironment(source = process.env) {
  const noProxy = bypass(source);
  // The controller resolves policy explicitly before remote traffic. Do not
  // activate a possibly invalid inherited proxy before its local panel boots.
  return { ...source, NODE_USE_ENV_PROXY: '0', NO_PROXY: noProxy, no_proxy: noProxy };
}
