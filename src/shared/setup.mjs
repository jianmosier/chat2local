// Public routing metadata only. Never put an operator or device secret here.
export const DEFAULT_RELAY = ''; // Each installation supplies its own instance; no author-hosted default.
export function installPage(value) {
  if (!value) return null;
  try {
    const url = new URL(value);
    if (url.origin !== 'https://chatgpt.com' || url.username || url.password || url.search || url.hash || !/^\/(?:plugins|apps)\/[A-Za-z0-9_-]+\/?$/.test(url.pathname)) return null;
    return url.href;
  } catch { return null; }
}
export function oauthCallbackOrigin(value) {
  const url = new URL(value);
  if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password || !/^(?:[a-z0-9.-]+|\[[a-f0-9:.]+\])$/i.test(url.hostname)) throw new Error('Unsafe OAuth callback origin.');
  return url.origin;
}
export function setupAvailability({ installUrl, selfService, alreadyEnrolled = false, developerHandoff = false, customConnector = false }) {
  // Public installation and owner-operated developer testing are distinct paths.
  // This exception never registers a device or grants access: the device must
  // already possess an identity and prove it to the relay before browser binding.
  if (!installPage(installUrl) && alreadyEnrolled && developerHandoff === true) return { ready: true, code: 'DEVELOPER_READY', mode: 'developer', message: '可以为已注册的这台电脑完成自动配对；随后回到你已打开的 ChatGPT 授权页确认。无需输入配对码。' };
  if (!installPage(installUrl) && customConnector === true) {
    if (!alreadyEnrolled && selfService !== true) return { ready: false, code: 'REGISTRATION_CLOSED', message: '维护者尚未开放新电脑接入；不需要填写管理员密钥。' };
    return { ready: true, code: 'CUSTOM_READY', mode: 'custom', message: '本服务支持自定义 MCP 接入，无需等待目录上架。完成本机绑定后，在 ChatGPT 添加服务给出的连接地址并确认授权。' };
  }
  if (!installPage(installUrl)) return { ready: false, code: 'PUBLICATION_REQUIRED', message: '公开安装尚未就绪。开发实连测试需要维护者先注册这台电脑；这不是等待上架才能测试，也不需要你填写密钥或配对码。' };
  if (!alreadyEnrolled && selfService !== true) return { ready: false, code: 'REGISTRATION_CLOSED', message: '连接服务尚未开放新设备注册。请稍后重试，不需要索取管理员邀请。' };
  return { ready: true, code: 'READY', message: '可以继续到官方页面确认连接。' };
}
