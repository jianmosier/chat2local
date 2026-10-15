import fs from 'node:fs/promises';
import path from 'node:path';
import { platformInfo } from '../platform.mjs';
import { approveRoot } from '../files.mjs';
import { rootWriteMode } from '../permissions.mjs';
import { browseFolders } from '../folder-browser.mjs';
import { recoveryNavigation, recoveryPage, recoveryScript } from '../browser-recovery.mjs';
import { TERMINAL_CONFIRMATION } from '../terminal.mjs';
import { bodyJson, boolean, failure, fields, matchesSecret, securityHeaders, selectedPermission } from '../controller-http.mjs';
import { uiAsset } from '../ui-assets.mjs';
import { authorizationReturn } from '../../shared/authorization-navigation.mjs';
import { terminalPermission } from '../../shared/terminal-permission.mjs';

/** Loopback HTTP routing only; controller state and services remain injected. */
export function createHttpRouter({
  state, getOrigin, token, store, uiDir, setup, picker, recovery, recoveryBinding,
  accountOnboarding, instanceOnboarding, managementSessions, folderManagement, shareRemoval,
  status, connectionState, existingRoot, changePolicy, serial, mutate,
}) {
  return (request, response) => {
    const origin = getOrigin();
    const send = (code, data, type = 'application/json', extraHeaders = {}) => {
      if (response.destroyed || response.writableEnded) return;
      response.writeHead(code, { ...securityHeaders, 'Content-Type': `${type}; charset=utf-8`, ...extraHeaders });
      response.end(type === 'application/json' ? JSON.stringify(data) : data);
    };
    void (async () => {
      if (state.closing) throw failure(503, 'Controller is closing.');
      if (request.headers.host !== new URL(origin).host) throw failure(403, 'Invalid Host.');
      if (request.headers.origin && request.headers.origin !== origin) throw failure(403, 'Invalid Origin.');
      const accountNavigation = request.method === 'GET' && ['/account-connect', '/instance-connect'].includes(request.url)
        && request.headers['sec-fetch-mode'] === 'navigate' && request.headers['sec-fetch-dest'] === 'document';
      if (request.headers['sec-fetch-site'] === 'cross-site' && !recoveryNavigation(request) && !accountNavigation) {
        throw failure(403, 'Cross-site access is not allowed.');
      }
      if (!request.url?.startsWith('/') || request.url.startsWith('//') || request.url.includes('?')) throw failure(400, 'Invalid request target.');
      const route = request.url;
      if (['/account-connect', '/instance-connect'].includes(route) && request.method === 'GET') {
        if (request.headers['sec-fetch-dest'] && request.headers['sec-fetch-dest'] !== 'document') throw failure(403, 'Top-level page required.');
        const privateMode = route === '/instance-connect';
        const adapter = privateMode ? instanceOnboarding : accountOnboarding;
        const nonce = adapter.pageSession(request);
        let page = (await fs.readFile(path.join(uiDir, 'account-connect.html'), 'utf8')).replace('{{NONCE}}', nonce);
        if (privateMode) page = page.replace('/account-connect.js', '/instance-connect.js').replace('<dt>账号</dt>', '<dt>私人实例</dt>')
          .replace('登录验证与平台自身的确认不由本程序跳过。', '不需要第三方账号登录；平台自身的确认仍由平台处理。');
        send(200, page, 'text/html', { 'Set-Cookie': `c2l_${adapter.profile}_local=${nonce}; HttpOnly; SameSite=Strict; Path=${route}; Max-Age=86400` });
        return;
      }
      if (['/account-connect.js', '/instance-connect.js'].includes(route) && request.method === 'GET') {
        send(200, await fs.readFile(path.join(uiDir, 'account-connect.js'), 'utf8'), 'text/javascript');
        return;
      }
      if (route.startsWith('/account-connect/') || route.startsWith('/instance-connect/')) {
        if (request.method !== 'POST' || request.headers.origin !== origin) throw failure(403, 'Same-origin onboarding operation required.');
        const value = await bodyJson(request);
        const adapter = route.startsWith('/instance-connect/') ? instanceOnboarding : accountOnboarding;
        send(200, await adapter.handle(route.slice(route.indexOf('/', 1) + 1), value, request.headers.cookie));
        return;
      }
      if (route === '/connect' && request.method === 'GET') {
        if (request.headers['sec-fetch-dest'] && request.headers['sec-fetch-dest'] !== 'document') throw failure(403, 'Top-level page required.');
        const available = Boolean(state.secrets.identity && state.config.roots.length && !state.config.paused);
        const nonce = recovery.issue(recoveryBinding());
        const reason = state.config.paused ? '本机访问已暂停。请在原向导恢复访问后再继续。'
          : '请先启动 chat2local 主向导并选择文件夹；不会自动登记设备或开放目录。';
        send(200, recoveryPage({ token: nonce, name: platformInfo().name, available, reason, relay: setup.origin() }),
          'text/html', { 'Set-Cookie': `c2l_recovery=${nonce}; HttpOnly; SameSite=Strict; Path=/connect; Max-Age=300` });
        return;
      }
      if (route === '/recovery.js' && request.method === 'GET') { send(200, recoveryScript, 'text/javascript'); return; }
      if (route === '/connect/continue') {
        if (request.method !== 'POST') throw failure(405, 'POST required.');
        if (request.headers.origin !== origin) throw failure(403, 'Same-origin confirmation required.');
        const value = await bodyJson(request);
        fields(value, ['nonce', 'confirm', 'returnUrl']);
        if (value.confirm !== true || !state.secrets.identity || !state.config.roots.length || state.config.paused) {
          throw failure(409, '请先在本机主向导完成连接；没有修改任何权限。');
        }
        authorizationReturn(value.returnUrl, state.secrets.identity.origin);
        recovery.consume(value.nonce, request.headers.cookie, recoveryBinding());
        if (setup.active) throw failure(409, '连接正在进行，不重复打开授权页。');
        const binding = recoveryBinding();
        let handoff;
        const work = setup.start({ allowEnrollment: false, onHandoff: async url => {
          if (state.closing || state.config.paused || recoveryBinding() !== binding) throw failure(409, '本机状态已变化，连接已取消。');
          handoff = url;
        } });
        const attempt = setup.active;
        const onClose = () => { if (!response.writableEnded && setup.active === attempt) setup.cancel(); };
        response.once('close', onClose);
        try {
          const result = await work;
          if (result.ok && (!handoff || state.closing || state.config.paused || recoveryBinding() !== binding)) throw failure(409, '连接已取消。');
          send(200, result.ok ? { ok: true, url: handoff } : result);
        } finally { response.removeListener('close', onClose); }
        return;
      }
      if (route.startsWith('/api/')) {
        const launcherAuthenticated = matchesSecret(request.headers['x-chat2local-token'], token);
        if (!launcherAuthenticated && !await managementSessions.accepts(request)) {
          throw failure(401, 'Local control session required. Open the installed Chat2Local launcher.');
        }
        if (route === '/api/status' && request.method === 'GET') { send(200, status()); return; }
        if (route === '/api/guide' && request.method === 'GET') { send(200, connectionState()); return; }
        if (request.method !== 'POST') throw failure(405, 'POST required.');
        if (request.headers.origin !== origin) throw failure(403, 'Same-origin confirmation required.');
        const value = await bodyJson(request);
        if (route === '/api/management/session') {
          fields(value, []);
          const session = await managementSessions.establish(request.headers.cookie, launcherAuthenticated);
          send(200, { ready: true, expiresAt: session.expiresAt }, 'application/json', { 'Set-Cookie': session.cookie });
          return;
        }
        if (route === '/api/management/startup') {
          fields(value, ['enabled']); boolean(value.enabled);
          send(200, await serial(() => mutate('startup', value)));
          return;
        }
        if (route === '/api/management/logout') {
          fields(value, []);
          send(200, { cleared: true }, 'application/json', { 'Set-Cookie': await managementSessions.logout(request.headers.cookie) });
          return;
        }
        if (route === '/api/terminal/permissions') {
          fields(value, []);
          const { connections } = await folderManagement.connections();
          send(200, { connections: connections.map(connection => ({ ...connection, roots: connection.roots.map(root => ({
            ...root, ...terminalPermission({ grants: state.config.terminalGrants, connectionId: connection.connectionId,
              resource: state.secrets.identity.origin + '/mcp', rootId: root.rootId, mode: root.mode,
              scopes: connection.scopes, available: root.locallyPresent }),
          })) })), sandboxed: false });
          return;
        }
        if (route === '/api/terminal/set-permission') {
          fields(value, ['connectionId', 'rootId', 'enabled', 'confirmation']); boolean(value.enabled);
          if (value.enabled && value.confirmation !== TERMINAL_CONFIRMATION) {
            throw failure(400, '请明确确认：终端以当前系统用户权限运行，不是目录沙箱；可能修改或删除目录外文件和访问网络。');
          }
          const { connections } = await folderManagement.connections();
          const selected = connections.find(connection => connection.connectionId === value.connectionId);
          const root = selected?.roots.find(item => item.rootId === value.rootId && item.locallyPresent);
          if (!root || (value.enabled && root.mode !== 'direct')) throw failure(403, '只有原连接内允许直接读写的本机目录可以启用终端。');
          await serial(async () => {
            if (state.config.paused) throw failure(409, '本机访问已暂停。');
            const local = [...state.config.roots, ...(state.config.accountRoots || [])].find(item => item.id === value.rootId);
            if (!local || (value.enabled && rootWriteMode(local) !== 'direct')) throw failure(409, '目录权限已变化。');
            const grants = (state.config.terminalGrants || []).filter(grant => !(grant.connectionId === value.connectionId && grant.rootId === value.rootId));
            if (value.enabled) grants.push({ connectionId: value.connectionId, rootId: value.rootId, resource: state.secrets.identity.origin + '/mcp', enabled: true });
            await changePolicy({ ...state.config, terminalGrants: grants });
          });
          send(200, { saved: true, enabled: value.enabled, oauthScopeGranted: selected.scopes.includes('terminal:execute'), sandboxed: false });
          return;
        }
        if (['/api/shares/remove-prepare', '/api/shares/remove-confirm', '/api/shares/removals'].includes(route)) {
          send(200, await shareRemoval.execute(route.slice('/api/shares/'.length), value)); return;
        }
        if (route.startsWith('/api/shares/')) {
          send(200, await folderManagement.execute(route.slice('/api/shares/'.length), value)); return;
        }
        if (route === '/api/setup/inspect') { fields(value, []); send(200, await setup.inspect()); return; }
        if (route === '/api/setup/start') {
          fields(value, []);
          if (setup.active) throw failure(409, '连接正在处理中；不会重复注册或打开配对页。');
          const work = mutate('setup/start', value);
          const attempt = setup.active;
          const onClose = () => { if (!response.writableEnded && attempt && setup.active === attempt) setup.cancel(); };
          response.once('close', onClose);
          try { send(200, await work); }
          finally { response.removeListener('close', onClose); }
          return;
        }
        if (route === '/api/folder/browse') {
          fields(value, ['path']);
          if (value.path !== undefined && typeof value.path !== 'string') throw failure(400, '目录路径必须是文字。');
          if (state.browsing >= 2) throw failure(429, '目录列表正在加载，请稍候。');
          state.browsing++;
          try {
            const page = await browseFolders(value.path, store.directory);
            const existing = page.selectable ? await existingRoot(page.path) : null;
            send(200, { ...page, existingRoot: existing ? { id: existing.id, writeMode: rootWriteMode(existing), label: existing.label } : null });
          } finally { state.browsing--; }
          return;
        }
        if (route === '/api/pick-folder' || route === '/api/folder/select') {
          // Human waits stay outside the shared policy queue.
          const add = route === '/api/folder/select';
          fields(value, add ? ['write', 'writeMode', 'confirmDirect'] : []);
          if (add) selectedPermission(value);
          if (state.config.paused) throw failure(409, '本机访问已暂停，请恢复访问后再添加目录。');
          const revision = state.selectionRevision;
          const abort = new AbortController();
          const onClose = () => { if (!response.writableEnded) abort.abort(); };
          const expired = () => abort.signal.aborted || state.closing || state.config.paused || revision !== state.selectionRevision;
          response.once('close', onClose);
          try {
            const selected = await picker.run({ signal: abort.signal });
            if (selected.cancelled || expired()) { send(200, add ? { cancelled: true, expired: selected.expired } : { path: null }); return; }
            if (!add) { send(200, { path: selected.path }); return; }
            const root = await serial(async () => {
              if (expired()) return { cancelled: true };
              const permission = selectedPermission(value);
              const checked = await approveRoot(selected.path, store.directory, permission.write);
              const existing = await existingRoot(checked.path);
              if (existing) return { ...existing, writeMode: rootWriteMode(existing), alreadyAuthorized: true };
              if (expired()) return { cancelled: true };
              return mutate('root/add', { ...value, path: checked.path });
            });
            send(200, root);
          } finally { response.removeListener('close', onClose); }
          return;
        }
        send(200, await serial(() => mutate(route.slice(5), value)));
        return;
      }
      if (request.method !== 'GET') throw failure(405, 'GET required.');
      const asset = uiAsset(route);
      if (!asset) throw failure(404, 'Not found.');
      send(200, await fs.readFile(asset[0], 'utf8'), asset[1]);
    })().catch(error => send(error.status ?? 400, { error: error.code ? `Local operation failed (${error.code}).` : error.message }));
  };
}
