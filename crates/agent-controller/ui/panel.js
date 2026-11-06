'use strict';
(() => {
  const incoming = location.hash.slice(1);
  history.replaceState(null, '', location.pathname);
  const storageKey = 'chat2local.native.launcher';
  let token = /^[a-f0-9]{64}$/.test(incoming) ? incoming : '';
  try { if (token) sessionStorage.setItem(storageKey, token); else token = sessionStorage.getItem(storageKey) || ''; } catch { /* Browser storage may be disabled; the current page still works. */ }
  const el = id => document.getElementById(id);
  const bridgeLabels = new Map([['not-configured', '尚未配置连接'], ['connecting', '正在连接'], ['connected', '已连接'], ['reconnecting', '正在重新连接'], ['disconnected', '已断开'], ['failed', '连接发生故障'], ['unavailable', '当前连接不可用']]);
  const guideLabels = new Map([['choose-folder', '请选择并明确授权目录'], ['connect', '目录已保存，等待连接'], ['check-tools', '请检查当前会话工具与权限'], ['verify', '等待远程真实读写验证'], ['ready', '已完成远程读写验证'], ['reconnecting', '正在恢复已有连接'], ['paused', '访问已暂停']]);
  let state, guide, busy = false, pendingGuide;
  const say = text => { el('message').textContent = text; };
  async function api(route, body) {
    const response = await fetch('/api/' + route, { method: body === undefined ? 'GET' : 'POST', credentials: 'omit', cache: 'no-store', headers: { 'X-Chat2Local-Token': token, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    const result = await response.json();
    if (response.status === 401) { token = ''; try { sessionStorage.removeItem(storageKey); } catch {} el('controls').hidden = true; el('session-required').hidden = false; }
    if (!response.ok) throw Error(result.error || '本机请求失败');
    return result;
  }
  async function action(work) {
    if (busy) return;
    busy = true; say(''); el('controls').setAttribute('aria-busy', 'true');
    for (const button of el('controls').querySelectorAll('button')) button.disabled = true;
    try { await work(); await refresh(); } catch (error) { try { if (token) await refresh(); } catch {} say(error.message + '。请核对当前状态；未自动重复提交。'); } finally { busy = false; el('controls').setAttribute('aria-busy', 'false'); for (const button of el('controls').querySelectorAll('button')) button.disabled = false; el('pause').disabled = Boolean(state?.nativeFault); el('save-startup').disabled = !state?.startupAvailable; }
  }
  function button(text, handler) { const b = document.createElement('button'); b.type = 'button'; b.textContent = text; b.disabled = busy; b.addEventListener('click', () => action(handler)); return b; }
  function modes(selected) { const select = document.createElement('select'); for (const [value, label] of [['read-only', '只读'], ['review', '逐次审批'], ['direct', '直接读写']]) { const option = document.createElement('option'); option.value = value; option.textContent = label; select.append(option); } select.value = selected; select.setAttribute('aria-label', '目录权限'); return select; }
  async function refresh() {
    state = await api('status');
    el('connection').textContent = state.nativeFault ? '原生 Agent 已进入永久故障状态，请正常退出并重新启动。当前页面仍可限制或移除授权。' + (state.lifecycleWarning ? ' ' + state.lifecycleWarning : '') : state.paused ? '远程访问已暂停' : '远程连接：' + (bridgeLabels.get(state.bridge) || '待确认');
    el('pause').textContent = state.nativeFault ? '远程访问已停止' : state.paused ? '恢复远程访问' : '暂停远程访问';
    el('pause').disabled = busy || Boolean(state.nativeFault);
    el('startup').checked = Boolean(state.startup); el('save-startup').disabled = !state.startupAvailable;
    el('startup-note').textContent = state.startupAvailable ? '仅管理本原生程序的启动项，不改动已有 JS 启动项。' : '自定义状态目录或当前系统不支持原生启动项。';
    el('roots').replaceChildren();
    for (const root of state.roots) {
      const row = document.createElement('div'); row.className = 'root'; row.dataset.rootId = root.id;
      const title = document.createElement('strong'); title.textContent = root.label;
      const path = document.createElement('p'); path.className = 'path'; path.textContent = root.path;
      const select = modes(root.writeMode); const label = document.createElement('label'); label.className = 'check'; const confirm = document.createElement('input'); confirm.type = 'checkbox'; label.append(confirm, document.createTextNode('确认直接读写（选择直接读写时需要）'));
      row.append(title, path, select, label, button('保存权限', async () => { const result = await api('root/set-mode', { id: root.id, expectedWriteMode: root.writeMode, writeMode: select.value, confirmDirect: confirm.checked }); if (result.warning) say(result.warning); }), document.createTextNode(' '), button('移除授权', () => api('root/remove', { id: root.id })));
      el('roots').append(row);
    }
    el('pending').replaceChildren();
    for (const operation of state.pending || []) {
      const row = document.createElement('div'); row.className = 'root'; row.dataset.operationId = operation.operationId;
      const details = document.createElement('pre'); details.textContent = JSON.stringify(operation, null, 2);
      row.append(details, button('批准此修改', () => api('approve', { operationId: operation.operationId, approved: true })), document.createTextNode(' '), button('拒绝此修改', () => api('approve', { operationId: operation.operationId, approved: false })));
      el('pending').append(row);
    }
    el('events').textContent = JSON.stringify(state.events || [], null, 2);
    try { guide = await api('guide'); el('guide-stage').textContent = guideLabels.get(guide.stage) || '待确认'; el('guide-prompt').textContent = (guide.stage === 'check-tools' ? guide.toolCheckPrompt : guide.verificationPrompt) || ''; el('cancel-guide').hidden = !guide.attemptId; } catch (e) { guide = null; el('guide-stage').textContent = e.message; }
  }
  el('pause').onclick = () => { if (!state?.nativeFault) return action(() => api('pause', { paused: !state.paused })); };
  el('refresh').onclick = () => action(async () => {});
  el('pick-folder').onclick = () => action(async () => { const picked = await api('pick-folder', {}); if (picked.path) el('folder-path').value = picked.path; });
  el('browse-folder').onclick = () => action(async () => { const browse = await api('folder/browse', el('folder-path').value ? { path: el('folder-path').value } : {}); el('folder-path').value = browse.path; el('browse-results').replaceChildren(); for (const entry of browse.entries || []) el('browse-results').append(button(entry.name, async () => { el('folder-path').value = entry.path; })); });
  el('add-root').onclick = () => action(async () => { const result = await api('root/add', { path: el('folder-path').value, writeMode: el('write-mode').value, confirmDirect: el('confirm-direct').checked }); say((result.alreadyAuthorized ? '此目录已在本机授权，保留原有权限。' : '本机目录授权已保存。') + ' 请点击“共享给应用”，选择 Gemini 等连接并确认共享。'); });
  el('authorize-guide').onclick = () => action(async () => { if (!el('confirm-direct').checked) throw Error('请先明确勾选直接读写确认。'); const checked = await api('folder/browse', { path: el('folder-path').value }); if (!checked.selectable) throw Error('此目录不能授权。'); if (pendingGuide?.path !== checked.path) pendingGuide = { path: checked.path, requestId: crypto.randomUUID() }; if (guide?.attemptId === pendingGuide.requestId) { say('此验证步骤已保存。'); return; } await api('guide/authorize', { path: checked.path, expectedRootId: checked.existingRoot?.id ?? null, expectedWriteMode: checked.existingRoot?.writeMode ?? null, requestId: pendingGuide.requestId, confirmDirect: true }); });
  el('cancel-guide').onclick = () => action(() => api('guide/cancel', { attemptId: guide.attemptId }));
  el('save-session-tools').onclick = () => action(() => { if (!guide?.attemptId) throw Error('请先开始目录验证步骤。'); return api('guide/session-tools', { attemptId: guide.attemptId, tools: el('session-tools').value.split(/[\s,，]+/).filter(Boolean) }); });
  el('save-startup').onclick = () => action(() => api('startup', { enabled: el('startup').checked }));
  let quitting = false;
  el('quit').onclick = async () => {
    if (busy || quitting) return;
    quitting = true; busy = true;
    for (const button of el('controls').querySelectorAll('button')) button.disabled = true;
    try {
      await api('shutdown', {});
      token = ''; try { sessionStorage.removeItem(storageKey); } catch {}
      el('controls').hidden = true;
      say('已提交正常退出。进程结束后可运行新版或保留版本的安装程序；目录、设备身份和权限已保留。');
    } catch {
      say('退出结果未确认。请重新打开管理入口核对状态；未自动重复发送退出请求。');
    }
  };
  el('manage-shares').onclick = event => { event.preventDefault(); try { sessionStorage.setItem('chat2local-control', token); } catch { say('浏览器禁止本地会话存储。请允许会话存储后，通过本机启动入口重新打开管理页，再共享给应用。'); return; } location.assign('/shares'); };
  el('import-invitation').onclick = () => action(async () => { const result = await api('instance/import-invitation', { url: el('instance-invitation').value }); el('instance-invitation').value = ''; el('setup-message').textContent = '实例入口已保存：' + result.origin + '。尚未授权目录，请回到原实例页面继续。'; });
  el('inspect-setup').onclick = () => action(async () => { const result = await api('setup/inspect', {}); el('setup-message').textContent = result.message; const link = el('account-entry'); link.hidden = true; if (result.accountEntryUrl) { const url = new URL(result.accountEntryUrl); if (['https:', 'http:'].includes(url.protocol) && url.pathname === '/account/add' && !url.username && !url.password && !url.search && !url.hash) { link.href = url.href; link.hidden = false; } } });
  el('start-setup').onclick = () => action(async () => { const result = await api('setup/start', {}); el('setup-message').textContent = result.message; });
  if (!/^[a-f0-9]{64}$/.test(token)) { el('session-required').hidden = false; return; }
  el('controls').hidden = false; action(async () => {});
})();
