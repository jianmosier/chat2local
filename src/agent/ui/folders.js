const $ = id => document.getElementById(id);
if (/^#[a-f0-9]{64}$/.test(location.hash)) { sessionStorage.setItem('chat2local-control', location.hash.slice(1)); history.replaceState(null, '', location.pathname); }
const token = sessionStorage.getItem('chat2local-control') || '';
const labels = { direct: '允许读写 · 覆盖前备份', 'read-only': '只读', review: '逐次确认修改' };
let connections = [], pending = [], page, view, draft, busy = false, browses = 0;
function note(text) { $('message').textContent = text; }
function element(tag, text) { const node = document.createElement(tag); if (text !== undefined) node.textContent = text; return node; }
async function api(action, body = {}) {
  const response = await fetch('/api/' + action, { method: 'POST', headers: { 'X-Chat2Local-Token': token, 'Content-Type': 'application/json' }, body: JSON.stringify(body), redirect: 'error', signal: AbortSignal.timeout(65000) });
  const value = await response.json(); if (!response.ok) throw Error(value.error || '操作未完成'); return value;
}
const selected = () => connections.find(c => c.connectionId === $('connection').value);
function folderList(target, folders) {
  target.replaceChildren();
  for (const folder of folders) { const row = element('div', folder.path || folder.label || '本机已撤销的目录'); row.className = 'folder'; row.append(element('small', labels[folder.mode] || folder.mode)); target.append(row); }
}
function controls() {
  $('prepare').disabled = busy || !pending.length || !selected();
  $('confirm').disabled = busy || !view?.requiresConsent;
  $('connection').disabled = busy || Boolean(draft) || connections.length < 2;
  $('add-current').disabled = busy || !page?.selectable || Boolean(draft);
  $('browse').disabled = busy || Boolean(draft); $('up').disabled = busy || !page?.parent || Boolean(draft);
}
function drawPending() {
  $('pending').replaceChildren();
  for (const folder of pending) {
    const row = element('div'); row.className = 'pending-row'; row.append(element('span', folder.path));
    const mode = element('select'); mode.setAttribute('aria-label', '目录权限 ' + folder.path);
    for (const value of ['direct','read-only','review']) {
      if ((value === 'direct' && !selected()?.scopes.includes('files:write')) || (value === 'review' && !selected()?.scopes.includes('files:propose'))) continue;
      mode.add(new Option(labels[value], value));
    }
    mode.value = folder.mode; mode.disabled = busy || Boolean(draft); mode.onchange = () => { folder.mode = mode.value; };
    const remove = element('button', '移除'); remove.className = 'secondary'; remove.disabled = busy || Boolean(draft); remove.onclick = () => { pending = pending.filter(item => item !== folder); drawPending(); };
    row.append(mode, remove); $('pending').append(row);
  }
  controls();
}
function queue(path) {
  if (busy || draft || !selected()) return;
  if (selected().roots.some(r => r.path === path && r.locallyPresent)) { note('这个目录已经共享，原权限保持不变。'); return; }
  if (pending.some(p => p.path === path)) return;
  if (pending.length >= 20) { note('一次最多选择 20 个目录。'); return; }
  pending.push({ path, mode: selected().scopes.includes('files:write') ? 'direct' : 'read-only' }); drawPending();
}
async function browse(path) {
  const sequence = ++browses;
  try {
    const result = await api('folder/browse', path ? { path } : {});
    if (sequence !== browses) return;
    page = result; $('path').value = result.path; $('entries').replaceChildren(); $('places').replaceChildren();
    for (const place of result.locations) { const b = element('button', place.label); b.className = 'secondary'; b.onclick = () => browse(place.path); $('places').append(b); }
    for (const entry of result.entries) {
      const row = element('div'); row.className = 'entry'; const check = element('input'); check.type = 'checkbox'; check.setAttribute('aria-label', '加入待授权列表 ' + entry.name); check.checked = pending.some(f => f.path === entry.path); check.onchange = () => { if (check.checked) queue(entry.path); else { pending = pending.filter(f => f.path !== entry.path); drawPending(); } };
      const b = element('button', entry.name + ' ›'); b.onclick = () => browse(entry.path); row.append(check, b); $('entries').append(row);
    }
    controls();
  } catch (error) { note(error.message); }
}
async function refreshTerminal() {
  const value = await api('terminal/permissions'); $('terminal-roots').replaceChildren();
  const connection = value.connections.find(c => c.connectionId === $('connection').value);
  for (const root of connection?.roots || []) {
    if (!root.locallyPresent || root.mode !== 'direct') continue;
    const row = element('div', root.path); row.className = 'folder';
    const button = element('button', root.terminalAllowed ? '关闭此目录的终端' : '启用此目录的终端'); button.className = 'secondary';
    button.onclick = async () => {
      const enabled = !root.terminalAllowed;
      if (enabled && !confirm(`允许原连接在这台电脑执行终端命令？\n工作目录：${root.path}\n\n命令以当前系统用户权限运行，不是目录沙箱，可能修改/删除其他文件和访问网络。文件修改不受普通文本工具的备份保证。`)) return;
      button.disabled = true;
      try {
        const result = await api('terminal/set-permission', { connectionId: connection.connectionId, rootId: root.rootId, enabled, ...(enabled ? { confirmation: 'allow-unsandboxed-terminal-v1' } : {}) });
        note(enabled ? result.oauthScopeGranted ? '终端本机权限已启用，原连接也具备终端 scope。' : '本机终端权限已保存。原连接还需明确授予 terminal:execute，当前不能执行命令。' : '终端权限已关闭。正在运行的命令会收到停止请求；此前副作用不会回滚。');
        await refreshTerminal();
      } catch (error) { note(error.message); button.disabled = false; }
    };
    row.append(element('small', root.terminalAllowed ? '本机已启用 · 非沙箱' : '本机未启用')); row.append(button); $('terminal-roots').append(row);
  }
}
async function refreshConnections() {
  const value = await api('shares/connections'); connections = value.connections;
  const old = $('connection').value; $('connection').replaceChildren();
  for (const c of connections) $('connection').add(new Option(`${c.clientName} · ${c.callbackOrigin}`, c.connectionId));
  if (connections.some(c => c.connectionId === old)) $('connection').value = old;
  folderList($('shared'), selected()?.roots || []); controls(); await refreshTerminal();
}
function showView() {
  $('editor').hidden = Boolean(view); $('review').hidden = !view || view.connected; $('done').hidden = !view?.connected;
  if (view) {
    $('target').textContent = `${view.deviceName} → ${view.clientName} · ${view.callbackOrigin}`;
    folderList($('summary'), view.selections || []);
    if (view.connected) { folderList($('result'), view.selections || []); note('本机保存和连接更新均已完成。无需重新连接插件。'); sessionStorage.removeItem('chat2local-folder-draft'); }
    else note(view.requiresConsent ? '核对以下目录和权限，确认一次即可。' : '此前确认已保存，正在核对同一次变更。不要重复授权。');
  }
  controls();
}
$('connection').onchange = () => { pending = []; drawPending(); folderList($('shared'), selected()?.roots || []); };
$('browse').onclick = () => browse($('path').value.trim()); $('up').onclick = () => page?.parent && browse(page.parent);
$('path').oninput = () => { ++browses; page = null; controls(); };
$('path').onkeydown = event => { if (event.key === 'Enter') { event.preventDefault(); void browse($('path').value.trim()); } };
$('add-current').onclick = () => page?.selectable && queue(page.path);
$('prepare').onclick = async () => {
  if (busy || !selected() || !pending.length) return;
  busy = true; controls();
  draft ||= { requestId: crypto.randomUUID().replaceAll('-', ''), connectionId: selected().connectionId, folders: pending };
  sessionStorage.setItem('chat2local-folder-draft', JSON.stringify(draft));
  try { view = await api('shares/prepare', draft); showView(); } catch (error) { note(error.message); }
  finally { busy = false; controls(); }
};
async function resume() {
  if (!view || view.connected || view.requiresConsent || busy) return;
  busy = true; controls();
  try { view = await api('shares/resume', { requestId: draft.requestId }); showView(); }
  catch (error) { note(error.message + ' 已保留请求，重新打开管理页会核对结果。'); }
  finally { busy = false; controls(); }
}
$('confirm').onclick = async () => {
  if (busy || !view?.requiresConsent) return;
  busy = true; controls();
  try { view = await api('shares/confirm', { requestId: draft.requestId, snapshotDigest: view.snapshotDigest, confirmation: 'allow-shared-folders-v1' }); }
  catch (error) { try { view = await api('shares/status', { requestId: draft.requestId }); } catch { view = { ...view, requiresConsent: false }; } note(error.message); }
  finally { busy = false; showView(); }
  if (view?.connected) await refreshConnections().catch(error => note(error.message)); else await resume();
};
$('another').onclick = async () => { view = null; draft = null; pending = []; $('editor').hidden = false; $('done').hidden = true; drawPending(); await refreshConnections().catch(error => note(error.message)); };
(async () => {
  try {
    if (!token) throw Error('请通过已安装的 chat2local 启动入口打开此页；无需重新安装或配对。');
    const response = await fetch('/api/status', { headers: { 'X-Chat2Local-Token': token }, redirect: 'error' });
    if (!response.ok) throw Error('本机管理会话已过期，请重新运行 chat2local 启动入口。');
    const state = await response.json(); $('device').textContent = `${state.device.name} · ${state.device.system}`;
    await refreshConnections();
    if (!connections.length) { note('尚无这台电脑的有效共享连接。已有目录不会被自动迁移。'); return; }
    draft = JSON.parse(sessionStorage.getItem('chat2local-folder-draft') || 'null');
    if (draft) { view = await api('shares/prepare', draft); showView(); await resume(); }
    else { note('可以在下方批量添加目录，不需要安装密码。'); await browse(); }
  } catch (error) { note(error.message); }
})();
