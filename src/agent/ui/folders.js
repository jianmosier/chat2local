const $ = id => document.getElementById(id);
if (/^#[a-f0-9]{64}$/.test(location.hash)) {
  sessionStorage.setItem('chat2local-control', location.hash.slice(1));
  history.replaceState(null, '', location.pathname);
}
let token = sessionStorage.getItem('chat2local-control') || '';
let managementLocked = false;
const storageKey = 'chat2local-folder-draft';
const labels = { direct: '读写', 'read-only': '只读', review: '逐次确认' };
let state, connections = [], terminals = [], terminalKnown = false, pending = [], page, view, draft;
let busy = false, refreshing = false, browses = 0, refreshSequence = 0, terminalTarget, removeTarget, removePreview;
let autoTimer, lastSync = 0, refreshWork;
const groupNodes = new Map(), expandedGroups = new Set();
let choicesKey = '';
function text(id, value) { const node = $(id); if (node.textContent !== value) node.textContent = value; }
function isEditing() { return busy || folderDialog.open || terminalDialog.open || removeDialog.open || $('authorization-dialog').open; }
const removeDialog = $('remove-dialog');
const selected = () => connections.find(c => c.connectionId === $('connection').value);
const folderDialog = $('folder-dialog'), terminalDialog = $('terminal-dialog');
function element(tag, text, className) {
  const node = document.createElement(tag); if (text !== undefined) node.textContent = text; if (className) node.className = className; return node;
}
function nameOf(path) { return path.replace(/[\\/]+$/, '').split(/[\\/]/).pop() || path; }
function note(text = '', kind = '') {
  $('message-text').textContent = text; $('message').hidden = !text; $('message').className = 'notice ' + kind;
}
function dialogNote(text = '') { $('dialog-message').textContent = text; $('dialog-message').hidden = !text; }
function managementExpired() {
  managementLocked = true; token = ''; sessionStorage.removeItem('chat2local-control');
  document.body.dataset.managementLocked = 'true'; $('management-recovery').hidden = false;
  if (!state) text('device', '本机');
  text('connection-status', '管理页待验证'); $('connection-status').className = 'status-dot';
  text('sync-state', '等待验证'); note();
  // Do not leave a perpetual loading state or claim the cloud is disconnected.
  if (!state) $('shared').replaceChildren(element('p', '打开启动入口后显示共享文件夹', 'empty'));
  const platform = navigator.userAgent;
  if (/Macintosh|Mac OS X/.test(platform)) { text('management-entry-label', '在终端运行：'); $('management-entry').value = 'open "$HOME/Applications/Chat2Local.command"'; }
  else if (!/Windows/.test(platform)) { text('management-entry-label', '打开已安装的 Chat2Local 启动文件：'); $('management-entry').value = 'Chat2Local.command'; }
  controls();
}
function failedResponse(response, message) {
  if (response.status === 401) managementExpired();
  return Object.assign(Error(response.status === 401 ? '请通过本机启动入口验证这个浏览器。' : message), { status: response.status });
}
async function api(action, body = {}) {
  const response = await fetch('/api/' + action, { method: 'POST', credentials: 'same-origin', headers: { 'X-Chat2Local-Token': token, 'X-Chat2Local-Manager': '1', 'Content-Type': 'application/json' }, body: JSON.stringify(body), redirect: 'error', signal: AbortSignal.timeout(65000) });
  const value = await response.json();
  if (!response.ok) throw failedResponse(response, value.error || '操作未完成，请重试。'); return value;
}
async function establishManagement() {
  const result = await api('management/session');
  if (result.ready !== true) throw Error('未能验证管理登录。');
  // The browser now uses its HttpOnly proof, not a stale per-process token.
  token = ''; sessionStorage.removeItem('chat2local-control'); managementLocked = false;
  document.body.dataset.managementLocked = 'false'; $('management-recovery').hidden = true;
}
async function status() {
  const response = await fetch('/api/status', { credentials: 'same-origin', headers: { 'X-Chat2Local-Token': token, 'X-Chat2Local-Manager': '1' }, redirect: 'error', signal: AbortSignal.timeout(5000) });
  if (!response.ok) throw failedResponse(response, '本机服务暂不可用，请稍后重试。');
  return response.json();
}
function controls() {
  const frozen = busy || Boolean(draft), unavailable = managementLocked || !selected() || state?.paused;
  $('open-add').disabled = busy || unavailable || Boolean(state && !selected()?.scopes.includes('files:write'));
  text('open-add', draft && !view?.connected ? '查看待处理' : '＋ 添加文件夹');
  $('connection').disabled = busy || folderDialog.open || terminalDialog.open || removeDialog.open || Boolean(draft);
  $('refresh').disabled = busy || folderDialog.open || terminalDialog.open || removeDialog.open;
  for (const id of ['close-remove','cancel-remove','confirm-remove']) $(id).disabled = busy || (id === 'confirm-remove' && !removePreview);
  for (const node of document.querySelectorAll('[data-remove-button]')) node.disabled = busy || folderDialog.open || terminalDialog.open || removeDialog.open;
  $('prepare').disabled = busy || !pending.length || unavailable;
  text('prepare', busy ? '正在保存…' : draft ? '重试本次添加' : `共享${pending.length ? '（' + pending.length + '）' : ''}`);
  $('confirm').disabled = busy || !view?.requiresConsent;
  text('confirm', busy ? '正在保存…' : '确认共享');
  $('back-edit').disabled = busy || !view?.requiresConsent;
  for (const id of ['close-add','cancel-add','close-terminal','cancel-terminal','confirm-terminal']) $(id).disabled = busy;
  $('retry-result').disabled = busy;
  $('browse').disabled = frozen; $('path').disabled = frozen;
  $('up').disabled = frozen || !page?.parent;
  $('add-current').disabled = frozen || !page?.selectable;
  for (const node of document.querySelectorAll('#places button,#entries button')) node.disabled = frozen;
  for (const node of document.querySelectorAll('#entries input')) node.disabled = frozen || node.dataset.shared === 'true';
  for (const node of document.querySelectorAll('#pending button,#pending select')) node.disabled = frozen;
  for (const node of document.querySelectorAll('[data-terminal-button]')) node.disabled = busy || !terminalKnown || unavailable || folderDialog.open;
}
function renderLifecycle() {
  const toggle = $('login-startup');
  toggle.checked = state?.startup === true;
  toggle.disabled = busy || managementLocked || state?.startupAvailable !== true;
  const mac = state?.device?.platform === 'darwin' || /Macintosh/.test(navigator.userAgent);
  const windows = state?.device?.platform === 'win32' || /Windows/.test(navigator.userAgent);
  $('daily-entry').value = mac ? 'open "$HOME/Applications/Chat2Local.command"' : windows ? '%LOCALAPPDATA%\\Chat2Local\\Chat2Local.cmd' : '打开已安装的 Chat2Local.command';
  let origin;
  try { const url = new URL(state?.relay || state?.setupOrigin); if (url.protocol !== 'https:' || url.href !== url.origin + '/') throw Error(); origin = url.origin; } catch { $('update-command').value = '实例未配置'; $('copy-update').disabled = true; return; }
  $('copy-update').disabled = false;
  $('update-command').value = windows
    ? `& ([scriptblock]::Create((Invoke-RestMethod 'https://raw.githubusercontent.com/jianmosier/chat2local/main/install.ps1'))) -Instance '${origin}'`
    : `curl -fS --proto '=https' --connect-timeout 20 --max-time 60 '${origin}/install.sh' | sh`;
}
$('login-startup').onchange = async () => {
  if (busy || managementLocked || state?.startupAvailable !== true) { renderLifecycle(); return; }
  const enabled = $('login-startup').checked; busy = true; $('login-startup').disabled = true; controls();
  try {
    const result = await api('management/startup', { enabled });
    if (result.enabled !== enabled) throw Error('启动设置未确认。');
    await refreshConnections(); note(enabled ? '已设置为登录后自动连接' : '已关闭登录自动连接', 'success');
  } catch (error) { note(error.message, 'error'); }
  finally { busy = false; renderLifecycle(); controls(); }
};
$('copy-update').onclick = async () => {
  try { await navigator.clipboard.writeText($('update-command').value); note('更新命令已复制', 'success'); }
  catch { $('update-command').focus(); $('update-command').select(); note('请复制选中的更新命令'); }
};
$('authorization-help').onclick = () => $('authorization-dialog').showModal();
for (const id of ['close-authorization','authorization-done']) $(id).onclick = () => $('authorization-dialog').close();
function folderList(target, folders) {
  target.replaceChildren();
  for (const folder of folders) {
    const row = element('div', undefined, 'review-row');
    row.append(element('span', folder.path || folder.label || '目录不可用', 'path'), element('span', labels[folder.mode] || '未知', 'badge'));
    target.append(row);
  }
}
function rowModel(root, connection, terminalConnection) {
  const terminal = terminalConnection?.roots.find(r => r.rootId === root.rootId);
  const known = terminalKnown && Boolean(terminal);
  return { ...root, known, local: Boolean(known && (terminal.terminalLocalEnabled ?? terminal.terminalAllowed)), authorized: Boolean(terminalConnection?.scopes.includes('terminal:execute')), connectionId: connection.connectionId, clientName: connection.clientName };
}
function buildRow(root) {
  const row = element('div', undefined, 'shared-row'); row.dataset.rootId = root.rootId;
  const identity = element('div', undefined, 'folder-identity');
  const icon = element('span', undefined, 'folder-icon'); icon.setAttribute('aria-hidden', 'true');
  const copy = element('div', undefined, 'folder-copy');
  const title = root.label || (root.path ? nameOf(root.path) : '目录不可用');
  copy.append(element('strong', title, 'folder-name'), element('span', root.path || '本机共享已撤销', 'folder-path'));
  identity.append(icon, copy);
  const permission = element('div', undefined, 'project-permission');
  const legacy = root.mode !== 'direct' ? `${labels[root.mode] || '未知'}（旧授权）` : '仅文件（旧授权）';
  const label = !root.locallyPresent ? '已撤销' : root.mode !== 'direct' ? legacy : !root.known ? '未读取' : !root.local ? legacy : root.authorized ? '完整共享' : '可读写';
  permission.append(element('span', label, 'badge ' + (root.local ? root.authorized ? 'ok' : 'wait' : 'muted')));
  if (root.locallyPresent && root.mode === 'direct' && root.local && !root.authorized) permission.append(element('small', '命令待授权', 'pending-capability'));
  const actions = element('div', undefined, 'share-actions');
  if (root.locallyPresent && root.mode === 'direct' && (!root.known || !root.local)) {
    const upgrade = element('button', '升级共享', 'text-button');
    upgrade.dataset.terminalButton = 'true'; upgrade.setAttribute('aria-label', '升级共享 ' + title);
    upgrade.disabled = !root.known;
    upgrade.onclick = () => {
      if (busy || !root.known || selected()?.connectionId !== root.connectionId) return;
      terminalTarget = { connectionId: root.connectionId, rootId: root.rootId, path: root.path, clientName: root.clientName, authorized: root.authorized, enabled: false };
      text('terminal-target', `${state.device.name} · ${root.clientName}`); text('terminal-path', root.path);
      $('terminal-auth-note').hidden = root.authorized;
      $('terminal-error').hidden = true; terminalDialog.showModal(); controls(); $('cancel-terminal').focus();
    };
    actions.append(upgrade);
  }
  const remove = element('button', '移除共享', 'text-button danger-text');
  remove.dataset.removeButton = 'true'; remove.setAttribute('aria-label', '移除共享 ' + title);
  remove.onclick = () => openRemoval(root.connectionId, root);
  actions.append(remove); row.append(identity, permission, actions); return row;
}
function renderShared() {
  const connection = selected(), roots = connection?.roots || [];
  const terminalConnection = terminals.find(c => c.connectionId === connection?.connectionId);
  const models = roots.map(r => rowModel(r, connection, terminalConnection));
  const visible = models.filter(r => !r.coveredBy || !models.some(p => p.rootId === r.coveredBy));
  text('folder-count', `${visible.filter(r => r.locallyPresent).length} 个文件夹`);
  $('connection-picker').hidden = connections.length < 2;
  $('connection-name').hidden = connections.length > 1;
  text('connection-name', connection?.clientName || '未连接');
  const container = $('shared'), wanted = [];
  for (const root of visible) {
    const children = models.filter(r => r.coveredBy === root.rootId);
    const key = connection.connectionId + ':' + root.rootId;
    const signature = JSON.stringify([root, children]);
    let entry = groupNodes.get(key);
    if (!entry || entry.signature !== signature) {
      const node = element('div', undefined, 'share-group'); node.append(buildRow(root));
      if (children.length) {
        const details = element('details', undefined, 'covered-shares');
        details.open = expandedGroups.has(key);
        details.append(element('summary', `包含 ${children.length} 项独立共享`));
        for (const child of children) details.append(buildRow(child));
        details.addEventListener('toggle', () => { if (details.open) expandedGroups.add(key); else if (details.isConnected) expandedGroups.delete(key); });
        node.append(details);
      }
      entry = { node, signature }; groupNodes.set(key, entry);
    }
    wanted.push(entry.node);
  }
  if (!wanted.length) {
    const message = connections.length ? '还没有共享文件夹' : '未找到这台电脑的有效连接';
    if (container.firstElementChild?.className !== 'empty' || container.firstElementChild.textContent !== message) container.replaceChildren(element('p', message, 'empty'));
  } else {
    // Never clear a live list for a poll. Reuse unchanged DOM nodes, including
    // keyboard focus, text selection, expanded children and scroll position.
    for (const child of [...container.children]) if (!wanted.includes(child)) child.remove();
    wanted.forEach((node, index) => { if (container.children[index] !== node) container.insertBefore(node, container.children[index] || null); });
  }
  for (const key of groupNodes.keys()) if (!key.startsWith((connection?.connectionId || '') + ':') || !visible.some(r => key.endsWith(':' + r.rootId))) groupNodes.delete(key);
  $('terminal-hint').hidden = !models.some(r => r.local && !r.authorized);
  text('terminal-hint', '文件读写已可用，命令执行需在 ChatGPT 确认一次。');
  $('authorization-help').hidden = $('terminal-hint').hidden;
  renderLifecycle();
  text('detail-client', connection ? `${connection.clientName} · ${connection.callbackOrigin}` : '—');
  text('detail-origin', state?.setupOrigin || '—');
  text('detail-terminal', !terminalKnown ? '读取失败，可重试' : terminalConnection?.scopes.includes('terminal:execute') ? '已授予命令执行权限' : '尚未授予命令执行权限');
  text('detail-version', state?.version || '—');
}
async function refreshConnections(background = false) {
  if (refreshWork) return refreshWork;
  refreshWork = refreshSnapshot(background).finally(() => { refreshWork = null; });
  return refreshWork;
}
async function refreshSnapshot(background) {
  const sequence = ++refreshSequence; refreshing = true;
  if (!state) controls();
  try {
    const [nextState, value, terminalValue] = await Promise.all([status(), api('shares/connections'), api('terminal/permissions').then(value => ({ value }), error => ({ error }))]);
    if (sequence !== refreshSequence || (background && isEditing())) return;
    state = nextState; connections = value.connections;
    terminalKnown = !terminalValue.error; terminals = terminalValue.value?.connections || [];
    const nextChoices = JSON.stringify(connections.map(c => [c.connectionId, c.clientName, c.callbackOrigin]));
    if (nextChoices !== choicesKey) {
      const old = $('connection').value; $('connection').replaceChildren();
      for (const c of connections) $('connection').add(new Option(c.clientName + ' · ' + c.callbackOrigin, c.connectionId));
      if (connections.some(c => c.connectionId === old)) $('connection').value = old;
      choicesKey = nextChoices;
    }
    text('device', state.device.name);
    const connected = !state.paused && state.bridge === 'connected';
    text('connection-status', state.paused ? '已暂停' : connected ? '已连接' : '连接中');
    const stateClass = 'status-dot ' + (state.paused ? 'paused' : connected ? 'online' : '');
    if ($('connection-status').className !== stateClass) $('connection-status').className = stateClass;
    renderShared();
    lastSync = Date.now(); text('detail-sync', new Date(lastSync).toLocaleTimeString());
    text('sync-state', terminalValue.error ? '部分状态待同步' : '已同步');
    if (terminalValue.error) note('终端状态读取失败，等待自动同步。', 'error');
  } finally { if (sequence === refreshSequence) { refreshing = false; controls(); } }
}
async function setTerminal(target, enabled) {
  if (busy || selected()?.connectionId !== target.connectionId) return;
  busy = true; controls();
  let result, error;
  try {
    result = await api('terminal/set-permission', { connectionId: target.connectionId, rootId: target.rootId, enabled, ...(enabled ? { confirmation: 'allow-unsandboxed-terminal-v1' } : {}) });
  } catch (failure) { error = failure; }
  try {
    await refreshConnections();
    const saved = terminals.find(c => c.connectionId === target.connectionId)?.roots.find(r => r.rootId === target.rootId);
    if (!result && (!terminalKnown || !saved || (saved.terminalLocalEnabled ?? saved.terminalAllowed) !== enabled)) throw error || Error('未能确认保存结果，请刷新状态后核对。');
    if (terminalDialog.open) terminalDialog.close(); terminalTarget = null;
    note(enabled ? result?.oauthScopeGranted || terminals.find(c => c.connectionId === target.connectionId)?.scopes.includes('terminal:execute') ? '已升级为完整共享' : '本机已确认完整共享，等待 ChatGPT 授权。' : '终端已关闭；已发生的命令操作不会撤销。', 'success');
  } catch (failure) {
    terminalKnown = false; renderShared();
    const text = failure?.message || '保存结果未确认，请刷新后核对。';
    if (terminalDialog.open) { $('terminal-error').textContent = text; $('terminal-error').hidden = false; } else note(text, 'error');
  } finally { busy = false; controls(); }
}
function syncChecks() {
  for (const check of document.querySelectorAll('#entries input')) check.checked = check.dataset.shared === 'true' || pending.some(folder => folder.path === check.dataset.path);
}
function drawPending() {
  $('pending-count').textContent = pending.length; $('pending').replaceChildren();
  if (!pending.length) $('pending').append(element('p', '勾选文件夹，支持多选', 'empty'));
  for (const folder of pending) {
    const row = element('div', undefined, 'pending-row');
    const copy = element('div', undefined, 'pending-copy'); copy.append(element('strong', nameOf(folder.path)), element('small', folder.path));
    copy.append(element('span', draft && draft.accessProfile !== 'project' ? labels[folder.mode] : '文件 + 命令', 'selection-mode'));
    const remove = element('button', '×', 'icon-button'); remove.setAttribute('aria-label', '移除 ' + nameOf(folder.path));
    remove.onclick = () => { if (busy || draft) return; pending = pending.filter(item => item !== folder); drawPending(); };
    row.append(copy, remove); $('pending').append(row);
  }
  syncChecks(); controls();
}
function queue(path) {
  if (busy || draft || !selected()) return;
  if (selected().roots.some(r => r.path === path && r.locallyPresent)) { dialogNote('这个文件夹已共享。'); syncChecks(); return; }
  if (pending.some(p => p.path === path)) return;
  if (pending.length >= 20) { dialogNote('每次最多添加 20 个文件夹。'); syncChecks(); return; }
  if (!selected().scopes.includes('files:write')) { dialogNote('请先为此连接授权文件读写。'); return; }
  pending.push({ path, mode: 'direct' }); dialogNote(); drawPending();
}
async function browse(path) {
  if (busy || draft) return;
  const sequence = ++browses; page = null; controls(); $('entries').replaceChildren(element('p', '正在读取…', 'empty'));
  try {
    const result = await api('folder/browse', path ? { path } : {});
    if (sequence !== browses || !folderDialog.open) return;
    page = result; $('path').value = result.path; $('entries').replaceChildren(); $('places').replaceChildren();
    for (const place of result.locations) { const b = element('button', place.label); b.onclick = () => browse(place.path); $('places').append(b); }
    for (const entry of result.entries) {
      const row = element('div', undefined, 'entry');
      const check = element('input'); check.type = 'checkbox'; check.dataset.path = entry.path;
      check.dataset.shared = String(Boolean(selected()?.roots.some(r => r.path === entry.path && r.locallyPresent)));
      check.setAttribute('aria-label', '加入待授权列表 ' + entry.name);
      check.onchange = () => { if (busy || draft) { syncChecks(); return; } if (check.checked) queue(entry.path); else { pending = pending.filter(f => f.path !== entry.path); drawPending(); } };
      const b = element('button', entry.name + ' ›'); b.onclick = () => browse(entry.path);
      row.append(check, b); if (check.dataset.shared === 'true') row.append(element('small', '已共享')); $('entries').append(row);
    }
    if (!result.entries.length) $('entries').append(element('p', '没有子文件夹', 'empty'));
    $('browse-note').hidden = !result.truncated;
    $('browse-note').textContent = result.truncated ? '仅显示部分目录；其他位置可输入完整路径。' : '';
    dialogNote(); syncChecks(); controls();
  } catch (error) { if (sequence === browses) { $('entries').replaceChildren(element('p', '无法读取此位置', 'empty')); dialogNote(error.message); controls(); } }
}
function saveDraft() { sessionStorage.setItem(storageKey, JSON.stringify(draft)); }
function resetDraft() { draft = null; view = null; sessionStorage.removeItem(storageKey); }
function showView() {
  $('editor').hidden = Boolean(view);
  $('review').hidden = !view?.requiresConsent || view?.connected;
  $('recovering').hidden = !view || view.requiresConsent || view.connected;
  $('done').hidden = !view?.connected;
  $('folder-title').textContent = view?.connected ? '添加完成' : view?.requiresConsent ? '确认共享' : view ? '保存结果' : '添加文件夹';
  if (view?.requiresConsent) {
    text('review-consent', view.accessProfile === 'project' ? '读写文件并执行命令。命令可修改或删除目录外文件、访问网络，不保证自动备份。内容经连接服务与 ChatGPT 处理。' : '保留原有文件权限，不启用命令执行。内容经连接服务与 ChatGPT 处理。');
    $('target').textContent = `${view.deviceName} · ${view.clientName} · ${view.callbackOrigin}`;
    folderList($('summary'), view.selections || []);
  }
  if (view?.connected) {
    const count = view.selections?.length || 0;
    $('done-title').textContent = `已添加 ${count} 个文件夹`;
    folderList($('result'), view.selections || []); sessionStorage.removeItem(storageKey);
    note(`已添加 ${count} 个文件夹`, 'success'); dialogNote();
  }
  controls();
}
// Consent is given by the single labelled Add button while exact paths/modes
// are visible. Never apply it to a different server snapshot: changed paths,
// modes, device or connection require a separate explicit review instead.
function sameSelection(prepared, intended) {
  const normalized = folders => folders.map(f => [f.path, f.mode]).sort((a, b) => a[0].localeCompare(b[0]));
  return prepared.accessProfile === intended.accessProfile && prepared.connectionId === intended.connectionId && prepared.deviceName === state.device.name && Array.isArray(prepared.selections) && JSON.stringify(normalized(prepared.selections)) === JSON.stringify(normalized(intended.folders));
}
async function confirmPrepared() {
  try {
    view = await api('shares/confirm', { requestId: draft.requestId, snapshotDigest: view.snapshotDigest, confirmation: view.accessProfile === 'project' ? 'allow-project-files-and-terminal-v1' : 'allow-shared-folders-v1' });
    dialogNote();
  } catch (error) {
    try { view = await api('shares/status', { requestId: draft.requestId }); }
    catch { view = { ...view, requiresConsent: false, connected: false }; }
    dialogNote(view.connected ? '' : '保存结果待核对，请勿重复添加。');
  }
}
async function recover() {
  if (busy || !draft || view?.connected) return;
  busy = true; controls();
  try {
    view = await api('shares/status', { requestId: draft.requestId });
    if (!view.connected && !view.requiresConsent) view = await api('shares/resume', { requestId: draft.requestId });
    showView();
    if (view.connected) await refreshConnections();
    else if (view.requiresConsent) dialogNote('本次尚未授权，请核对后确认。');
  } catch (error) { dialogNote(error.message + ' 可稍后重新检查。'); }
  finally { busy = false; controls(); }
}
async function addFolders() {
  if (busy || !selected() || !pending.length) return;
  const isNewDecision = !draft;
  busy = true; dialogNote();
  if (!draft) { draft = { requestId: crypto.randomUUID().replaceAll('-', ''), connectionId: selected().connectionId, accessProfile: 'project', folders: pending.map(f => ({ ...f })) }; saveDraft(); }
  controls();
  try {
    view = await api('shares/prepare', draft);
    if (isNewDecision && view.requiresConsent && sameSelection(view, draft)) await confirmPrepared();
    else if (view.requiresConsent) dialogNote('请核对当前目录和权限后确认。');
    showView();
    if (view.connected) await refreshConnections();
  } catch (error) { dialogNote(error.message); }
  finally { busy = false; controls(); }
  if (view && !view.requiresConsent && !view.connected) await recover();
}
async function openFolders() {
  if (busy || !selected()) return;
  folderDialog.showModal(); dialogNote(); showView(); controls();
  if (draft) { if (!view) { busy = true; controls(); try { view = await api('shares/prepare', draft); showView(); } catch (error) { dialogNote(error.message); } finally { busy = false; controls(); } } if (view && !view.requiresConsent && !view.connected) await recover(); }
  else { drawPending(); if (!page) await browse(); }
}
function closeFolders() {
  if (busy) return;
  ++browses;
  if (!view || view.requiresConsent || view.connected) { resetDraft(); pending = []; page = null; drawPending(); }
  folderDialog.close(); controls(); $('open-add').focus();
}
$('open-add').onclick = openFolders;
for (const id of ['close-add','cancel-add','another']) $(id).onclick = closeFolders;
folderDialog.addEventListener('cancel', event => { event.preventDefault(); closeFolders(); });
$('back-edit').onclick = () => { if (busy || !view?.requiresConsent) return; pending = draft.folders.map(f => ({ ...f })); resetDraft(); showView(); dialogNote(); drawPending(); };
$('prepare').onclick = addFolders;
$('confirm').onclick = async () => {
  if (busy || !view?.requiresConsent) return;
  busy = true; controls(); await confirmPrepared(); busy = false; showView();
  if (view.connected) await refreshConnections().catch(error => note(error.message, 'error')); else if (!view.requiresConsent) await recover();
};
$('retry-result').onclick = recover;
$('browse').onclick = () => browse($('path').value.trim()); $('up').onclick = () => page?.parent && browse(page.parent);
function editPath() { if (busy || draft) return; ++browses; page = null; controls(); }
$('path').onfocus = editPath; $('path').oninput = editPath;
$('path').onkeydown = event => { if (event.key === 'Enter') { event.preventDefault(); void browse($('path').value.trim()); } };
$('add-current').onclick = () => page?.selectable && queue(page.path);
$('connection').onchange = () => { if (busy || draft) return; ++browses; pending = []; page = null; view = null; renderShared(); controls(); };
$('refresh').onclick = async () => { note(); await autoRefresh(true); };
$('dismiss-message').onclick = () => note();
function closeTerminal() { if (busy) return; terminalDialog.close(); terminalTarget = null; controls(); }
for (const id of ['close-terminal','cancel-terminal']) $(id).onclick = closeTerminal;
terminalDialog.addEventListener('cancel', event => { event.preventDefault(); closeTerminal(); });
$('confirm-terminal').onclick = () => { if (terminalTarget) void setTerminal(terminalTarget, true); };
async function openRemoval(connectionId, root) {
  if (busy || selected()?.connectionId !== connectionId) return;
  removeTarget = { connectionId, rootId: root.rootId }; removePreview = null;
  $('remove-target').textContent = root.path || root.label;
  $('remove-folders').replaceChildren(); $('remove-overlap').hidden = true; $('remove-retained').hidden = true; $('remove-error').hidden = true;
  removeDialog.showModal(); busy = true; controls();
  try {
    removePreview = await api('shares/remove-prepare', removeTarget);
    folderList($('remove-folders'), removePreview.folders);
    $('remove-overlap').hidden = !removePreview.includesOverlaps;
    $('remove-retained').hidden = !removePreview.retainedChildren?.length;
    text('remove-retained', removePreview.retainedChildren?.length ? `保留 ${removePreview.retainedChildren.length} 项独立子目录共享。` : '');
  } catch (error) { $('remove-error').textContent = error.message; $('remove-error').hidden = false; }
  finally { busy = false; controls(); $('cancel-remove').focus(); }
}
function closeRemoval() { if (busy) return; removeDialog.close(); removePreview = null; removeTarget = null; controls(); }
for (const id of ['close-remove','cancel-remove']) $(id).onclick = closeRemoval;
removeDialog.addEventListener('cancel', event => { event.preventDefault(); closeRemoval(); });
$('confirm-remove').onclick = async () => {
  if (busy || !removePreview) return;
  busy = true; controls();
  try {
    const result = await api('shares/remove-confirm', { requestId: removePreview.requestId, snapshotDigest: removePreview.snapshotDigest, confirmation: 'remove-shares-keep-files-v1' });
    if (result.localRevoked !== true) throw Error('撤销结果未确认，请稍后核对。');
    removeDialog.close(); removePreview = null; removeTarget = null;
    note(result.cloudSynced ? '已移除共享，磁盘文件保留。' : '本机权限已撤销，云端待同步。磁盘文件保留。', result.cloudSynced ? 'success' : '');
    await refreshConnections();
  } catch (error) { $('remove-error').textContent = error.message; $('remove-error').hidden = false; }
  finally { busy = false; controls(); }
};
async function autoRefresh(force = false) {
  if (managementLocked || busy || refreshing || folderDialog.open || terminalDialog.open || removeDialog.open || (!force && document.hidden)) return;
  try {
    await refreshConnections(true);
    const removals = await api('shares/removals').catch(() => null);
    if (removals?.pending.length) $('sync-state').textContent = '撤销待同步';
  } catch (error) {
    if (error.status === 401) return;
    terminalKnown = false; renderShared(); controls();
    $('connection-status').textContent = '状态待同步'; $('connection-status').className = 'status-dot';
    $('sync-state').textContent = '暂未同步'; if (force) note(error.message, 'error');
  }
}
function startPolling() { if (!autoTimer) autoTimer = setInterval(() => { void autoRefresh(); }, 5000); }
let managementWork;
async function restoreManagement() {
  if (busy || managementWork) return managementWork;
  managementWork = (async () => {
    $('retry-management').disabled = true;
    try { await establishManagement(); await refreshConnections(); startPolling(); note(); }
    catch (error) { if (error.status !== 401) note(error.message, 'error'); }
    finally { $('retry-management').disabled = false; managementWork = null; }
  })(); return managementWork;
}
$('retry-management').onclick = restoreManagement;
$('copy-management-entry').onclick = async () => {
  try { await navigator.clipboard.writeText($('management-entry').value); text('copy-management-entry', '已复制'); }
  catch { $('management-entry').focus(); $('management-entry').select(); }
};
$('forget-management').onclick = async () => {
  if (busy || isEditing()) return;
  try { await api('management/logout'); managementExpired(); }
  catch (error) { note(error.message, 'error'); }
};
window.addEventListener('focus', () => { if (managementLocked) void restoreManagement(); else if (Date.now() - lastSync > 800) void autoRefresh(); });
document.addEventListener('visibilitychange', () => { if (!document.hidden) { if (managementLocked) void restoreManagement(); else void autoRefresh(); } });
window.addEventListener('pagehide', () => { clearInterval(autoTimer); autoTimer = null; });
window.addEventListener('pageshow', () => { if (state && !managementLocked) { startPolling(); void autoRefresh(); } });
(async () => {
  try {
    await establishManagement();
    await refreshConnections();
    startPolling();
    try { draft = JSON.parse(sessionStorage.getItem(storageKey) || 'null'); } catch { sessionStorage.removeItem(storageKey); }
    if (draft) {
      if (!connections.some(c => c.connectionId === draft.connectionId)) { note('之前的目录变更所属连接不可用，未继续授权。', 'error'); controls(); return; }
      $('connection').value = draft.connectionId; pending = draft.folders.map(f => ({ ...f })); renderShared();
      await openFolders();
    }
  } catch (error) {
    if (error.status === 401) return;
    note(error.message, 'error'); text('connection-status', '状态未读取');
    if (!state) { text('device', '本机'); $('shared').replaceChildren(element('p', '暂时无法读取状态', 'empty')); }
  }
})();
