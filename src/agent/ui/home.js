const $ = id => document.getElementById(id);
const fragment = location.hash.slice(1);
if (/^[a-f0-9]{64}$/.test(fragment)) { sessionStorage.setItem('chat2local-control', fragment); history.replaceState(null, '', location.pathname); }
const token = sessionStorage.getItem('chat2local-control') || '';
const permissionLabels = { 'read-only': '只读', review: '每次修改前确认', direct: '允许直接读写（自动备份）' };
let state; let stopped = false; let picking = false; let connecting = false; let folderKey = ''; let changeKey = '';
let revision = 0; let refreshNumber = 0; let appliedRefresh = 0;
let browseGeneration = 0; let folderPage; let addingFolder = false; let setupAttempted = false;
const saving = new Set();
function message(text, error = false) { $('message').hidden = false; $('message').textContent = text; $('message').className = error ? 'error' : ''; }
async function api(route, body) {
  const timeout = ['folder/select', 'pick-folder'].includes(route) ? 125000 : route === 'setup/start' ? 70000 : body === undefined ? 5000 : 15000;
  let response;
  try { response = await fetch(`/api/${route}`, { method: body === undefined ? 'GET' : 'POST', headers: { 'X-Chat2Local-Token': token, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }), cache: 'no-store', signal: AbortSignal.timeout(timeout) }); }
  catch (error) { throw new Error(error.name === 'TimeoutError' ? '操作等待已超时；没有自动重试。请查看当前状态后再操作。' : '暂时无法连接本机程序，请确认程序仍在运行。'); }
  const value = await response.json();
  if (!response.ok) throw new Error(value.error || '操作未完成，请稍后重试。');
  return value;
}
function element(tag, text) { const node = document.createElement(tag); if (text !== undefined) node.textContent = text; return node; }
function confirmDirect(path) {
  return confirm(`允许网页 AI 直接创建和修改这个目录中的文本文件？\n${path}\n\n后续普通写入不再逐次要求本机审批；覆盖前保存备份。不允许越界访问、删除或执行命令。\n仅作用于这个目录，可随时改回只读。`);
}
async function action(fn) {
  revision++;
  try { await fn(); } catch (error) { message(error.message, true); }
  finally {
    revision++;
    render();
    if (!stopped) await refresh().catch(() => { $('localState').textContent = '本机状态暂时无法获取；未自动重复提交。'; });
  }
}
function renderControls() {
  if (stopped) return;
  const pickerActive = picking || state?.folderPickerActive;
  $('chooseFolder').disabled = Boolean(pickerActive || !state || state.paused);
  $('chooseFolder').textContent = pickerActive ? '正在选择文件夹' : state?.roots.length ? '添加文件夹' : '选择文件夹';
  $('pickerNotice').hidden = !pickerActive;
  $('folderBrowser').hidden = !picking;
  $('cancelPicker').disabled = addingFolder;
  $('browseGo').disabled = addingFolder; $('browsePath').disabled = addingFolder;
  $('newFolderMode').disabled = addingFolder;
  $('useFolder').textContent = addingFolder ? '正在保存授权…' : { direct: '选择并允许读写', 'read-only': '选择并仅允许查看', review: '选择并逐次确认修改' }[$('newFolderMode').value];
  $('browseUp').disabled = addingFolder || !folderPage?.parent;
  $('pickerMessage').textContent = picking ? '直接在本页选择目录。不会打开新的系统窗口，也不会中断已连接的 AI。' : '维护者目录选择窗口仍在等待，可以点击取消；已有连接不受影响。';
  const used = Boolean(state?.lastRemoteCallAt || state?.hasRemoteUse);
  const online = state?.bridge === 'connected';
  // Folder selection never disables pairing, pause, or existing permissions.
  $('connectChatGPT').disabled = connecting || !state || state.paused || !state.roots.length;
  $('repairConnection').disabled = $('connectChatGPT').disabled;
  $('setupActions').hidden = used;
  $('pauseAccess').textContent = state?.paused ? '恢复访问' : '暂停访问';
  $('localState').textContent = state?.paused ? '本机访问已暂停' : '本机程序正在运行';
  if (state?.paused) $('connection').textContent = '访问已暂停。恢复访问即可继续，不需要重新配对。';
  else if (connecting) $('connection').textContent = '正在打开授权流程… 添加目录和已有文件权限不受影响。';
  else if (used && online) $('connection').textContent = '本机通道在线，已收到远端工具调用。回到原来的 chat2local-mcp 对话继续使用，无需再次点击连接。';
  else if (used) $('connection').textContent = '已有连接正在恢复。无需重新注册；软件会按现有网络设置重连。';
  else if (state?.setup?.code && state.setup.code !== 'NOT_CHECKED') $('connection').textContent = state.setup.message;
  else $('connection').textContent = state?.roots.length ? '目录已添加。首次使用时连接 ChatGPT；这不是目录权限的保存按钮。' : '请先添加一个允许访问的文件夹。';
  $('publication').hidden = state?.setup?.code !== 'PUBLICATION_REQUIRED';
}
function renderFolders() {
  if (!state) return;
  const roots = [...state.roots, ...(state.accountRoots || [])];
  const key = JSON.stringify([roots, [...saving].sort()]);
  if (key === folderKey) return;
  folderKey = key; $('folders').replaceChildren();
  if (!roots.length) $('folders').append(element('p', '尚未开放目录。点击“添加文件夹”选择一个具体目录。'));
  for (const root of roots) {
    const currentMode = root.writeMode || (root.write ? 'review' : 'read-only');
    const row = element('div'); row.className = 'folder';
    const text = element('span', root.path); text.className = 'folder-path';
    const effective = element('small', saving.has(root.id) ? '正在保存权限… 以服务端确认结果为准。' : `当前已生效：${permissionLabels[currentMode]}`);
    effective.className = 'effective-permission'; text.append(effective);
    if (root.accountScoped) {
      text.append(element('small', '账号连接专用；不会开放给旧连接。'));
      const remove = element('button', '撤销本机共享'); remove.disabled = saving.has(root.id);
      remove.addEventListener('click', () => { saving.add(root.id); renderFolders(); void action(async () => {
        try { await api('account-root/remove', { id: root.id }); state.accountRoots = state.accountRoots.filter(item => item.id !== root.id); message('已撤销这个目录的本机访问，不影响其他共享目录。'); }
        finally { saving.delete(root.id); }
      }); });
      row.append(text, remove); $('folders').append(row); continue;
    }
    const controls = element('div'); controls.className = 'folder-controls';
    const label = element('label', '目录权限（更改即保存）');
    const mode = element('select'); mode.setAttribute('aria-label', `${root.label} 目录权限`);
    for (const [value, title] of Object.entries(permissionLabels)) { const option = element('option', title); option.value = value; mode.append(option); }
    mode.value = currentMode; mode.disabled = saving.has(root.id); label.append(mode);
    mode.addEventListener('change', () => {
      const writeMode = mode.value;
      if (writeMode === currentMode || saving.has(root.id)) return;
      if (writeMode === 'direct' && !confirmDirect(root.path)) { mode.value = currentMode; return; }
      saving.add(root.id); renderFolders();
      void action(async () => {
        try {
          const result = await api('root/set-mode', { id: root.id, writeMode, expectedWriteMode: currentMode, confirmDirect: writeMode === 'direct' });
          state.roots = state.roots.map(item => item.id === root.id ? result : item);
          message(result.warning || (writeMode === 'direct' ? '该目录已允许直接读写，权限已保存。无需重新连接；后续使用 write_file。' : '目录权限已保存，无需重新连接。'), Boolean(result.warning));
        } finally { saving.delete(root.id); }
      });
    });
    const remove = element('button', '移除'); remove.disabled = saving.has(root.id);
    remove.addEventListener('click', () => { saving.add(root.id); renderFolders(); void action(async () => { try { await api('root/remove', { id: root.id }); state.roots = state.roots.filter(item => item.id !== root.id); message('已撤销这个目录，不影响其他目录或账号连接。'); } finally { saving.delete(root.id); } }); });
    controls.append(label, remove); row.append(text, controls); $('folders').append(row);
  }
}
function renderChanges() {
  if (!state) return;
  const key = JSON.stringify(state.pending);
  if (key === changeKey) return;
  changeKey = key; $('changes').replaceChildren(); $('approvals').hidden = !state.pending.length;
  for (const op of state.pending) {
    const card = element('article'); card.className = 'change'; card.append(element('strong', `${op.rootLabel} / ${op.path}`));
    const comparison = element('div'); comparison.className = 'compare';
    for (const [label, content] of [['原文', op.before], ['建议修改后', op.content]]) { const group = element('label', label); const field = element('textarea'); field.readOnly = true; field.value = content; group.append(field); comparison.append(group); }
    card.append(comparison);
    for (const [label, approved] of [['确认写入', true], ['拒绝', false]]) {
      const button = element('button', label);
      button.addEventListener('click', () => { button.disabled = true; void action(async () => { try { const result = await api('approve', { operationId: op.operationId, approved }); message(result.status === 'approved' ? '已写入，原文件内容已备份。' : result.status === 'rejected' ? '已拒绝，文件没有修改。' : result.message || '修改未完成。', !['approved', 'rejected'].includes(result.status)); } finally { button.disabled = false; } }); }); card.append(button);
    }
    $('changes').append(card);
  }
}
function render() {
  if (stopped) return;
  if (state?.setupOrigin) $('relayHost').textContent = new URL(state.setupOrigin).hostname;
  if (state?.device) $('deviceIdentity').textContent = `当前电脑：${state.device.name} · ${state.device.system} · ${state.device.arch}`;
  renderControls(); renderFolders(); renderChanges();
}
async function refresh() {
  if (stopped) return;
  const currentRevision = revision; const number = ++refreshNumber;
  const next = await api('status');
  if (stopped || currentRevision !== revision || number < appliedRefresh) return;
  appliedRefresh = number; state = next; render();
}
async function browseFolder(path) {
  if (addingFolder) return;
  const generation = ++browseGeneration;
  folderPage = null; $('useFolder').disabled = true; $('browseEntries').textContent = '正在读取子文件夹…'; $('browseNote').textContent = '';
  try {
    const value = await api('folder/browse', path ? { path } : {});
    if (!picking || generation !== browseGeneration) return;
    folderPage = value; $('browsePath').value = value.path; $('browseNote').textContent = value.note;
    $('browseUp').disabled = !value.parent; $('useFolder').disabled = !value.selectable || addingFolder;
    $('browseLocations').replaceChildren();
    for (const place of value.locations) { const button = element('button', place.label); button.className = 'secondary'; button.addEventListener('click', () => { void browseFolder(place.path); }); $('browseLocations').append(button); }
    $('browseEntries').replaceChildren();
    for (const entry of value.entries) { const button = element('button', `${entry.name}　›`); button.className = 'directory-entry'; button.addEventListener('click', () => { void browseFolder(entry.path); }); $('browseEntries').append(button); }
    if (!value.entries.length) $('browseEntries').append(element('p', '没有可显示的子文件夹；可以使用当前目录。'));
    if (value.truncated) $('browseEntries').append(element('p', '仅显示前 300 个子目录；其他目录可在上方位置框直接打开。'));
  } catch (error) { if (picking && generation === browseGeneration) { $('browseEntries').textContent = error.message; $('browseNote').textContent = '没有授予任何新权限。可以输入其他位置，或取消选择。'; } }
}
$('chooseFolder').addEventListener('click', () => { if (picking || state?.folderPickerActive) return; picking = true; $('newFolderMode').value = 'direct'; $('newFolderOptions').open = false; renderControls(); void browseFolder(); });
$('newFolderMode').addEventListener('change', renderControls);
function editBrowsePath() {
  // Invalidate on focus as well as input: a response may arrive between selecting
  // the old text and inserting new text (including browser autofill/paste).
  browseGeneration++; folderPage = null; $('useFolder').disabled = true;
}
$('browsePath').addEventListener('focus', editBrowsePath);
$('browsePath').addEventListener('input', editBrowsePath);
$('browseGo').addEventListener('click', () => { void browseFolder($('browsePath').value.trim()); });
$('browsePath').addEventListener('keydown', event => { if (event.key === 'Enter') { event.preventDefault(); void browseFolder($('browsePath').value.trim()); } });
$('browseUp').addEventListener('click', () => { if (folderPage?.parent) void browseFolder(folderPage.parent); });
$('useFolder').addEventListener('click', () => {
  if (!folderPage?.selectable || addingFolder) return;
  const path = folderPage.path; const writeMode = $('newFolderMode').value;
  let continueSetup = false;
  addingFolder = true; $('useFolder').disabled = true; renderControls();
  void action(async () => {
    try {
      // This request is sent only by the explicitly labelled confirmation button.
      // Browsing, initial defaults, cancellation and page load grant no access.
      const result = await api('root/add', { path, writeMode, confirmDirect: writeMode === 'direct' });
      state.roots = [...state.roots.filter(root => root.id !== result.id), result];
      picking = false; folderPage = null; browseGeneration++;
      if (result.alreadyAuthorized) {
        message('该目录已在列表中，原权限保持不变。不重复授权或连接；需要更改时使用该目录的权限选项。');
      } else {
        message(`目录授权已保存：${permissionLabels[result.writeMode]}。`);
        continueSetup = !setupAttempted && !connecting && !state.lastRemoteCallAt && !state.hasRemoteUse && state.setup?.code !== 'BROWSER_OPENED';
      }
    } finally { addingFolder = false; $('useFolder').disabled = !folderPage?.selectable; }
  }).then(() => { if (continueSetup && !stopped && !state?.paused) void connect(true); });
});
$('cancelPicker').addEventListener('click', () => {
  if (addingFolder) return;
  picking = false; folderPage = null; browseGeneration++; renderControls();
  if (state?.folderPickerActive) void action(async () => { await api('folder/cancel', {}); message('已取消选择，没有新增目录。已有权限和连接保持不变。'); });
  else message('已取消选择，没有新增目录。已有权限和连接保持不变。');
});
async function connect(afterFolderSelection = false) {
  if (connecting) return;
  setupAttempted = true; connecting = true; renderControls();
  message(`${afterFolderSelection ? '目录授权已保存。' : ''}正在继续连接… 已有目录和权限保持不变。`);
  await action(async () => {
    try {
      const result = await api('setup/start', {});
      state.setup = { ...state.setup, ...result };
      message(`${afterFolderSelection ? '目录授权已保存。' : ''}${result.message}`, !result.ok);
    } catch (error) {
      throw new Error(`${afterFolderSelection ? '目录授权已保存，无需重新选择；连接尚未完成。' : ''}${error.message}`);
    } finally { connecting = false; }
  });
}
$('connectChatGPT').addEventListener('click', () => { void connect(); });
$('repairConnection').addEventListener('click', () => { void connect(); });
$('pauseAccess').addEventListener('click', () => { void action(async () => { const result = await api('pause', { paused: !state.paused }); state.paused = result.paused; }); });
$('exitApp').addEventListener('click', () => { void action(async () => {
  if (!confirm('退出后，网页 AI 将无法访问本机文件。现在退出？')) return;
  await api('shutdown', {}); stopped = true; clearInterval(poll); sessionStorage.removeItem('chat2local-control');
  $('localState').textContent = 'Chat2Local 已退出'; document.querySelectorAll('button,select').forEach(button => { button.disabled = true; });
}); });
refresh().catch(error => message(token ? error.message : '请双击软件启动入口打开此页面，不要手工输入本地地址。', true));
const poll = setInterval(() => refresh().catch(() => { if (!stopped) $('localState').textContent = '本机状态暂时不可用；不要重复配对。'; }), 3000);
