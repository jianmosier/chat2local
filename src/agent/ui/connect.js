const $ = id => document.getElementById(id);
const fragment = location.hash.slice(1);
if (/^[a-f0-9]{64}$/.test(fragment)) { sessionStorage.setItem('chat2local-control', fragment); history.replaceState(null, '', location.pathname); }
const token = sessionStorage.getItem('chat2local-control') || '';
const labels = { 'read-only': '只读', review: '逐次确认修改', direct: '允许直接读写' };
let state, guide, selected, page, requestId;
let initialized = false, browsing = false, grantBusy = false, connectBusy = false, stopped = false;
let entryChecking = false, entryBlocked = false;
async function detectAccountEntry() {
  try {
    const info = await api('setup/inspect', {});
    if (stopped || state?.paused) return;
    if (info.code === 'ACCOUNT_CONFIGURATION_REQUIRED') { entryBlocked = true; notice(info.message, true); return; }
    if (info.accountEntryUrl) {
      const next = new URL(info.accountEntryUrl), expected = new URL(state.setupOrigin);
      if (next.origin !== expected.origin || next.pathname !== '/account/add' || next.search || next.hash || next.username || next.password) throw new Error('账号入口不匹配，没有打开外部页面。');
      // Fresh installations navigate to the configured account entry BEFORE any
      // legacy folder grant. There is no second consent or copied MCP URL here.
      location.assign(next.href);
    }
  } catch (error) { notice(error.message, true); }
  finally { entryChecking = false; render(); }
}
let generation = 0, selectionGeneration = 0, revision = 0, requested = 0, applied = 0, foldersKey = '';
function notice(text, error = false) { $('notice').hidden = !text; $('notice').textContent = text; $('notice').className = error ? 'error' : ''; }
function el(tag, text) { const item = document.createElement(tag); item.textContent = text; return item; }
async function api(route, body) {
  let response;
  try {
    response = await fetch(`/api/${route}`, { method: body === undefined ? 'GET' : 'POST', headers: { 'X-Chat2Local-Token': token, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }), cache: 'no-store', signal: AbortSignal.timeout(route === 'setup/start' ? 70000 : body === undefined ? 6000 : 15000) });
  } catch { throw Error('暂时无法确认本机响应。已保存的步骤会自动恢复；不会重复提交授权或文件写入。'); }
  const result = await response.json();
  if (!response.ok) throw Error(result.error || '当前步骤未完成。');
  return result;
}
function select(root, checked = false) {
  selected = checked ? { path: root.path, label: root.path.split(/[\\/]/).filter(Boolean).at(-1), expectedRootId: root.existingRoot?.id || null, expectedWriteMode: root.existingRoot?.writeMode || null }
    : { path: root.path, label: root.label, expectedRootId: root.id, expectedWriteMode: root.writeMode || (root.write ? 'review' : 'read-only') };
  requestId = crypto.randomUUID(); selectionGeneration++; render();
}
function render() {
  if (stopped || !state || !guide) return;
  const stage = guide.stage;
  const choosing = stage === 'choose-folder';
  const caps = guide.capabilities;
  const checkingTools = stage === 'check-tools';
  $('capabilityCheck').hidden = !guide.directoryGranted;
  $('capDirectory').textContent = guide.directoryGranted ? '已授权，不需要重选目录' : '尚未授权';
  $('capTransport').textContent = guide.online ? '在线（不代表写工具可用）' : '断线重连中；不发送文件操作';
  $('capServer').textContent = caps?.server.status === 'observed-on-authenticated-call' ? `${caps.server.serverVersion} · ${caps.server.toolNames.length} 项：${caps.server.toolNames.join('、')}` : '未知：尚无本次设备调用的服务端诊断';
  $('capSaved').textContent = '未知：本地程序无法读取；需查看原连接的工具清单与启用状态';
  $('capSession').textContent = caps?.session.status === 'reported' ? `${caps.session.tools.length} 项（会话侧人工核对）：${caps.session.missingTools.length ? '缺少 ' + caps.session.missingTools.join('、') : '所需工具已报告存在，尚不代表写入成功'}` : '未知：不能用服务端工具清单代替当前对话工具';
  $('capScope').textContent = caps?.latestCallWriteScope === true ? '最近一次调用含 files:write；不代表其他会话也已授权' : caps?.latestCallWriteScope === false ? '最近一次调用缺少 files:write；本机目录权限保持有效' : '未知：尚未观察到有效调用的授权范围';
  $('device').textContent = `${state.device.name} · ${state.device.system} · ${state.device.arch}`;
  const target = choosing ? selected : guide.root;
  $('selected').hidden = !target;
  if (target) {
    $('selectedLabel').textContent = target.label || '当前目录'; $('selectedPath').textContent = target.path;
    const mode = target.expectedWriteMode || target.writeMode;
    $('selectedMode').textContent = choosing ? (mode ? `已有权限：${labels[mode]}；下方按钮才会确认此次读写授权。` : '尚未授权。浏览目录不开放访问。') : '此目录已授权；不需要再次选择或保存。';
  }
  const key = JSON.stringify([state.roots, choosing]);
  if (key !== foldersKey) {
    foldersKey = key; $('savedFolders').replaceChildren();
    if (choosing && state.roots.length > 1) for (const root of state.roots) {
      const button = el('button', `${root.label} — ${labels[root.writeMode || (root.write ? 'review' : 'read-only')]}`);
      button.addEventListener('click', () => { if (!grantBusy) select(root); }); $('savedFolders').append(button);
    }
  }
  $('choose').hidden = !choosing; $('choose').disabled = grantBusy || browsing || entryChecking || entryBlocked;
  $('choose').textContent = selected ? '选择其他文件夹' : '选择文件夹';
  $('consent').hidden = !choosing || !selected || browsing;
  $('browser').hidden = !browsing;
  $('cancelBrowse').disabled = grantBusy; $('go').disabled = grantBusy; $('path').disabled = grantBusy; $('up').disabled = grantBusy || !page?.parent;
  $('selectFolder').disabled = grantBusy || !page?.selectable;
  $('primary').hidden = browsing || checkingTools || stage === 'verify' || stage === 'ready';
  $('primary').disabled = grantBusy || connectBusy || entryChecking || entryBlocked || (choosing && !selected) || ['connecting', 'reconnecting'].includes(stage);
  $('goChat').hidden = !['check-tools', 'verify', 'ready', 'platform-consent'].includes(stage);
  $('goChat').textContent = checkingTools ? '复制只读检查指令并前往 ChatGPT' : stage === 'platform-consent' ? '前往 ChatGPT 完成原连接授权' : stage === 'ready' ? '回到 ChatGPT 开始工作' : '复制验证指令并前往 ChatGPT';
  $('verification').hidden = !checkingTools && stage !== 'verify'; $('prompt').value = checkingTools ? guide.toolCheckPrompt : guide.verificationPrompt;
  $('instructionText').textContent = checkingTools ? '在原 chat2local 对话中核对实际工具并调用 list_roots。此步骤不创建、不修改文件，也不重新授权目录。' : '工具与授权检查后再发起原测试；只有真实创建、备份修改和读回才会标记完成。';
  const messages = {
    'choose-folder': ['选择目录，一次确认', state.roots.length ? '已识别原来的插件和设备。可以使用已有目录，也可以另选一个；不会重建身份。' : '选择愿意交给 chat2local 读取和修改的具体文件夹。', '允许读写并继续'],
    connect: ['目录已保存，继续连接', guide.setup?.message || '程序负责设备登记和打开必要的授权步骤。无需配置端口、隧道或密钥。', '继续连接'],
    connecting: ['正在连接…', '正在沿用当前设备准备连接；授权已保存。等待期间仍可暂停或退出。', '正在连接…'],
    'platform-consent': ['只剩平台确认', '已打开必要的授权页面。使用同一个 chat2local 连接完成确认后，在 ChatGPT 发起一次调用；此页会自动推进。', '重新打开授权步骤'],
    'check-tools': [caps?.session.missingTools?.includes('write_file') ? '当前对话缺少 write_file' : caps?.latestCallWriteScope === false ? '当前调用尚无直接写权限' : '先检查网页工具与权限', '目录授权已完成。先分清线上服务声明、ChatGPT 保存并启用的工具、当前对话工具和 OAuth 权限；未知项目保持未知，不再直接要求写文件。', '检查工具'],
    verify: ['连接已用过，验证真实读写', '不再重复绑定电脑。请把一条验证指令交给现有 chat2local；我们只在观察到真实的创建、修改和读回后标记完成。', '验证'],
    ready: ['这台电脑的读写已验证', '已观察到经远端客户端创建测试文件、覆盖前备份、修改以及一致的读回。无需再点“完成”。', '完成'],
    reconnecting: ['正在恢复已有连接', '保留原目录和授权，等待当前电脑重新上线。不会新建设备或将请求转到另一台电脑。', '等待恢复…'],
    paused: ['访问已暂停', '没有重新授权或恢复文件访问。恢复后继续原来的步骤。', '恢复访问'],
  };
  const text = messages[stage] || messages.connect;
  $('eyebrow').textContent = guide.previousRemoteUse ? '已有连接 · 统一接入向导' : '新电脑 · 统一接入向导';
  $('heading').textContent = text[0]; $('explanation').textContent = text[1]; $('primary').textContent = grantBusy ? '正在保存这一项授权…' : text[2];
  for (const [id, completed, active] of [['stepFolder', guide.directoryGranted, choosing], ['stepConnection', guide.online && Boolean(guide.evidence.createdAt || caps?.mayAttemptWrite), ['connect', 'connecting', 'platform-consent', 'check-tools'].includes(stage)], ['stepVerify', guide.complete, stage === 'verify']]) $('' + id).className = completed ? 'done' : active ? 'active' : '';
  for (const [id, field, label] of [['created', 'createdAt', '创建'], ['updated', 'updatedAt', '修改并备份'], ['readback', 'readBackAt', '读回一致']]) {
    $('' + id).textContent = `${guide.evidence[field] ? '✓' : '○'} ${label}`; $('' + id).className = guide.evidence[field] ? 'done' : '';
  }
  $('nextHint').textContent = guide.warning || (checkingTools ? '无需重装或重配目录。检查工具名与启用状态；只有实际缺少 OAuth 范围时才处理原连接授权。' : stage === 'verify' ? '本地权限已处理。若平台缺少工具或要求确认，只处理平台当前提示，不要再回来修改目录开关。' : '');
  $('endpoint').textContent = state.mcpUrl ? `同一个插件入口：${state.mcpUrl}` : '';
  $('retryBinding').disabled = connectBusy || !guide.directoryGranted || state.paused;
  $('cancelGuide').disabled = grantBusy || !guide.attemptId;
  $('pause').disabled = false; $('exit').disabled = false; $('pause').textContent = state.paused ? '恢复访问' : '暂停访问';
  $('localStatus').textContent = state.paused ? '已暂停' : '本机程序正在运行';
}
async function refresh() {
  if (stopped) return;
  const rev = revision, number = ++requested;
  const [nextState, nextGuide] = await Promise.all([api('status'), api('guide')]);
  if (stopped || rev !== revision || number < applied) return;
  applied = number; state = nextState; guide = nextGuide;
  if (!initialized) {
    initialized = true;
    if (!guide.attemptId && state.roots.length === 1) select(state.roots[0]);
    if (!state.paused && !state.device?.deviceId && state.roots.length === 0 && !(state.accountRoots || []).length) { entryChecking = true; void detectAccountEntry(); }
  }
  render();
}
async function action(fn) {
  revision++;
  try { await fn(); } catch (error) { notice(error.message, true); }
  finally { revision++; await refresh().catch(error => notice(error.message, true)); render(); }
}
async function browse(path) {
  if (grantBusy) return;
  const current = ++generation; page = null; $('entries').textContent = '正在列出本机文件夹…'; render();
  try {
    const result = await api('folder/browse', path ? { path } : {});
    if (!browsing || generation !== current) return;
    page = result; $('path').value = result.path; $('browseNote').textContent = result.note;
    $('places').replaceChildren(); $('entries').replaceChildren();
    for (const place of result.locations) { const button = el('button', place.label); button.className = 'secondary'; button.addEventListener('click', () => { void browse(place.path); }); $('places').append(button); }
    for (const entry of result.entries) { const button = el('button', `${entry.name}　›`); button.addEventListener('click', () => { void browse(entry.path); }); $('entries').append(button); }
    if (!result.entries.length) $('entries').append(el('p', '没有可显示的子目录。'));
    if (result.truncated) $('entries').append(el('p', '显示前 300 个目录；其他位置可在上方输入。'));
  } catch (error) { if (browsing && current === generation) $('entries').textContent = error.message; }
  render();
}
async function authorize() {
  if (!selected || grantBusy) return;
  const target = { ...selected }; const intent = requestId; grantBusy = true; render();
  let continueConnection = false;
  await action(async () => {
    try {
      guide = await api('guide/authorize', { path: target.path, expectedRootId: target.expectedRootId, expectedWriteMode: target.expectedWriteMode, requestId: intent, confirmDirect: true });
      browsing = false; page = null; generation++; notice('目录与接入进度已保存，继续下一步。');
      continueConnection = guide.stage === 'connect';
    } finally { grantBusy = false; }
  });
  if (continueConnection && guide?.stage === 'connect' && !stopped) await connect();
}
async function connect() {
  if (connectBusy || state?.paused) return;
  connectBusy = true; notice('正在准备必要的连接步骤；目录授权已保留。'); render();
  await action(async () => { try { const result = await api('setup/start', {}); notice(result.message, !result.ok); } finally { connectBusy = false; } });
}
$('choose').addEventListener('click', () => { if (!grantBusy) { browsing = true; render(); void browse(selected?.path); } });
$('cancelBrowse').addEventListener('click', () => { if (!grantBusy) { browsing = false; page = null; generation++; render(); notice('已取消选择，没有更改任何目录权限。'); } });
for (const event of ['focus', 'input']) $('path').addEventListener(event, () => { generation++; page = null; render(); });
$('go').addEventListener('click', () => { void browse($('path').value.trim()); });
$('path').addEventListener('keydown', event => { if (event.key === 'Enter') { event.preventDefault(); void browse($('path').value.trim()); } });
$('up').addEventListener('click', () => { if (page?.parent) void browse(page.parent); });
$('selectFolder').addEventListener('click', () => { if (page?.selectable && !grantBusy) { select(page, true); void authorize(); } });
$('primary').addEventListener('click', () => { if (guide?.stage === 'choose-folder') void authorize(); else if (guide?.stage === 'paused') void action(() => api('pause', { paused: false })); else void connect(); });
$('goChat').addEventListener('click', () => {
  if (!['check-tools', 'verify'].includes(guide?.stage)) return;
  // The anchor opens ChatGPT through the user's own click. No invented install URL,
  // private API, ChatGPT cookie, or automatic account action is used.
  navigator.clipboard.writeText(guide.stage === 'check-tools' ? guide.toolCheckPrompt : guide.verificationPrompt).then(() => notice('当前步骤指令已复制。检查步骤仅列工具和读目录，不写测试文件。')).catch(() => { $('promptDetails').open = true; $('prompt').select(); notice('浏览器未允许复制，请从展开的指令框手动复制。', true); });
});
$('retryBinding').addEventListener('click', () => { void connect(); });
$('cancelGuide').addEventListener('click', () => { if (guide?.attemptId) void action(async () => { await api('guide/cancel', { attemptId: guide.attemptId }); notice('本轮向导已结束，原目录权限与插件身份保持不变。'); }); });
$('pause').addEventListener('click', () => { void action(() => api('pause', { paused: !state.paused })); });
$('exit').addEventListener('click', () => { if (confirm('退出 chat2local 后网页将不能访问本机。现在退出？')) void action(async () => { await api('shutdown', {}); stopped = true; clearInterval(poll); sessionStorage.removeItem('chat2local-control'); $('localStatus').textContent = '已退出'; document.querySelectorAll('button').forEach(button => { button.disabled = true; }); $('goChat').hidden = true; }); });
refresh().catch(error => notice(token ? error.message : '请通过 chat2local 启动入口打开向导，不要手工输入本机地址。', true));
const poll = setInterval(() => refresh().catch(() => { if (!stopped) $('localStatus').textContent = '正在等待本机状态恢复，不需要重新配对。'; }), 2000);
