import { parseInvitation, connectionSteps, helpfulError } from './onboarding.js';
const $ = id => document.getElementById(id);
const hashToken = location.hash.slice(1);
if (/^[a-f0-9]{64}$/.test(hashToken)) { sessionStorage.setItem('chat2local-control', hashToken); history.replaceState(null, '', location.pathname); }
const token = sessionStorage.getItem('chat2local-control') || '';
let state; let pendingKey = ''; let rootsKey = ''; let stopped = false; let pairExpiresAt = 0; let networkDirty = false;
function notice(message, error = false) { $('notice').hidden = false; $('notice').textContent = error ? helpfulError(message) : message; $('notice').className = error ? 'error' : ''; }
async function api(route, body) {
  const response = await fetch(`/api/${route}`, { method: body === undefined ? 'GET' : 'POST', headers: { 'X-Chat2Local-Token': token, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }), cache: 'no-store' });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `请求失败 (${response.status})`);
  return data;
}
function bind(id, action) { $(id).addEventListener('click', async () => { $(id).disabled = true; try { await action(); await refresh(); } catch (error) { notice(error.message, true); } finally { $(id).disabled = false; } }); }
function el(tag, text, className) { const node = document.createElement(tag); if (text !== undefined) node.textContent = text; if (className) node.className = className; return node; }
async function refresh() {
  if (stopped) return;
  state = await api('status');
  const steps = connectionSteps(state);
  for (const [id, complete, label] of [['stepFolder', steps.folder, '1　选择文件夹'], ['stepRelay', steps.relay, '2　连接入口'], ['stepClient', steps.verified, '3　验证远端调用']]) {
    $(id).textContent = `${complete ? '✓ ' : ''}${label}`; $(id).classList.toggle('complete', complete);
  }
  $('clientBadge').textContent = steps.verified ? '已收到远端调用' : '尚未验证';
  $('clientDetail').textContent = steps.verified ? `最近一次成功远端工具调用：${new Date(state.lastRemoteCallAt).toLocaleTimeString()}。这不代表客户端已获得写入权限。` : '收到真实远端工具调用后，顶部第三步才会标记为已验证。';
  if (pairExpiresAt && Date.now() >= pairExpiresAt) { $('pairValue').value = ''; $('pairBox').hidden = true; pairExpiresAt = 0; }
  if (!state.mcpUrl) { $('pairBox').hidden = true; $('pairValue').value = ''; }
  const names = { connected: '电脑已连接中继', connecting: '正在连接中继', reconnecting: '连接中断，正在重试', disconnected: '中继未连接', 'not-configured': '本地已就绪，尚未配置中继' };
  $('status').textContent = state.paused ? 'AI 访问已暂停' : (names[state.bridge] || state.bridge);
  $('statusDetail').textContent = state.paused ? '本机已拒绝新的文件操作。未确认建议已取消。' : `本地面板正在运行；当前授权 ${state.roots.length} 个目录，写入按各目录权限执行。`;
  $('statusDot').className = 'dot ' + (state.paused ? 'paused' : state.bridge === 'connected' ? 'connected' : '');
  $('pause').textContent = state.paused ? '恢复访问' : '暂停访问';
  $('mcpUrl').value = state.mcpUrl || '';
  $('relayBadge').textContent = state.bridge === 'connected' ? '已连接' : '未连接';
  $('startup').checked = state.startup;
  if (!networkDirty) {
    $('networkMode').value = state.networkSettings?.mode || 'auto';
    $('networkProxy').value = state.networkSettings?.proxy || '';
    $('networkProxy').disabled = $('networkMode').value !== 'proxy';
  }
  const networkNames = { 'not-checked': '尚未检查远端网络', 'loopback': '本机回环直连', 'direct': '应用层直连，使用系统路由', 'system-direct': '系统未要求代理，使用系统路由', 'system-proxy': '使用系统为此入口选择的代理', 'environment': '按已有代理环境变量及绕过规则连接', 'manual-proxy': '使用你指定的代理', 'error': '网络配置暂不可用' };
  $('networkStatus').textContent = state.network?.error || networkNames[state.network?.source] || '尚未检查远端网络';
  if (document.activeElement !== $('relayUrl')) $('relayUrl').value = state.relay || '';
  const nextRoots = JSON.stringify(state.roots);
  if (nextRoots !== rootsKey) {
    rootsKey = nextRoots; $('roots').replaceChildren();
    if (!state.roots.length) $('roots').append(el('div', '尚未授权目录。你可以先用示例体验，再选择自己的项目。', 'empty'));
    for (const root of state.roots) {
      const row = el('div', undefined, 'root'); const info = el('div', undefined, 'root-info');
      info.append(el('strong', root.label), el('small', root.path));
      const mode = el('span', root.writeMode === 'direct' ? '直接读写' : root.write ? '逐次确认' : '只读', 'pill'); const remove = el('button', '撤销授权', 'secondary');
      remove.addEventListener('click', async () => { try { await api('root/remove', { id: root.id }); await refresh(); } catch (error) { notice(error.message, true); } });
      row.append(info, mode, remove); $('roots').append(row);
    }
  }
  const pending = state.pending;
  $('approvalCount').textContent = `${pending.length} 项`;
  const nextPending = JSON.stringify(pending);
  if (nextPending !== pendingKey) {
    pendingKey = nextPending; $('pending').replaceChildren();
    if (!pending.length) $('pending').append(el('div', '没有待确认写入。AI 的建议会先显示在这里，不会直接覆盖文件。', 'empty'));
    for (const op of pending) {
      const card = el('article', undefined, 'proposal'); card.append(el('div', `${op.rootLabel} / ${op.path}`, 'proposal-title'));
      const comparison = el('div', undefined, 'compare');
      for (const [label, value] of [['原文', op.before], ['建议写入的完整内容', op.content]]) {
        const column = el('div'); const text = el('textarea'); text.value = value; text.readOnly = true; text.setAttribute('aria-label', label); column.append(el('label', label), text); comparison.append(column);
      }
      const actions = el('div', undefined, 'actions');
      for (const [label, approved, style] of [['确认写入', true, 'primary'], ['拒绝', false, 'danger']]) {
        const button = el('button', label, style);
        button.addEventListener('click', async () => {
          button.disabled = true;
          try { const result = await api('approve', { operationId: op.operationId, approved }); notice(result.status === 'approved' ? '已写入。原有内容已在本机保留备份。' : result.status === 'rejected' ? '已拒绝，没有修改文件。' : `没有完成写入：${result.message || result.status}`, result.status === 'failed'); await refresh(); }
          catch (error) { notice(error.message, true); button.disabled = false; }
        }); actions.append(button);
      }
      card.append(comparison, actions); $('pending').append(card);
    }
  }
  $('events').replaceChildren();
  const actionNames = { read: '读取', proposed: '提交建议', rejected: '拒绝写入', written: '完成写入' };
  for (const event of state.events.slice().reverse().slice(0, 20)) {
    const row = el('div', undefined, 'event'); row.append(el('b', actionNames[event.action] || event.action), document.createTextNode(` · ${new Date(event.at).toLocaleTimeString()} · ${event.path || event.operationId || ''}`)); $('events').append(row);
  }
  if (!state.events.length) $('events').append(el('div', '还没有文件操作记录。'));
}
$('networkMode').addEventListener('change', () => { networkDirty = true; $('networkProxy').disabled = $('networkMode').value !== 'proxy'; });
$('networkProxy').addEventListener('input', () => { networkDirty = true; });
bind('saveNetwork', async () => {
  const mode = $('networkMode').value;
  await api('network/set', { mode, ...(mode === 'proxy' ? { proxy: $('networkProxy').value.trim() } : {}) });
  networkDirty = false; notice('网络选择已保存。只重建连接，不会重复执行之前的文件操作。');
});
bind('checkNetwork', async () => {
  if (networkDirty) throw new Error('请先保存网络选择，再检测连接。');
  let origin = state?.relay || $('relayUrl').value.trim();
  if (!origin && $('invitation').value) origin = parseInvitation($('invitation').value).origin;
  if (!origin) throw new Error('请先填写可信入口地址或粘贴连接邀请。');
  const result = await api('network/check', { origin }); notice(result.message, !result.ok);
});
bind('browse', async () => { const { path } = await api('pick-folder', {}); if (path) $('folderPath').value = path; });
bind('addFolder', async () => { await api('root/add', { path: $('folderPath').value, write: $('allowWrite').checked }); $('folderPath').value = ''; $('allowWrite').checked = false; notice('目录已授权。所有写入仍需在本机逐次确认。'); });
bind('pause', async () => { await api('pause', { paused: !state.paused }); });
bind('demo', async () => { await api('demo', {}); notice('本地 MCP 演示已读取示例文件并提交修改建议。请在下方审查并确认；这不是一次真实 AI 调用。'); $('approvals').scrollIntoView({ behavior: 'smooth' }); });
$('invitation').addEventListener('input', () => {
  try { $('invitePreview').textContent = `将连接：${parseInvitation($('invitation').value).origin}。确认你信任这个入口后再点击连接。`; }
  catch { $('invitePreview').textContent = '请粘贴完整邀请；在你点击连接前，不会发出网络请求。'; }
});
bind('connectInvite', async () => {
  const invitation = parseInvitation($('invitation').value);
  if (!window.confirm(`允许将这台电脑注册到 ${invitation.origin}？\n文件请求会经过该入口，仅继续使用你信任的服务。`)) return;
  await api('enroll', invitation); $('invitation').value = ''; $('invitePreview').textContent = '邀请已使用并从输入框清除。'; notice('设备已注册。接下来在网页 AI 中添加应用并完成授权。');
});
bind('copyPrompt', async () => { await navigator.clipboard.writeText('请使用 Chat2Local 列出我授权的文件夹，不要修改任何文件。'); notice('验证用语已复制。请在聊天中选中 Chat2Local，再发送。'); });
bind('connect', async () => { await api('enroll', { origin: $('relayUrl').value.trim(), enrollmentToken: $('enrollmentKey').value }); $('enrollmentKey').value = ''; notice('设备已注册，正在建立出站连接。'); });
bind('disconnect', async () => { const result = await api('disconnect', {}); $('pairBox').hidden = true; $('pairValue').value = ''; notice(result.remoteRevoked ? '本机已断开并暂停访问，云端设备授权已撤销。' : result.warning, !result.remoteRevoked); });
bind('pair', async () => { const { code, expiresAt } = await api('pair-code', {}); $('pairValue').value = code; $('pairBox').hidden = false; pairExpiresAt = new Date(expiresAt).getTime() || Date.now() + 300000; $('pairExpiry').textContent = `有效期至 ${new Date(pairExpiresAt).toLocaleTimeString()}，仅可使用一次。`;  });
bind('copyUrl', async () => { if (!$('mcpUrl').value) throw new Error('尚未配置中继。'); await navigator.clipboard.writeText($('mcpUrl').value); notice('MCP 地址已复制。在 AI 客户端选择 OAuth 认证。'); });
bind('copyPair', async () => { await navigator.clipboard.writeText($('pairValue').value); notice('配对码已复制，仅用于可信的 Chat2Local 授权页面。'); });
$('startup').addEventListener('change', async () => { try { await api('startup', { enabled: $('startup').checked }); notice('Windows 登录启动设置已更新。'); } catch (error) { notice(error.message, true); } await refresh().catch(() => {}); });
refresh().catch(error => notice(token ? error.message : '缺少本机访问令牌。请双击 Chat2Local 启动入口重新打开面板。', true));
const poll = setInterval(() => refresh().catch(() => { if (!stopped) $('status').textContent = '本地程序连接不可用，请重新双击启动'; }), 4000);
$('shutdown').addEventListener('click', async () => {
  if (!window.confirm('完全退出后，网页 AI 将无法访问本机文件。下次使用请重新双击启动。现在退出？')) return;
  try { await api('shutdown', {}); stopped = true; clearInterval(poll); sessionStorage.removeItem('chat2local-control'); $('status').textContent = 'Chat2Local 已退出'; $('statusDetail').textContent = '现在可以关闭这个页面。'; $('statusDot').className = 'dot'; document.querySelectorAll('button,input,select').forEach(node => { node.disabled = true; }); notice('程序已停止接收请求。下次请双击启动文件。'); }
  catch (error) { notice(error.message, true); }
});
