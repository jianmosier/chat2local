const $ = id => document.getElementById(id);
const nonce = $('account-nonce').value;
const privateMode = location.pathname === '/instance-connect';
const localPrefix = privateMode ? '/instance-connect/' : '/account-connect/';
const cloudPrefix = privateMode ? '/instance' : '/account';
const storageKey = privateMode ? 'chat2local-instance-flow' : 'chat2local-account-flow';
let bootstrap, current, busy = false, retries = 0, stopped = false, feedback = ''; 
function message(text) { $('account-status').textContent = text; }
async function api(action, input = {}) {
  const response = await fetch(localPrefix + action, { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin', body: JSON.stringify({ nonce, ...input }), redirect: 'error', signal: AbortSignal.timeout(action === 'choose' ? 125000 : 65000) });
  const result = await response.json(); if (!response.ok) throw Object.assign(new Error(result.error || '连接暂时未完成'), { status: response.status }); return result;
}
function render() {
  if (!current || stopped) return;
  $('account-summary').hidden = false;
  $('account-name').textContent = current.displayName || '已验证账号';
  $('account-client').textContent = `${current.clientName || '请求应用'} · ${current.callbackOrigin || '回调站点未知'}`;
  $('account-device').textContent = current.deviceName || '这台电脑';
  const modes = { direct: '允许读写，覆盖前备份', review: '修改需本机确认', 'read-only': '只读' };
  $('account-folder').textContent = current.selection?.path || '尚未选择';
  if (current.reuseExisting) {
    document.querySelector('h1').textContent = '恢复已有连接';
    $('account-folder').textContent = '';
    for (const item of current.selections || []) {
      const row = document.createElement('p'); row.textContent = `${item.path} — ${modes[item.mode] || '权限未知'}`; $('account-folder').append(row);
    }
    $('account-note').textContent = '沿用上方已有目录，不重新选文件夹、不重新配对、不增加权限。';
  }
  $('account-callback').textContent = '已登记的应用回调站点：' + (current.callbackOrigin || '未知');
  $('account-choose').hidden = Boolean(current.snapshotDigest);
  $('account-choose').disabled = busy;
  $('account-choose').textContent = current.selection ? '继续准备所选文件夹' : '选择文件夹';
  $('account-permission').hidden = !current.snapshotDigest;
  $('account-permission').textContent = current.reuseExisting ? '此次仅授权上方请求应用访问列出的原有目录，权限以每个目录旁的说明为准。不删除文件、不执行命令、不开放其他目录。' : current.selection?.mode === 'direct' ? '允许上方应用读取、创建和修改这个文件夹中的文本，覆盖前备份。不删除文件，不执行命令，不开放其他目录。' : '仅允许上方应用读取这个文件夹中的文本，不修改文件。';
  $('account-confirm').hidden = !current.requiresConsent;
  $('account-confirm').disabled = busy;
  $('account-confirm').textContent = current.reuseExisting ? '确认以上范围并恢复连接' : current.selection?.mode === 'direct' ? '允许读写并连接' : '允许查看并连接';
  if (current.terminalRequested) {
    $('account-permission').hidden = false;
    $('account-permission').textContent += ' 此次还授权 terminal:execute（终端执行）：仅在本机另外启用终端的目录生效。终端以系统用户权限运行，不是目录沙箱，可能修改或删除目录外文件、访问网络。';
  }
  if (current.connected) {
    message('共享已保存，正在返回原来的 ChatGPT 连接…');
    const finish = new URL(current.finishUrl);
    if (finish.origin !== bootstrap.origin || finish.pathname !== cloudPrefix + '/finish' || finish.searchParams.get('flow') !== current.flowId || finish.hash) throw new Error('返回地址不匹配，未跳转。');
    stopped = true; location.assign(finish.href);
  } else if (current.requiresConsent) message(current.reuseExisting ? '已找到这台电脑原有的目录授权。核对请求应用和范围后，只需确认一次。' : privateMode ? '核对自己的实例、应用和文件夹，确认一次即可。' : '核对上方账号、应用和文件夹，确认一次即可。');
  else if (current.phase === 'choose-folder') message(privateMode ? '私人实例邀请已验证。选择文件夹后，只需确认一次；无需第三方登录。' : '账号已识别。先选择要交给这个连接的文件夹，选择本身不开放访问。');
  else message('此前的确认已保存，正在继续同一次连接…');
  if (feedback && !current.connected) message(feedback);
}
async function recover() {
  if (stopped || busy || !current || current.requiresConsent || current.phase === 'choose-folder') return;
  busy = true; feedback = '';
  try { current = await api('resume', { flowId: current.flowId }); retries = 0; render(); }
  catch { feedback = '连接暂未完成；已保存的确认不会丢失，也不会重复授权。'; message(feedback); if (++retries <= 3) setTimeout(recover, 2000 * retries); }
  finally { busy = false; renderWithoutNavigationError(); }
}
function renderWithoutNavigationError() { try { render(); } catch (error) { message(error.message); } }
$('account-choose').addEventListener('click', async () => {
  if (busy || !current) return;
  busy = true; feedback = ''; render(); message('请在系统窗口选择文件夹。');
  try { current = await api('choose', { flowId: current.flowId }); }
  catch (error) { feedback = error.message; message(feedback); }
  finally { busy = false; renderWithoutNavigationError(); }
});
$('account-confirm').addEventListener('click', async () => {
  if (busy || !current?.requiresConsent) return;
  busy = true; feedback = ''; render(); message('正在保存这一项授权并连接…');
  try { current = await api('confirm', { flowId: current.flowId, snapshotDigest: current.snapshotDigest, confirmation: 'allow-shared-folders-v1' }); }
  catch (error) {
    try { current = await api('status', { flowId: current.flowId }); }
    catch { current = { ...current, requiresConsent: false, phase: 'outcome-unknown' }; feedback = '暂时无法核对结果。不要重新授权；程序将核对原请求。'; }
    if (!feedback) feedback = error.message;
    message(feedback);
  } finally { busy = false; renderWithoutNavigationError(); }
  if (!current.requiresConsent && !current.connected) void recover();
});
(async () => {
  try {
    if (location.hash) {
      const query = new URLSearchParams(location.hash.slice(1));
      if (query.getAll('origin').length !== 1 || query.getAll('flow').length !== 1 || [...query.keys()].some(k => !['origin','flow'].includes(k))) throw new Error('连接链接格式不正确。');
      bootstrap = { origin: query.get('origin'), flow: query.get('flow') };
      history.replaceState(null, '', location.pathname);
      sessionStorage.setItem(storageKey, JSON.stringify(bootstrap));
    } else bootstrap = JSON.parse(sessionStorage.getItem(storageKey) || 'null');
    if (!bootstrap) throw new Error('请从原 chat2local 连接入口继续，不要手工填写本机地址。');
    for (let attempt = 0; ; attempt++) {
      try { current = await api('start', bootstrap); break; }
      catch (error) {
        if (attempt >= 2 || (error.status && error.status < 500)) throw error;
        message('正在恢复同一次接入请求，不重建设备、不重复授权…');
        await new Promise(resolve => setTimeout(resolve, 1000 * (attempt + 1)));
      }
    }
    render();
    if (!current.requiresConsent && current.phase !== 'choose-folder' && !current.connected) void recover();
  } catch (error) { message(error.message); }
})();
