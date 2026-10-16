import { installationInstructions } from '../shared/installation.mjs';

const escapeHtml = value => String(value).replace(/[&<>"']/g, character => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
})[character]);

export function installerPage(nonce, origin) {
  let windows = '', mac = '';
  // Loopback fixtures may exercise native login, but must not advertise an
  // insecure HTTP download command as a production installation route.
  if (origin.startsWith('https:')) {
    windows = installationInstructions(origin, 'win32').command;
    mac = installationInstructions(origin, 'darwin').command;
  }
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>安装到这台电脑 · Chat2Local</title>
  <script defer src="/install.js"></script>
  <style>
    body { font:16px/1.65 system-ui; background:#f4f6f8; color:#182334; margin:0; padding:24px; }
    main { max-width:600px; margin:5vh auto; background:white; padding:28px; border:1px solid #dce3eb; border-radius:16px; }
    h1 { font-size:28px; line-height:1.25; }
    input,select,button { font:inherit; box-sizing:border-box; max-width:100%; padding:12px; border:1px solid #ccd4df; border-radius:8px; }
    input,select { width:100%; margin:8px 0 16px; }
    button { background:#254fc0; color:white; cursor:pointer; }
    button:disabled { opacity:.5; }
    pre { white-space:pre-wrap; overflow-wrap:anywhere; background:#f4f6f8; padding:16px; font-size:13px; border-radius:8px; }
    small { color:#596777; }
    [hidden] { display:none!important; }
  </style>
</head>
<body><main>
  <strong>Chat2Local · 私人实例</strong><h1>安装到这台电脑</h1>
  <p id="message" role="status">正在检查安装入口…</p>
  <input type="hidden" id="csrf" value="${escapeHtml(nonce)}">
  <section id="download" hidden>
    <label for="platform">这台电脑的系统</label>
    <select id="platform">
      <option value="win32" data-command="${escapeHtml(windows)}">Windows · PowerShell</option>
      <option value="darwin" data-command="${escapeHtml(mac)}">macOS · 终端</option>
    </select>
    <pre id="command"></pre><button id="copy" type="button">复制安装命令</button>
    <p>在这台电脑运行命令，然后输入实例安装密码、选择文件夹并确认。继续使用原 ChatGPT 连接，旧电脑无需在线。</p>
    <p><small>无需预装 Node.js、Git 或 Codex。命令会下载并运行安装器，仅执行自己信任的实例命令。</small></p>
  </section>
  <section id="runner" hidden>
    <p id="machine"></p>
    <form id="login-form" hidden>
      <label for="password">实例安装密码</label>
      <input id="password" type="password" autocomplete="current-password" minlength="16" maxlength="256" required>
      <button id="login" type="submit">登录并继续</button>
      <p><small>不是电脑或 ChatGPT 密码。仅用于加入新电脑，不提供现有文件访问权。</small></p>
    </form>
    <div id="selection" hidden><label for="connection">加入哪个现有连接</label><select id="connection"></select><button id="continue" type="button">继续</button></div>
    <p id="after" hidden>安装器正在连接这台电脑。接下来选择本机文件夹，并确认一次。</p>
  </section>
</main></body>
</html>`;
}

export const installerScript = String.raw`
const $ = id => document.getElementById(id);
const csrf = $('csrf').value;
let ticket = null, busy = false, stopped = false;

async function api(action, body = {}) {
  const response = await fetch('/install/' + action, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Chat2Local-CSRF': csrf },
    body: JSON.stringify(body), credentials: 'same-origin', redirect: 'error',
    signal: AbortSignal.timeout(15000),
  });
  const result = await response.json();
  if (!response.ok) throw Error(result.error || '安装暂未完成');
  return result;
}
function note(text) { $('message').textContent = text; }

async function choose(connectionId = null) {
  if (busy || stopped) return;
  busy = true;
  try {
    await api('authorize', { ...ticket, connectionId });
    $('selection').hidden = true; $('after').hidden = false;
    note('连接信息已交给这台电脑的安装器，无需操作旧电脑。');
  } catch (error) { note(error.message); }
  finally { busy = false; }
}

async function refresh() {
  if (stopped || busy || !ticket) return;
  try {
    const state = await api('context', ticket);
    $('machine').textContent = '当前安装器：' + state.name;
    $('login-form').hidden = state.authenticated || !state.configured;
    if (!state.configured) {
      note('实例尚未设置安装密码。请实例所有者先设置。');
      stopped = true; return;
    }
    if (!state.authenticated) { note('请输入实例安装密码。'); return; }
    if (state.nextUrl) {
      const next = new URL(state.nextUrl);
      if (next.origin !== location.origin || next.pathname !== '/instance/invite'
          || next.search || !/^#[a-f0-9]{32}\.[a-f0-9]{64}$/.test(next.hash)) {
        throw Error('安装返回地址不匹配');
      }
      stopped = true; location.assign(next.href); return;
    }
    if (state.phase !== 'pending') {
      note('正在等待本机安装器接收连接信息…'); $('after').hidden = false; return;
    }
    if (state.connections.length === 1) { await choose(state.connections[0].connectionId); return; }
    if (!state.connections.length) {
      note('此实例还没有可加入的连接，请先完成首次连接。'); return;
    }
    const select = $('connection');
    if (!select.options.length) {
      select.add(new Option('请选择', ''));
      for (const connection of state.connections) {
        select.add(new Option(connection.name + ' · ' + connection.callbackOrigin, connection.connectionId));
      }
    }
    $('selection').hidden = false; note('请选择要加入的原连接。');
  } catch (error) { note(error.message); }
}

$('login-form').onsubmit = async event => {
  event.preventDefault();
  if (busy) return;
  busy = true; $('login').disabled = true;
  const password = $('password').value;
  try {
    await api('login', { password });
    $('login-form').hidden = true;
  } catch (error) { note(error.message); }
  finally {
    $('password').value = ''; busy = false; $('login').disabled = false;
    await refresh();
  }
};
$('continue').onclick = () => { if ($('connection').value) void choose($('connection').value); };

function showDownload() {
  $('download').hidden = false;
  $('platform').value = /Macintosh|Mac OS X/.test(navigator.userAgent) ? 'darwin' : 'win32';
  const update = () => {
    const command = $('platform').selectedOptions[0].dataset.command;
    $('command').textContent = command || '公开安装命令需要 HTTPS 实例地址。';
    $('copy').disabled = !command;
  };
  $('platform').onchange = update; update();
  $('copy').onclick = async () => {
    try {
      await navigator.clipboard.writeText($('command').textContent);
      note('命令已复制，请在这台电脑运行。');
    } catch { note('请复制上方命令。'); }
  };
  note('添加新电脑，或更新这台电脑。');
}

(async () => {
  try {
    if (location.hash) {
      const proof = location.hash.slice(1);
      history.replaceState(null, '', location.pathname);
      if (!/^[a-f0-9]{32}\.[a-f0-9]{64}$/.test(proof)) throw Error('安装请求格式不正确');
      const [id, browser] = proof.split('.'); ticket = { id, browser };
      sessionStorage.setItem('c2l-installer-ticket', JSON.stringify(ticket));
    } else {
      ticket = JSON.parse(sessionStorage.getItem('c2l-installer-ticket') || 'null');
    }
    if (!ticket) { showDownload(); return; }
    $('runner').hidden = false;
    await refresh();
    const timer = setInterval(() => {
      if (stopped) clearInterval(timer); else void refresh();
    }, 2000);
  } catch (error) { note(error.message); }
})();
`;
