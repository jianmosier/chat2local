(() => {
  const message = document.getElementById('recovery-message'), button = document.getElementById('recovery-continue');
  const raw = location.hash.slice(1); history.replaceState(null, '', location.pathname);
  let returnUrl;
  try {
    const values = new URLSearchParams(raw), url = new URL(values.get('return'));
    if (values.getAll('return').length !== 1 || [...values.keys()].some(k => k !== 'return') || url.origin !== document.getElementById('recovery-relay').value || url.pathname !== '/authorize' || url.username || url.password || url.hash || !url.search || url.href.length > 8192) throw Error('Invalid continuation');
    returnUrl = url.href;
  } catch { button.disabled = true; message.textContent = '请从刚才的 chat2local 授权页点击“连接这台电脑”，不要手工填写地址。'; }
  button.addEventListener('click', async () => {
    button.disabled = true; message.textContent = '正在继续原连接…';
    try {
      const response = await fetch('/connect/continue', { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin', body: JSON.stringify({ nonce: document.getElementById('recovery-token').value, confirm: true, returnUrl }), redirect: 'error', signal: AbortSignal.timeout(70000) });
      const value = await response.json(); if (!response.ok || !value.ok) throw Error(value.error || value.message || '连接尚未完成');
      const link = new URL(value.url); if (link.origin !== new URL(returnUrl).origin || link.pathname !== '/link' || link.search || link.username || link.password || !/^[a-f0-9]{32}\.[a-f0-9]{64}$/.test(link.hash.slice(1))) throw Error('连接响应不匹配');
      link.hash = link.hash.slice(1) + '&return=' + encodeURIComponent(returnUrl); location.assign(link.href);
    } catch (error) { message.textContent = error.name === 'TimeoutError' ? '连接等待超时，没有自动重新提交。请返回授权页重试。' : error.message; }
  });
})();
