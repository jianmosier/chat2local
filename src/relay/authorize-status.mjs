/** Same-origin readiness check only. Never grants consent or exchanges a token. */
export const authorizeStatusScript = `(() => {
  const direct=document.querySelector('input[name="directWrite"]'), propose=document.querySelector('input[name="propose"]'), approve=document.getElementById('approve');
  const label=()=>{ if(approve) approve.textContent=direct?.checked?'允许读写并继续':propose?.checked?'允许查看和提交建议':'允许查看并继续'; };
  direct?.addEventListener('change',label); propose?.addEventListener('change',label); label();
  const waiting = document.getElementById('waiting-device');
  if (!waiting) return;
  const end = Date.now() + 280000;
  let timer;
  async function check() {
    if (Date.now() >= end) {
      waiting.textContent = '本次授权等待已结束。请先在本机完成连接，再回到 ChatGPT 重新发起授权。无需输入配对码。';
      return;
    }
    try {
      const response = await fetch('/authorize/device-status', {
        headers: { 'X-Chat2Local-Check': '1' }, credentials: 'same-origin',
        cache: 'no-store', signal: AbortSignal.timeout(5000)
      });
      if (response.ok && (await response.json()).linked === true) {
        // Refresh the original validated OAuth request so its consent ticket is
        // freshly bound to this browser's authenticated device. Never POST consent.
        location.reload();
        return;
      }
    } catch { /* Temporary loss leaves the user on the same authorization page. */ }
    timer = setTimeout(check, 1500);
  }
  window.addEventListener('pagehide', () => clearTimeout(timer), { once: true });
  void check();
})();`;
