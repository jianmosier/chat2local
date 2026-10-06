// Reusable one-decision view for the new authenticated account flow.
// The supplied API must be an authenticated same-origin native/account adapter.
// This component is not installed on the legacy homepage by this refactor.
export function mountConsentCard(host, api) {
  const make = (tag, text) => { const node = document.createElement(tag); if (text) node.textContent = text; return node; };
  const title = make('h1', '连接所选文件夹');
  const summary = make('dl');
  const details = ['账号', '应用', '电脑', '文件夹'].map(label => { const term = make('dt', label), value = make('dd'); summary.append(term, value); return value; });
  const scope = make('p', '允许读取、创建和修改文本；覆盖前备份。仅限以上文件夹，可随时撤销。');
  const button = make('button', '允许读写并连接'); button.type = 'button'; button.disabled = true;
  const status = make('p'); status.setAttribute('role', 'status'); status.setAttribute('aria-live', 'polite');
  host.replaceChildren(title, summary, scope, button, status);
  let view, busy = false, disposed = false, generation = 0, errorMessage = ''; 
  function render() {
    if (disposed) return;
    if (!view) { button.disabled = true; return; }
    details[0].textContent = view.accountLabel; details[1].textContent = view.clientLabel;
    details[2].textContent = view.deviceLabel; details[3].textContent = view.folderLabels.join('\n');
    const readonly = !view.scopes.includes('files:write');
    scope.textContent = readonly ? '仅允许读取以上文件夹中的文本，不修改文件；可随时撤销。' : '允许读取、创建和修改文本；覆盖前备份。仅限以上文件夹，可随时撤销。';
    title.textContent = view.connected ? '文件夹已连接' : view.requiresConsent ? '连接所选文件夹' : '正在继续原来的连接';
    button.hidden = view.connected || !view.requiresConsent;
    button.disabled = busy;
    button.textContent = readonly ? '允许查看并连接' : '允许读写并连接';
    status.textContent = view.connected ? '连接已建立。后续直接在原 chat2local 对话中使用。' : errorMessage || (busy ? '正在连接，已确认的步骤不会重复询问…' : view.requiresConsent ? '确认一次，后续绑定和连接由程序完成。' : '本次确认已保存，正在核对连接结果；没有重复写入文件。');
  }
  async function load() {
    const current = ++generation;
    const next = await api.load();
    if (disposed || current !== generation) return;
    view = next; render();
  }
  async function submit() {
    if (busy || !view?.requiresConsent) return;
    busy = true; errorMessage = ''; render();
    try {
      // One event carrying the exact displayed snapshot. No browser/device/OAuth
      // secondary button is auto-clicked; the coordinator executes this intent.
      await api.confirm({ intentId: view.intentId, snapshotDigest: view.snapshotDigest, confirmation: 'allow-shared-folders-v1' });
      await load();
    } catch {
      // Reconcile first: a lost response must not ask for a second authorization.
      try {
        await load();
        if (!view.requiresConsent && !view.connected) { await api.resume(view.intentId); await load(); }
      } catch { errorMessage = '连接暂未恢复；已保存本次选择和确认，请勿重新授权。'; }
    } finally { busy = false; render(); }
  }
  button.addEventListener('click', () => { void submit(); });
  const ready = load().catch(() => { button.hidden = true; status.textContent = '尚未取得已验证的账号和连接信息，未授权任何文件夹。'; });
  return { ready, refresh: load, dispose() { disposed = true; generation++; host.replaceChildren(); } };
}
