import { installationInstructions } from './installation.js';

/** Manage this computer only; all mutations still use the authenticated API. */
export function attachLifecycle({ api, getState, isBusy, isLocked, setBusy, updateState, note, onShutdown }) {
  const $ = id => document.getElementById(id);
  const exitDialog = $('shutdown-dialog');
  let pending = false;
  let pendingStartup = null;
  let shutdownRequested = false;

  function platform() {
    const native = getState()?.device?.platform;
    if (native) return native;
    return /Macintosh|Mac OS X/.test(navigator.userAgent) ? 'darwin'
      : /Windows/.test(navigator.userAgent) ? 'win32' : 'unknown';
  }

  function render() {
    const state = getState();
    const locked = !state || isBusy() || isLocked() || shutdownRequested;
    // Fail closed: UI implementation is not proof that the backend grants
    // these controls. The current controller does not advertise them yet.
    const canPause = state?.managementActions?.pause === true;
    const canShutdown = state?.managementActions?.shutdown === true;
    $('toggle-pause').hidden = !canPause;
    $('toggle-pause').disabled = locked || !canPause;
    $('toggle-pause').textContent = state?.paused ? '恢复访问' : '暂停访问';
    $('open-shutdown').hidden = !canShutdown;
    $('open-shutdown').disabled = locked || !canShutdown;
    $('login-startup').checked = pendingStartup ?? (state?.startup === true);
    $('login-startup').disabled = locked || state?.startupAvailable !== true;
    for (const id of ['close-shutdown', 'cancel-shutdown', 'confirm-shutdown']) {
      $(id).disabled = pending;
    }

    const native = platform();
    const shellLabel = native === 'win32' ? 'PowerShell' : '终端';
    $('command-shell').textContent = shellLabel;
    $('update-hint').textContent = `复制后在这台电脑的 ${shellLabel} 运行，保留共享设置。`;
    $('daily-entry-label').textContent = native === 'win32' ? '按 Win + R，粘贴以下路径：' : '在终端运行：';
    $('daily-entry').value = native === 'win32'
      ? '%LOCALAPPDATA%\\Chat2Local\\Chat2Local.cmd'
      : native === 'darwin' ? 'open "$HOME/Applications/Chat2Local.command"'
        : '打开已安装的 Chat2Local 启动文件';
    try {
      const info = installationInstructions(state?.relay || state?.setupOrigin, native);
      $('update-command').value = info.command;
      $('install-page').value = info.page;
      $('mcp-address').value = info.mcp;
      $('copy-update').disabled = locked;
      $('copy-install-page').disabled = locked;
      $('copy-mcp').disabled = locked;
    } catch {
      $('update-command').value = '尚无适用的安装命令';
      $('install-page').value = '';
      $('mcp-address').value = '';
      for (const id of ['copy-update', 'copy-install-page', 'copy-mcp']) $(id).disabled = true;
    }
    $('shutdown-jobs').hidden = !state?.terminalJobsRunning;
    $('shutdown-jobs').textContent = state?.terminalJobsRunning
      ? `还有 ${state.terminalJobsRunning} 个命令任务，退出会请求停止它们；已发生的修改不会回滚。`
      : '';
  }

  async function perform(action) {
    if (pending || isBusy() || isLocked() || shutdownRequested) return;
    pending = true;
    setBusy(true);
    render();
    try {
      await action();
    } catch (error) {
      note(error.message, 'error');
    } finally {
      pending = false;
      setBusy(false);
      render();
    }
  }

  $('toggle-pause').onclick = () => {
    if (getState()?.managementActions?.pause !== true) return;
    return perform(async () => {
    const paused = !getState().paused;
    const result = await api('pause', { paused });
    if (result.paused !== paused) throw Error('访问状态未确认，请刷新核对。');
    updateState({ paused });
    note(paused
      ? '已暂停新的访问。正在运行的命令需另行取消。'
      : '已恢复访问。', 'success');
    });
  };

  $('login-startup').onchange = () => {
    if (getState()?.startupAvailable !== true) { render(); return; }
    if (pending || isBusy() || isLocked() || shutdownRequested) { render(); return; }
    const enabled = $('login-startup').checked;
    pendingStartup = enabled;
    void perform(async () => {
      const result = await api('management/startup', { enabled });
      if (result.enabled !== enabled) throw Error('启动设置未确认，请刷新核对。');
      updateState({ startup: enabled });
      note(enabled ? '已设置为登录后自动连接' : '已关闭登录自动连接', 'success');
    }).finally(() => { pendingStartup = null; render(); });
  };

  $('open-shutdown').onclick = () => {
    if (isBusy() || isLocked() || shutdownRequested || getState()?.managementActions?.shutdown !== true) return;
    render();
    exitDialog.showModal();
    $('cancel-shutdown').focus();
  };
  const closeExit = () => { if (!pending) exitDialog.close(); };
  $('cancel-shutdown').onclick = closeExit;
  $('close-shutdown').onclick = closeExit;
  exitDialog.addEventListener('cancel', event => { event.preventDefault(); closeExit(); });
  $('confirm-shutdown').onclick = () => perform(async () => {
    const result = await api('shutdown');
    if (result.ok !== true) throw Error('退出请求未确认，请检查本机状态。');
    shutdownRequested = true;
    exitDialog.close();
    onShutdown();
    $('connection-status').textContent = '已请求退出';
    $('connection-status').className = 'status-dot paused';
    $('sync-state').textContent = '自动同步已停止';
    note('已请求退出。下次打开 Chat2Local 即可连接。', 'success');
  });

  for (const [button, field, message] of [
    ['copy-update', 'update-command', '更新命令已复制，请在这台电脑执行。'],
    ['copy-install-page', 'install-page', '安装页地址已复制，请在新电脑打开。'],
    ['copy-mcp', 'mcp-address', 'ChatGPT 连接地址已复制。'],
  ]) {
    $(button).onclick = async () => {
      if ($(button).disabled) return;
      try {
        await navigator.clipboard.writeText($(field).value);
        note(message, 'success');
      } catch {
        $(field).hidden = false;
        const details = $(field).closest('details');
        if (details) details.open = true;
        $(field).focus();
        $(field).select();
        note('请复制选中的内容。');
      }
    };
  }
  return { render };
}
