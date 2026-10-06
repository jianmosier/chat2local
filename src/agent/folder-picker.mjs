/** Owns one native dialog, outside the filesystem/policy queue. Cancellation
 * discards late results even when a test or platform picker ignores its signal. */
export class FolderPicker {
  constructor(pick, timeoutMs = 120000) { this.pick = pick; this.timeoutMs = timeoutMs; this.active = null; }
  cancel() { this.active?.abort(); }
  get busy() { return Boolean(this.active); }
  async run({ signal } = {}) {
    if (this.active) throw Object.assign(new Error('已有文件夹选择窗口打开。请完成或取消该窗口。'), { status: 409 });
    const controller = new AbortController();
    this.active = controller;
    const abort = () => controller.abort();
    signal?.addEventListener('abort', abort, { once: true });
    if (signal?.aborted) abort();
    let expired = false;
    const timer = setTimeout(() => { expired = true; abort(); }, this.timeoutMs);
    let rejectAbort;
    const cancelled = new Promise((_, reject) => { rejectAbort = () => reject(Object.assign(new Error('Folder selection cancelled.'), { name: 'AbortError' })); });
    controller.signal.addEventListener('abort', rejectAbort, { once: true });
    try {
      controller.signal.throwIfAborted();
      const path = await Promise.race([Promise.resolve().then(() => this.pick({ signal: controller.signal })), cancelled]);
      controller.signal.throwIfAborted();
      return { path: path || null, cancelled: !path, expired: false };
    } catch (error) {
      if (controller.signal.aborted) return { path: null, cancelled: true, expired };
      throw error;
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      controller.signal.removeEventListener('abort', rejectAbort);
      if (this.active === controller) this.active = null;
    }
  }
}
