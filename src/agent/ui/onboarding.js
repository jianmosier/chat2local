// Shared by the browser and tests. Parsing never makes a network request.
export function parseInvitation(input) {
  if (typeof input !== 'string' || input.length > 2300) throw new Error('请粘贴可信管理员提供的完整连接邀请。');
  let url;
  try { url = new URL(input.trim()); } catch { throw new Error('邀请格式不正确，请复制完整邀请，不要只复制配对码。'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/' || url.search || url.port || !/^#enroll=[a-f0-9]{64}$/.test(url.hash)) throw new Error('邀请必须是 HTTPS 入口，并包含有效的设备注册信息。');
  return { origin: url.origin, enrollmentToken: url.hash.slice('#enroll='.length) };
}
export function connectionSteps(state) {
  return {
    folder: Array.isArray(state.roots) && state.roots.length > 0,
    relay: state.bridge === 'connected',
    // A healthy relay is NOT proof of a successful remote tool call.
    verified: state.bridge === 'connected' && !state.paused && Boolean(state.lastRemoteCallAt),
  };
}
export function helpfulError(message) {
  const exact = {
    'Choose an absolute local folder.': '请点击“选择文件夹”，或填写完整的本机目录路径。',
    'Do not authorize an entire drive or user profile.': '请选择一个具体项目文件夹，不要选择整块磁盘或整个用户目录。',
    'Folder already authorized. Revoke it before changing its permissions.': '这个目录已经授权。如需修改权限，先撤销，再重新添加。',
    'Resume access before running the local demo.': '访问已暂停，请先点击“恢复访问”，再运行演示。',
    'Connect the computer to the relay first.': '请先连接可信入口，然后再生成网页 AI 授权需要的配对码。',
    'Local control token required. Reopen the app using its launcher.': '这个页面缺少本机授权。请重新双击启动文件，不要手动输入浏览器地址。',
    'This folder is read-only. Enable write proposals locally first.': '该目录目前只读。请重新授权并勾选“允许提交写入建议”。',
  };
  if (exact[message]) return exact[message];
  if (message === 'Failed to fetch' || message === 'fetch failed') return '暂时无法连接。请检查程序是否运行，以及网络或入口地址是否正常。';
  if (/ENOENT/.test(message)) return '没有找到这个目录或文件，请检查路径后重试。';
  if (/enrollment failed \(401\)/i.test(message)) return '入口拒绝了设备注册。请向管理员索取有效邀请，不要把网页 AI 的配对码当成邀请。';
  return message;
}
