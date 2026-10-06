import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { approveRoot } from './files.mjs';

const inside = (base, target) => { const rel = path.relative(base, target); return rel === '' || (rel !== '..' && !rel.startsWith(`..${path.sep}`) && !path.isAbsolute(rel)); };
const hidden = name => name.startsWith('.') || /^(node_modules|Chat2LocalOperator|System Volume Information|\$RECYCLE\.BIN)$/i.test(name);

/** Local UI ONLY: directory names, never file contents. Not an MCP tool.
 * A browser chooser avoids depending on an interactive Windows desktop session. */
export async function browseFolders(input, stateDir) {
  const home = os.homedir();
  const locations = [...new Set([home, path.parse(home).root, path.parse(process.cwd()).root])].map((item, index) => ({ path: item, label: index === 0 ? '用户文件夹' : item }));
  const requested = input || home;
  if (typeof requested !== 'string' || requested.length > 2048 || !path.isAbsolute(requested) || /^[\\/]{2}/.test(requested) || /[\x00-\x1f]/.test(requested)) throw new Error('请选择本机目录，或输入完整的本机目录路径。');
  const selected = await fs.lstat(requested);
  if (!selected.isDirectory() || selected.isSymbolicLink()) throw new Error('请选择实际目录，不支持链接或网络共享。');
  const canonical = await fs.realpath(requested);
  const protectedPaths = [stateDir, path.join(path.dirname(stateDir), 'Chat2LocalOperator'), process.env.WINDIR, process.env.ProgramFiles, process.env['ProgramFiles(x86)']].filter(Boolean).map(item => path.resolve(item));
  if (protectedPaths.some(item => inside(item, canonical))) throw new Error('系统目录和 Chat2Local 凭据目录不可浏览或授权。');
  let selectable = true;
  try { await approveRoot(canonical, stateDir, false); } catch { selectable = false; }
  const directory = await fs.opendir(canonical);
  const entries = []; let truncated = false;
  for await (const item of directory) {
    if (!item.isDirectory() || item.isSymbolicLink() || hidden(item.name)) continue;
    const target = path.join(canonical, item.name);
    if (protectedPaths.some(base => inside(base, target))) continue;
    if (entries.length >= 300) { truncated = true; break; }
    entries.push({ name: item.name, path: target });
  }
  entries.sort((a, b) => a.name.localeCompare(b.name));
  const parent = path.dirname(canonical);
  return { path: canonical, parent: parent === canonical ? null : parent, locations, entries, truncated, selectable,
    note: selectable ? '这里只浏览文件夹名称，点击“使用这个文件夹”后才会授予只读权限。' : '不能授权整块磁盘、整个用户目录或包含凭据的父目录；请进入一个具体项目文件夹。' };
}
