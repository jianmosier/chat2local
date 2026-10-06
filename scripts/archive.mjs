import fs from 'node:fs/promises';
import path from 'node:path';
import { gzipSync } from 'node:zlib';

export async function packageEntries(directory, prefix = '') {
  const output = [];
  for (const item of await fs.readdir(directory, { withFileTypes: true })) {
    const relative = prefix + item.name;
    if (item.isSymbolicLink()) throw new Error('Package sources must not contain links.');
    if (item.isDirectory()) output.push(...await packageEntries(path.join(directory, item.name), relative + '/'));
    else if (item.isFile()) output.push(relative);
    else throw new Error('Package sources must be regular files.');
  }
  return output.sort();
}

/** Emit only regular-file USTAR entries. This preserves POSIX executable modes
 * even when macOS/Linux packages are assembled on a Windows build machine.
 */
export function tarHeader(name, size, mode = 0o644, type = '0') {
  if (!name || name.startsWith('/') || name.includes('\\') || name.split('/').some(part => !part || part === '.' || part === '..') || /[\x00-\x1f\x7f]/.test(name)) throw new Error('Unsafe archive entry.');
  if (!Number.isSafeInteger(size) || size < 0 || size > 256 * 1024 * 1024) throw new Error('Archive member is too large.');
  const header = Buffer.alloc(512);
  let shortName = name; let prefix = '';
  if (Buffer.byteLength(name) > 100) {
    const boundaries = [...name.matchAll(/\//g)].map(match => match.index).reverse();
    const cut = boundaries.find(index => Buffer.byteLength(name.slice(index + 1)) <= 100 && Buffer.byteLength(name.slice(0, index)) <= 155);
    if (cut === undefined) throw new Error('Archive filename is too long.');
    prefix = name.slice(0, cut); shortName = name.slice(cut + 1);
  }
  const number = (value, offset, width) => { const text = value.toString(8).padStart(width - 1, '0') + '\0'; if (text.length !== width) throw new Error('Tar number overflow.'); header.write(text, offset, width, 'ascii'); };
  header.write(shortName, 0, 100, 'utf8'); number(mode, 100, 8); number(0, 108, 8); number(0, 116, 8); number(size, 124, 12); number(0, 136, 12);
  if (!['0', 'x'].includes(type)) throw new Error('Unsupported tar member type.');
  header.fill(32, 148, 156); header[156] = type.charCodeAt(0);
  header.write('ustar\0', 257, 6, 'ascii'); header.write('00', 263, 2, 'ascii'); header.write(prefix, 345, 155, 'utf8');
  const checksum = header.reduce((sum, value) => sum + value, 0);
  header.write(checksum.toString(8).padStart(6, '0') + '\0 ', 148, 8, 'ascii');
  return header;
}

function paxPathRecord(name) {
  const body = ` path=${name}\n`;
  let size = Buffer.byteLength(body) + 1;
  while (Buffer.byteLength(body) + String(size).length !== size) size = Buffer.byteLength(body) + String(size).length;
  return Buffer.from(`${size}${body}`, 'utf8');
}

export async function writeTarGz(directory, archive) {
  const parts = []; let total = 0; let sequence = 0;
  for (const relative of await packageEntries(directory)) {
    const bytes = await fs.readFile(path.join(directory, relative));
    total += bytes.length;
    if (total > 256 * 1024 * 1024) throw new Error('Package exceeds its uncompressed size limit.');
    const executable = relative === 'runtime/node' || relative === 'start-chat2local.sh';
    const name = `${path.basename(directory)}/${relative}`;
    // PAX carries UTF-8 names explicitly. Bare USTAR names otherwise depend on
    // the extractor's locale (notably Windows system tar with Chinese names).
    const header = tarHeader(name, bytes.length, executable ? 0o755 : 0o644);
    if (/[^\x20-\x7e]/.test(name)) {
      const record = paxPathRecord(name); const safeName = `PaxHeaders/entry-${++sequence}`;
      parts.push(tarHeader(safeName, record.length, 0o644, 'x'), record, Buffer.alloc((512 - record.length % 512) % 512));
      parts.push(tarHeader(`entry-${sequence}`, bytes.length, executable ? 0o755 : 0o644));
    } else parts.push(header);
    parts.push(bytes, Buffer.alloc((512 - bytes.length % 512) % 512));
  }
  parts.push(Buffer.alloc(1024));
  await fs.writeFile(archive, gzipSync(Buffer.concat(parts), { level: 9 }), { flag: 'wx' });
}
