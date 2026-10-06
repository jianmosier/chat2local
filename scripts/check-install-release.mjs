import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

/** Read-only publication check: downloads bytes from the canonical instance and
 * verifies each chunk AND the reconstructed archive. Does not install or launch
 * the Mac runtime, register a device, authenticate a browser or create a ticket.
 */
export async function checkInstallRelease(file, request = fetch) {
  const release = JSON.parse(await fs.readFile(file, 'utf8'));
  const origin = new URL(release.origin);
  if (origin.protocol !== 'https:' || origin.username || origin.password || origin.pathname !== '/' || origin.search || origin.hash) throw new Error('Invalid release origin.');
  const get = url => request(url, { redirect: 'error', signal: AbortSignal.timeout(45000) });
  const page = await get(origin.origin + '/install');
  if (page.status !== 200 || !(await page.text()).includes('/install.js')) throw new Error('Published installation page failed.');
  const script = await get(origin.origin + '/install.sh');
  if (script.status !== 200) throw new Error('Published bootstrap is unavailable.');
  const bytes = Buffer.from(await script.arrayBuffer()), local = await fs.readFile(path.join(file.replace(/\.json$/, ''), 'install.sh'));
  if (!bytes.equals(local)) throw new Error('Published bootstrap differs from the reviewed release.');
  const targets = [];
  for (const target of release.targets) {
    const all = createHash('sha256'); let length = 0;
    for (const part of target.parts) {
      if (!/^\/releases\/0\.1\.0-alpha\.[0-9]+\/darwin-(arm64|x64)\/[a-f0-9]{64}\.part[0-9]{2}$/.test(part.path)) throw new Error('Unexpected release part path.');
      const response = await get(origin.origin + part.path);
      if (response.status !== 200) throw new Error('Published chunk failed: ' + response.status);
      const hash = createHash('sha256'); let partLength = 0;
      for await (const bytes of response.body) { partLength += bytes.length; if (partLength > part.bytes) throw new Error('Published chunk is too large.'); hash.update(bytes); all.update(bytes); }
      if (partLength !== part.bytes || hash.digest('hex') !== part.sha256) throw new Error('Published chunk integrity failed.');
      length += partLength;
    }
    if (length !== target.bytes || all.digest('hex') !== target.sha256) throw new Error('Published archive integrity failed.');
    targets.push({ target: target.target, bytes: length, sha256: target.sha256, verifiedFromPublicDownload: true, nativeRuntimeExecuted: false });
  }
  const locked = await get(origin.origin + '/mcp'); if (locked.status !== 401) throw new Error('MCP must still require OAuth.');
  return { pageHttpStatus: 200, bootstrapMatches: true, targets, unauthenticatedMcpStatus: 401 };
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) checkInstallRelease(process.argv[2]).then(value => console.log(JSON.stringify(value, null, 2))).catch(error => { console.error(error.message); process.exitCode = 1; });
