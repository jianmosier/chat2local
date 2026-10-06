import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalOrigin, loadDeployment } from './cloud-setup.mjs';
import { GOOGLE_OIDC, googleCallbackUri, googleClientId, googleClientSecret } from '../src/shared/google-identity.mjs';

/** Read only the explicitly supplied Google export. Never searches user files,
 * writes a credential copy, contacts Google, uploads secrets or deploys a Worker.
 * The returned object is allowlisted and deliberately excludes client_secret.
 */
export function checkGoogleClient(document, origin) {
  const callback = googleCallbackUri(origin);
  if (!document || typeof document !== 'object' || Array.isArray(document) || Object.keys(document).length !== 1 || !document.web || typeof document.web !== 'object' || Array.isArray(document.web)) throw new Error('Download the OAuth Web application JSON, not a Desktop app or service-account key.');
  const web = document.web;
  const clientId = googleClientId(web.client_id); googleClientSecret(web.client_secret);
  if (!Array.isArray(web.redirect_uris) || web.redirect_uris.length > 100 || web.redirect_uris.some(uri => typeof uri !== 'string' || uri.length > 4096) || !web.redirect_uris.includes(callback)) throw new Error('The Google export does not contain the exact original relay /account/callback redirect. No setting was changed.');
  // Google's downloadable JSON may still name its older endpoints; do not use
  // those values for network routing. The actual runtime uses pinned metadata.
  if (web.auth_uri !== undefined && !['https://accounts.google.com/o/oauth2/auth', GOOGLE_OIDC.OIDC_AUTHORIZATION_ENDPOINT].includes(web.auth_uri)) throw new Error('Unexpected Google authorization endpoint in the supplied export.');
  if (web.token_uri !== undefined && ![GOOGLE_OIDC.OIDC_TOKEN_ENDPOINT, 'https://www.googleapis.com/oauth2/v3/token'].includes(web.token_uri)) throw new Error('Unexpected Google token endpoint in the supplied export.');
  return {
    provider: 'google', clientType: 'web', clientId, redirectUri: callback,
    publicSettings: { OIDC_PROVIDER: 'google', OIDC_CLIENT_ID: clientId },
    secretPresent: true, secretTarget: 'OIDC_CLIENT_SECRET (server-side secret only)',
    scopes: ['openid', 'profile'],
    fileChecked: true, googleLoginVerified: false, configurationWritten: false,
    secretsUploaded: false, accountModeEnabled: false, deployed: false,
  };
}
export async function inspectGoogleClientFile(filename, origin) {
  if (typeof filename !== 'string' || !path.isAbsolute(filename)) throw new Error('Select an explicit absolute path to the downloaded JSON file.');
  let stat;
  try { stat = await fs.lstat(filename); } catch { throw new Error('The selected JSON file could not be found or read. Check its actual download location.'); }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > 64 * 1024) throw new Error('Choose a regular, single-link client JSON file no larger than 64 KiB.');
  let document;
  try {
    const handle = await fs.open(filename, 'r');
    try {
      const current = await handle.stat();
      if (!current.isFile() || current.nlink !== 1 || current.dev !== stat.dev || current.ino !== stat.ino || current.size > 64 * 1024) throw new Error();
      const buffer = Buffer.alloc(64 * 1024 + 1); let length = 0;
      while (length < buffer.length) { const { bytesRead } = await handle.read(buffer, length, buffer.length - length, null); if (!bytesRead) break; length += bytesRead; }
      if (length > 64 * 1024) throw new Error();
      document = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, length)).replace(/^\uFEFF/, ''));
    } finally { await handle.close(); }
  } catch { throw new Error('The selected file is not a valid, unchanged client JSON document. File contents were not printed.'); }
  return checkGoogleClient(document, origin);
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2);
    if (args.length !== 0 && (args.length !== 2 || args[0] !== '--check')) throw new Error('Usage: node scripts/check-google-client.mjs [--check ABSOLUTE_DOWNLOADED_JSON_PATH]');
    const origin = canonicalOrigin(await loadDeployment());
    const result = args.length ? await inspectGoogleClientFile(args[1], origin) : {
      provider: 'Google', applicationType: 'Web application', applicationName: 'chat2local',
      redirectUri: googleCallbackUri(origin), javascriptOriginsRequired: false,
      scopes: ['openid', 'profile'], clientRegistrationRequired: true,
      configurationWritten: false, secretsUploaded: false, deployed: false,
    };
    console.log(JSON.stringify(result, null, 2));
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
