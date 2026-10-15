import { json } from '../shared/protocol.mjs';
import { bootstrapSource } from '../shared/distribution.mjs';
import { publicBootstrap, publicPowerShellBootstrap } from '../shared/public-bootstrap.mjs';

const macChunk = /^\/releases\/0\.1\.0-alpha\.[0-9]+\/(darwin-arm64|darwin-x64)\/[a-f0-9]{64}\.part[0-9]{2}$/;

// Download routing only. Installer login and device authorization remain in
// install-http.mjs; none of these public endpoints grants local access.
export function installAssetRoute(request, env, origin) {
  const url = new URL(request.url);
  const script = ['/install.sh', '/install.ps1'].includes(url.pathname);
  if (!script && !macChunk.test(url.pathname)) return null;
  if (env.PRIVATE_INSTANCE !== 'true' || !['GET', 'HEAD'].includes(request.method) || url.search) {
    return json({ error: 'Published installer is not available.' }, 404);
  }

  if (url.pathname === '/install.ps1') {
    // Older instances can keep their existing Mac assets. Windows uses the
    // same instance address and the explicitly pinned public distribution.
    const source = env.PUBLIC_BOOTSTRAP_URL || bootstrapSource('sh');
    return scriptResponse(request, publicPowerShellBootstrap(origin, source), 'text/plain');
  }
  if (url.pathname === '/install.sh' && !env.ASSETS && env.PUBLIC_BOOTSTRAP_URL) {
    return scriptResponse(request, publicBootstrap(origin, env.PUBLIC_BOOTSTRAP_URL), 'application/x-sh');
  }
  if (!env.ASSETS) return json({ error: 'Published installer is not available.' }, 404);
  return env.ASSETS.fetch(new Request(origin + url.pathname, { method: request.method }));
}

function scriptResponse(request, script, contentType) {
  return new Response(request.method === 'HEAD' ? null : script, {
    headers: {
      'Content-Type': contentType + '; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}
