/** An owner-issued invitation is a scoped secret, not an operator/device key.
 * Keep it in URL fragments or a private local file. Never log the input.
 */
export function parseInstanceInvitation(value, allowLocal = false) {
  if (typeof value !== 'string' || value.length > 4096) throw new Error('Invalid private-instance invitation.');
  let url; try { url = new URL(value); } catch { throw new Error('Invalid private-instance invitation.'); }
  const loopback = allowLocal && url.protocol === 'http:' && ['127.0.0.1','localhost','[::1]'].includes(url.hostname);
  if ((!loopback && url.protocol !== 'https:') || url.username || url.password || url.search || url.pathname !== '/instance/invite' || !/^[a-f0-9]{32}\.[a-f0-9]{64}$/.test(url.hash.slice(1))) throw new Error('Use the exact installation invitation from your own instance.');
  return { origin: url.origin, invitation: url.hash.slice(1) };
}
