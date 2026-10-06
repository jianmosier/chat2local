/** Navigation only, never authorization. A resumed page must revalidate OAuth,
 * bind the current browser and obtain explicit consent before issuing a token.
 */
export function authorizationReturn(value, origin) {
  if (typeof value !== 'string' || value.length > 8192) throw new Error('Invalid authorization return address.');
  const url = new URL(value);
  if (url.origin !== origin || url.pathname !== '/authorize' || url.username || url.password || url.hash || !url.search) throw new Error('Authorization must return to the configured relay.');
  return url.href;
}
