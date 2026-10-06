// Canonical directory metadata only. This is a display/revocation relation,
// never a filesystem sandbox or a way to manufacture a new grant.
function parts(value, platform) {
  if (typeof value !== 'string' || !value || /[\x00-\x1f]/.test(value)) return null;
  const windows = platform === 'win32';
  const text = windows ? value.replaceAll('\\', '/').toLowerCase() : value;
  if (!(windows ? /^(?:[a-z]:\/|\/\/[^/]+\/[^/]+)/.test(text) : text.startsWith('/'))) return null;
  const entries = text.split('/').filter(Boolean);
  if (entries.some(p => p === '.' || p === '..')) return null;
  return entries;
}
export function directoryContains(parent, child, platform = 'linux') {
  const a = parts(parent, platform), b = parts(child, platform);
  return Boolean(a && b && a.length <= b.length && a.every((p, i) => p === b[i]));
}
export function shareCovers(parent, child, platform = 'linux') {
  const rank = { 'read-only': 0, review: 1, direct: 2 };
  return parent.locallyPresent === true && child.locallyPresent === true &&
    Object.hasOwn(rank, parent.mode) && Object.hasOwn(rank, child.mode) &&
    directoryContains(parent.path, child.path, platform) && rank[parent.mode] >= rank[child.mode] &&
    (!child.terminalLocalEnabled || parent.terminalLocalEnabled === true);
}
export function annotateCoverage(roots, platform) {
  // Keep ALL explicit records. coveredBy controls only folding; deleting a
  // broader entry must be able to reveal still-valid independent child shares.
  return roots.map((root, index) => {
    const covering = roots.map((value, i) => ({ value, i })).filter(({ value, i }) =>
      i !== index && shareCovers(value, root, platform) &&
      (!shareCovers(root, value, platform) || i < index));
    covering.sort((a, b) => parts(a.value.path, platform).length - parts(b.value.path, platform).length || a.i - b.i);
    return { ...root, coveredBy: covering[0]?.value.rootId || null };
  });
}
