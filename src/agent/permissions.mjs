export const WRITE_MODES = Object.freeze(['read-only', 'review', 'direct']);

export function validateWriteMode(value) {
  if (!WRITE_MODES.includes(value)) throw new Error('请选择只读、逐次确认或允许直接读写。');
  return value;
}

/** Legacy write=true always means proposal/review, NEVER direct-write consent. */
export function rootWriteMode(root) {
  if (!root || typeof root.write !== 'boolean') throw new Error('Invalid saved directory permission.');
  const mode = validateWriteMode(root.writeMode ?? (root.write ? 'review' : 'read-only'));
  if (root.write !== (mode !== 'read-only')) throw new Error('Conflicting saved directory permissions; reselect this folder locally.');
  return mode;
}

export function rootPermission(mode) {
  validateWriteMode(mode);
  return { write: mode !== 'read-only', writeMode: mode };
}
