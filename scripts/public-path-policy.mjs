// Shared by export and read-only audits; names alone can identify private data.
const directories = new Set(['.git', '.artifacts', '.wrangler', 'codex', '.ssh']);
const privateFile = /^(?:wrangler\.local\.jsonc|vault\.json|session\.json|settings\.json|audit\.jsonl|handoff\.md)(?:$|[._~-])/;

export function isPrivatePublicationPath(name) {
  return name.replaceAll('\\', '/').split('/').some(part => {
    const lower = part.toLowerCase();
    return directories.has(lower) || /^\.env(?:$|[._~-])/.test(lower) || privateFile.test(lower);
  });
}
