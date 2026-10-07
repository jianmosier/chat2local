export const VERSION = '0.1.0-alpha.24';
export const TERMINAL_CAPABILITY = 'terminal-jobs-v1';
export const MAX_FILE_BYTES = 64 * 1024;
export const MAX_WIRE_BYTES = 512 * 1024;
export const PROTOCOL_VERSION = '2025-11-25';
export const SUPPORTED_PROTOCOLS = ['2025-03-26', '2025-06-18', PROTOCOL_VERSION];
const string = { type: 'string' };
const objectSchema = (properties, required = []) => ({ type: 'object', properties, required, additionalProperties: false });
export function requiredScopes(name) {
  return ['files:read', ...(name.startsWith('terminal_') ? ['terminal:execute'] : name === 'write_file' ? ['files:write'] : name === 'propose_write' ? ['files:propose'] : [])];
}
export const TOOLS = [
  { name: 'list_devices', description: 'List ONLY computers included in this OAuth authorization, including online/offline/revoked status. When more than one computer is authorized, specify deviceId on every folder/file/status operation. Never select another computer because the intended target is offline.', inputSchema: objectSchema({}), annotations: { readOnlyHint: true } },
  { name: 'list_roots', description: 'List explicitly authorized folders and their writeMode (read-only, review, direct). write_file requires directWriteAllowed=true and OAuth files:write. Paths are relative to the returned root ID.', inputSchema: objectSchema({}), annotations: { readOnlyHint: true } },
  { name: 'list_directory', description: 'List up to 500 immediate children of an authorized folder. Sensitive files and links are excluded.', inputSchema: objectSchema({ rootId: string, path: string }, ['rootId']), annotations: { readOnlyHint: true } },
  { name: 'read_file', description: 'Read a UTF-8 text file, at most 64 KiB, with a SHA-256 hash for optimistic concurrency.', inputSchema: objectSchema({ rootId: string, path: string }, ['rootId', 'path']), annotations: { readOnlyHint: true } },
  { name: 'propose_write', description: 'PROPOSE a UTF-8 file write. Does NOT write immediately: the local user must approve the exact content in Chat2Local. expectedHash must be the read_file hash, or null for a new file. Poll operation_status; never claim success while pending.', inputSchema: objectSchema({ rootId: string, path: string, content: string, expectedHash: { type: ['string', 'null'] } }, ['rootId', 'path', 'content', 'expectedHash']), annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false } },
  { name: 'write_file', description: 'Create or replace a UTF-8 text file (max 64 KiB) WITHOUT per-write local approval, ONLY when this folder has explicitly enabled direct writing AND this OAuth client has files:write. Read list_roots first. expectedHash must match the current read_file hash, or be null for a new file. Existing contents are backed up. Returns written only after commit; on timeout/unknown outcome read back before retrying. Never changes permissions, deletes files, or runs commands.', inputSchema: objectSchema({ rootId: string, path: string, content: string, expectedHash: { type: ['string', 'null'] } }, ['rootId', 'path', 'content', 'expectedHash']), annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false } },
  { name: 'terminal_execute', description: 'Start a non-interactive command on the exact selected computer. Requires a scoped terminal:execute grant AND explicit local terminal permission. Windows uses PowerShell; macOS/Linux use sh. This is NOT an OS sandbox: commands have the desktop user permissions and can modify/delete files beyond cwd or use the network. Use a new UUID requestId per intentional command; reuse it after a timeout, never generate another ID to retry blindly. Returns running, not success; poll terminal_status for bounded output and exit code. cwd is relative to rootId. Never start privileged or destructive operations without explicit user intent.', inputSchema: objectSchema({ rootId: string, requestId: string, command: string, cwd: string, shell: { type: 'string', enum: ['auto','powershell','sh'] }, timeoutMs: { type: 'integer', minimum: 100, maximum: 300000 } }, ['rootId','requestId','command']), annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true } },
  { name: 'terminal_status', description: 'Read the existing command state, bounded stdout/stderr and exit code. Requires the same computer, connection, rootId and requestId. interrupted or unknown is not success and must not trigger automatic rerun.', inputSchema: objectSchema({ rootId: string, requestId: string }, ['rootId','requestId']), annotations: { readOnlyHint: true } },
  { name: 'terminal_cancel', description: 'Request termination of this connection\'s command and its attached process tree. Poll status; cancellation does not roll back effects, and detached descendants may survive. Never claim termination unless confirmed.', inputSchema: objectSchema({ rootId: string, requestId: string }, ['rootId','requestId']), annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true } },
  { name: 'operation_status', description: 'Check whether an operation is pending, approved (reviewed write committed), written (direct write committed), rejected, expired, or failed. A proposal or unknown status is not a completed write.', inputSchema: objectSchema({ operationId: string }, ['operationId']), annotations: { readOnlyHint: true } },
].map(tool => {
  if (tool.name !== 'list_devices') tool = { ...tool, description: tool.description + ' For multiple authorized computers, specify the exact deviceId from list_devices; omission is rejected rather than guessing.', inputSchema: { ...tool.inputSchema, properties: { ...tool.inputSchema.properties, deviceId: string } } };
  const securitySchemes = [{ type: 'oauth2', scopes: requiredScopes(tool.name) }];
  return { ...tool, securitySchemes, _meta: { securitySchemes } };
});

export function checkArguments(name, args = {}) {
  const tool = TOOLS.find(t => t.name === name);
  if (!tool || !args || typeof args !== 'object' || Array.isArray(args)) throw new Error('Unknown tool or invalid arguments.');
  for (const key of Object.keys(args)) if (!Object.hasOwn(tool.inputSchema.properties, key)) throw new Error(`Unexpected argument: ${key}`);
  for (const key of tool.inputSchema.required) if (!(key in args)) throw new Error(`Missing argument: ${key}`);
  for (const [key, value] of Object.entries(args)) {
    if (key === 'expectedHash' && value === null) continue;
    if (key === 'timeoutMs') { if (!Number.isInteger(value) || value < 100 || value > 300000) throw new Error('Invalid command timeout.'); continue; }
    if (typeof value !== 'string') throw new Error(`Argument ${key} must be a string.`);
    if (!['content','command'].includes(key) && value.length > 4096) throw new Error('Argument too long.');
  }
  if (args.requestId !== undefined && !/^[a-f0-9-]{36}$/.test(args.requestId)) throw new Error('Invalid command requestId.');
  if (args.shell !== undefined && !['auto','powershell','sh'].includes(args.shell)) throw new Error('Invalid shell.');
  if (args.command !== undefined && (!args.command.trim() || args.command.includes('\0') || new TextEncoder().encode(args.command).length > 16384)) throw new Error('Invalid or oversized terminal command.');
  if (args.deviceId !== undefined && !/^[a-f0-9]{32}$/.test(args.deviceId)) throw new Error('Invalid target device ID.');
  if (args.rootId !== undefined && !/^[a-zA-Z0-9_-]{1,80}$/.test(args.rootId)) throw new Error('Invalid root ID.');
  if (args.operationId !== undefined && !/^[a-f0-9-]{36}$/.test(args.operationId)) throw new Error('Invalid operation ID.');
  if (args.expectedHash !== undefined && args.expectedHash !== null && !/^[a-f0-9]{64}$/.test(args.expectedHash)) throw new Error('Invalid expected SHA-256.');
  if (args.content !== undefined && (args.content.includes('\0') || new TextEncoder().encode(args.content).length > MAX_FILE_BYTES)) throw new Error('File exceeds 64 KiB or contains binary NUL characters.');
  return args;
}

export function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...extra } });
}

export async function readLimited(request, limit = MAX_WIRE_BYTES) {
  if (Number(request.headers.get('content-length') || 0) > limit) throw new Error('Request too large.');
  if (!request.body) return '';
  const reader = request.body.getReader();
  const chunks = []; let size = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) { await reader.cancel(); throw new Error('Request too large.'); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const joined = new Uint8Array(size); let offset = 0;
  for (const chunk of chunks) { joined.set(chunk, offset); offset += chunk.length; }
  return new TextDecoder('utf-8', { fatal: true }).decode(joined);
}

export async function handleMcp(request, invoke) {
  const version = request.headers.get('MCP-Protocol-Version');
  if (version && !SUPPORTED_PROTOCOLS.includes(version)) return json({ error: 'Unsupported MCP protocol version.', supported: SUPPORTED_PROTOCOLS }, 400);
  if (request.method !== 'POST') return new Response(null, { status: 405, headers: { Allow: 'POST' } });
  if (!request.headers.get('content-type')?.toLowerCase().startsWith('application/json')) return json({ error: 'application/json required' }, 415);
  let message;
  try { message = JSON.parse(await readLimited(request)); } catch { return json({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Invalid or oversized JSON body.' } }, 400); }
  if (!message || Array.isArray(message) || message.jsonrpc !== '2.0' || typeof message.method !== 'string' || (message.id !== undefined && typeof message.id !== 'string' && typeof message.id !== 'number')) {
    return json({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid request.' } }, 400);
  }
  if (message.id === undefined) {
    if (!message.method.startsWith('notifications/')) return json({ error: 'Tool requests require an ID.' }, 400);
    return new Response(null, { status: 202 });
  }
  const result = value => json({ jsonrpc: '2.0', id: message.id, result: value });
  if (message.method === 'initialize') return result({ protocolVersion: SUPPORTED_PROTOCOLS.includes(message.params?.protocolVersion) ? message.params.protocolVersion : PROTOCOL_VERSION, capabilities: { tools: {} }, serverInfo: { name: 'chat2local', version: VERSION }, instructions: 'Use list_devices to identify authorized computers. With multiple computers, specify deviceId for each operation; never switch targets when offline. Check list_roots for per-folder permissions. propose_write ALWAYS requires local review, even in direct mode. write_file needs explicit directory-direct permission plus OAuth files:write and creates/updates text files without another local click. Never use propose_write as a direct write, escalate permissions, or report a pending/failed/unknown operation as written.' });
  if (message.method === 'ping') return result({});
  if (message.method === 'tools/list') return result({ tools: TOOLS });
  if (message.method !== 'tools/call') return json({ jsonrpc: '2.0', id: message.id, error: { code: -32601, message: 'Method not found.' } });
  try {
    const { name, arguments: args = {} } = message.params || {};
    checkArguments(name, args);
    const data = await invoke(name, args);
    return result({ content: [{ type: 'text', text: JSON.stringify(data) }], isError: false });
  } catch (error) {
    return result({ content: [{ type: 'text', text: error instanceof Error ? error.message : 'Operation failed.' }], isError: true, ...(typeof error?.wwwAuthenticate === 'string' ? { _meta: { 'mcp/www_authenticate': [error.wwwAuthenticate] } } : {}) });
  }
}

export function relayOrigin(input, allowLoopback = false) {
  const url = new URL(input);
  const local = allowLoopback && ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
  if ((url.protocol !== 'https:' && !(local && url.protocol === 'http:')) || url.username || url.password || url.search || url.hash || url.pathname !== '/') throw new Error('Use an HTTPS relay origin without a path, credentials, query, or fragment.');
  return url.origin;
}

export async function sha256(value) {
  const data = typeof value === 'string' ? new TextEncoder().encode(value) : value;
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', data));
  return Array.from(digest, n => n.toString(16).padStart(2, '0')).join('');
}
export function randomSecret() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes, n => n.toString(16).padStart(2, '0')).join('');
}
