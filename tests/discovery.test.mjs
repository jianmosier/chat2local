import test from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { ListToolsResultSchema } from '@modelcontextprotocol/sdk/types.js';
import { handleMcp, TOOLS, SUPPORTED_PROTOCOLS } from '../src/shared/protocol.mjs';

// Independent protocol-client regression, not a real ChatGPT acceptance test.
test('official MCP SDK initializes, accepts notification/SSE refusal and validates file and terminal tools', async () => {
  const events = [];
  const client = new Client({ name: 'chat2local-discovery-regression', version: '1.0.0' });
  const transport = new StreamableHTTPClientTransport(new URL('http://127.0.0.1/mcp'), { fetch: async (url, options) => {
    const request = new Request(url, options);
    const method = typeof options?.body === 'string' ? JSON.parse(options.body).method : request.method;
    const response = await handleMcp(request, () => assert.fail('Discovery must not invoke a filesystem tool.'));
    events.push({ method, status: response.status });
    return response;
  } });
  try {
    await client.connect(transport, { timeout: 2000 });
    const listed = await client.listTools({}, { timeout: 2000 });
    assert.equal(ListToolsResultSchema.safeParse(listed).success, true);
    assert.deepEqual(listed.tools.map(tool => tool.name), TOOLS.map(tool => tool.name));
    assert.ok(events.some(event => event.method === 'initialize' && event.status === 200));
    assert.ok(events.some(event => event.method === 'notifications/initialized' && event.status === 202));
    assert.ok(events.some(event => event.method === 'tools/list' && event.status === 200));
  } finally { await client.close(); }
});

test('each advertised HTTP protocol version discovers the same static tools', async () => {
  for (const version of SUPPORTED_PROTOCOLS) {
    const response = await handleMcp(new Request('http://127.0.0.1/mcp', { method: 'POST', headers: { 'Content-Type': 'application/json', 'MCP-Protocol-Version': version }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }) }), () => assert.fail('No tool execution'));
    assert.equal(response.status, 200);
    const { result } = await response.json();
    assert.equal(ListToolsResultSchema.safeParse(result).success, true);
    assert.equal(result.tools.length, TOOLS.length);
  }
});
