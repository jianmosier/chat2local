import { timingSafeEqual } from 'node:crypto';
import { MAX_WIRE_BYTES } from '../shared/protocol.mjs';
import { rootPermission, validateWriteMode } from './permissions.mjs';

// HTTP mechanics only. This module does not read state or grant permissions.
export const securityHeaders = Object.freeze({
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Content-Security-Policy': [
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "connect-src 'self'",
    "img-src 'self'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
    "form-action 'none'",
  ].join('; '),
});

export function failure(status, message) {
  return Object.assign(new Error(message), { status });
}

export function matchesSecret(candidate, expected) {
  const valid = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
  return valid(candidate) && valid(expected)
    && timingSafeEqual(Buffer.from(candidate), Buffer.from(expected));
}

export function fields(value, names) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).some(key => !names.includes(key))) {
    throw failure(400, 'Invalid request fields.');
  }
}

export function boolean(value) {
  if (typeof value !== 'boolean') throw failure(400, 'An explicit boolean is required.');
  return value;
}

export function identifier(value) {
  if (typeof value !== 'string' || !/^[a-f0-9-]{36}$/.test(value)) {
    throw failure(400, 'Invalid identifier.');
  }
  return value;
}

export function selectedPermission(value) {
  if (Object.hasOwn(value, 'writeMode') && Object.hasOwn(value, 'write')) {
    throw failure(400, 'Ambiguous folder permission.');
  }
  const mode = Object.hasOwn(value, 'writeMode')
    ? validateWriteMode(value.writeMode)
    : (boolean(value.write) ? 'review' : 'read-only');
  if (value.confirmDirect !== undefined) boolean(value.confirmDirect);
  if (mode === 'direct' && value.confirmDirect !== true) {
    throw failure(400, '请明确确认：此目录允许直接创建和修改文件，不再逐次要求本机审批。');
  }
  return rootPermission(mode);
}

export async function bodyJson(request) {
  const contentType = request.headers['content-type']?.split(';')[0].trim().toLowerCase();
  if (contentType !== 'application/json') throw failure(415, 'application/json is required.');
  if (Number(request.headers['content-length']) > MAX_WIRE_BYTES) {
    throw failure(413, 'Request too large.');
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > MAX_WIRE_BYTES) throw failure(413, 'Request too large.');
    chunks.push(chunk);
  }
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
  } catch {
    throw failure(400, 'Invalid JSON.');
  }
}
