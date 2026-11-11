/**
 * @profullstack/key-grants — the app side of logicsrc app grants.
 *
 * An app never asks a person to paste an API key. It asks logicsrc for keys by
 * name; the person approves on logicsrc; their browser seals each value to the
 * app's per-user inbox key (@profullstack/sealed-secrets inbox-v2); logicsrc
 * posts the sealed text to the app's webhook, and again after every rotation.
 * The app stores it like any sealed secret: it can store it, never open it
 * without the person's unlock.
 *
 *   start(...)     a request (nonce + per-request webhook secret), then the
 *                  person goes to <logicsrc>/grant?origin=<app>&nonce=<n>
 *   manifest(n)    served at GET /.well-known/logicsrc-grant/<n>; logicsrc
 *                  fetches it over TLS, which is how it knows which app asks
 *   webhook(...)   POST <webhookPath>: grant.delivered / grant.updated /
 *                  grant.revoked, Standard Webhooks signature
 */

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

export const MANIFEST_PATH = '/.well-known/logicsrc-grant/';
export const DEFAULT_WEBHOOK_PATH = '/api/v1/logicsrc/webhook';
export const DEFAULT_LOGICSRC_URL = 'https://app.logicsrc.com';
export const RECIPIENT_FORMAT = 'sealed-secrets/inbox-v2';
export const SEALED_PREFIX = 'sealed:v2:';
const KEY_NAME = /^[A-Za-z_][A-Za-z0-9_.-]{0,127}$/;

export class KeyGrantError extends Error {
  /** @param {string} message @param {string} code @param {number} [status] */
  constructor(message, code, status = 400) {
    super(message);
    this.name = 'KeyGrantError';
    this.code = code;
    this.status = status;
  }
}

/** "A, B A" / ["A","B"] -> ["A","B"]: valid, unique, 1 to 20. */
export function parseKeyNames(input) {
  const list = (Array.isArray(input) ? input : String(input ?? '').split(/[,\s]+/))
    .map((s) => String(s).trim())
    .filter(Boolean);
  const names = [...new Set(list)];
  if (!names.length) throw new KeyGrantError('Name at least one key', 'no_keys');
  if (names.length > 20) throw new KeyGrantError('At most 20 keys per request', 'too_many');
  for (const n of names) if (!KEY_NAME.test(n)) throw new KeyGrantError(`"${n}" is not a valid key name`, 'bad_key');
  return names;
}

const safeNext = (p, fallback) => (typeof p === 'string' && p.startsWith('/') && !p.startsWith('//') ? p : fallback);

function lowerHeaders(headers) {
  if (!headers) return {};
  if (typeof headers.entries === 'function' && typeof headers.get === 'function') {
    return Object.fromEntries([...headers.entries()].map(([k, v]) => [k.toLowerCase(), v]));
  }
  return Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), Array.isArray(v) ? v.join(' ') : v]));
}

/**
 * Standard Webhooks check: "v1,<base64>" (a space-separated list is allowed),
 * HMAC-SHA256 over "<id>.<ts>.<body>", within `tolerance` seconds.
 * A "whsec_" secret is base64 per the spec; anything else is UTF-8.
 */
export function verifyWebhook(secret, headers, body, { now = Date.now(), tolerance = 300 } = {}) {
  const h = lowerHeaders(headers);
  const id = h['webhook-id'];
  const ts = Number(h['webhook-timestamp']);
  if (!id || !ts || Math.abs(Math.floor(now / 1000) - ts) > tolerance) return false;
  const key = secret.startsWith('whsec_') ? Buffer.from(secret.slice(6), 'base64') : Buffer.from(secret, 'utf8');
  const expected = Buffer.from(`v1,${createHmac('sha256', key).update(`${id}.${ts}.${body}`).digest('base64')}`);
  return String(h['webhook-signature'] ?? '')
    .split(' ')
    .some((s) => {
      const b = Buffer.from(s);
      return b.length === expected.length && timingSafeEqual(b, expected);
    });
}

/**
 * @param {object} o
 * @param {string} o.appName            shown on the logicsrc consent page
 * @param {string} o.origin             this app's public origin, e.g. https://meshhook.com
 * @param {import('./stores.js').KeyGrantStore} o.store
 * @param {(userId: string) => Promise<{app:string, scope:string, user_id:string, inbox_public_key:string} | null>} o.recipientFor
 *        the person's vault inbox (null = no vault yet)
 * @param {(e: {userId:string, scope:string|null, keyName:string, sealed:string, grantId:string, type:string}) => Promise<void>} o.onKey
 *        store the sealed value (the same `sealed:v2:` text the app's own secrets page writes)
 * @param {(e: {userId:string, scope:string|null, keyName:string, grantId:string}) => Promise<void>} [o.onRevoke]
 * @param {string} [o.logicsrcUrl]
 * @param {string} [o.webhookPath]
 * @param {number} [o.ttlMs]            how long a request may wait for approval (default 30 min)
 * @param {(name: string) => string} [o.describeKey]
 * @param {() => number} [o.now]
 */
export function createKeyGrants(o) {
  for (const k of ['appName', 'origin', 'store', 'recipientFor', 'onKey']) if (!o?.[k]) throw new TypeError(`createKeyGrants: ${k} is required`);
  const origin = new URL(o.origin).origin;
  const logicsrcUrl = (o.logicsrcUrl ?? DEFAULT_LOGICSRC_URL).replace(/\/$/, '');
  const webhookPath = o.webhookPath ?? DEFAULT_WEBHOOK_PATH;
  const ttlMs = o.ttlMs ?? 30 * 60_000;
  const now = o.now ?? Date.now;
  const describe = o.describeKey ?? (() => `Used by ${o.appName}; opens only while your vault is unlocked there`);
  const store = o.store;

  /** Create a request; returns the logicsrc URL to send the person to. */
  async function start({ userId, keys, next, scope = null }) {
    if (!userId) throw new KeyGrantError('Sign in first', 'signed_out', 401);
    if (!(await o.recipientFor(String(userId)))) throw new KeyGrantError('Create your key vault first: keys from logicsrc are sealed to it.', 'needs_vault', 409);
    const names = parseKeyNames(keys);
    const nonce = randomBytes(24).toString('base64url');
    const t = now();
    await store.saveRequest({
      nonce,
      user_id: String(userId),
      scope: scope == null ? null : String(scope),
      keys: JSON.stringify(names),
      webhook_secret: randomBytes(32).toString('base64url'),
      next_path: safeNext(next, '/'),
      created_at: t,
      expires_at: t + ttlMs,
    });
    const u = new URL(`${logicsrcUrl}/grant`);
    u.searchParams.set('origin', origin);
    u.searchParams.set('nonce', nonce);
    return u.toString();
  }

  /** The manifest for GET /.well-known/logicsrc-grant/<nonce>, or null (unknown, expired, no vault). */
  async function manifest(nonce) {
    const r = await store.getRequest(String(nonce ?? ''));
    if (!r || Number(r.expires_at) <= now()) return null;
    const recipient = await o.recipientFor(r.user_id);
    if (!recipient) return null;
    const ret = new URL(r.next_path, origin);
    ret.searchParams.set('logicsrc', 'granted');
    return {
      v: 1,
      app_name: o.appName,
      keys: JSON.parse(r.keys).map((name) => ({ name, description: describe(name) })),
      recipient: { format: RECIPIENT_FORMAT, app: recipient.app, scope: recipient.scope, user_id: recipient.user_id, inbox_public_key: recipient.inbox_public_key },
      webhook_url: `${origin}${webhookPath}`,
      webhook_secret: r.webhook_secret,
      return_url: ret.toString(),
      expires_at: Number(r.expires_at),
    };
  }

  /**
   * Apply one webhook. The request (and its secret) is found by grant id once
   * known; the first delivery is matched by trying the recipient's own
   * requests: whichever secret verifies the signature is the one.
   * @returns {Promise<{status:number, body:object}>}
   */
  async function webhook(headers, rawBody) {
    let event;
    try {
      event = JSON.parse(rawBody);
    } catch {
      return { status: 400, body: { error: 'not JSON' } };
    }
    const grantId = String(event?.grant_id ?? '');
    if (!grantId || typeof event.key_name !== 'string') return { status: 400, body: { error: 'grant_id and key_name required' } };

    const known = await store.getGrant(grantId);
    const candidates = known
      ? [await store.getRequest(known.nonce)].filter(Boolean)
      : await store.requestsForUser(String(event.recipient_user_id ?? ''), 50);
    const req = candidates.find((r) => verifyWebhook(r.webhook_secret, headers, rawBody, { now: now() }));
    if (!req) return { status: 401, body: { error: 'bad signature' } };
    if (!known && !JSON.parse(req.keys).includes(event.key_name)) return { status: 400, body: { error: 'we did not ask for that key' } };
    const keyName = known?.key_name ?? event.key_name;
    const ctx = { userId: req.user_id, scope: req.scope ?? null, keyName, grantId };

    if (event.type === 'grant.revoked') {
      if (known && known.status !== 'revoked') {
        await o.onRevoke?.(ctx);
        await store.saveGrant({ ...known, status: 'revoked', updated_at: now() });
      }
      return { status: 200, body: { ok: true } };
    }
    if (event.type !== 'grant.delivered' && event.type !== 'grant.updated') return { status: 200, body: { ignored: String(event.type) } };
    if (typeof event.sealed !== 'string' || !event.sealed.startsWith(SEALED_PREFIX)) return { status: 400, body: { error: 'not a sealed value' } };

    await o.onKey({ ...ctx, sealed: event.sealed, type: event.type });
    await store.saveGrant({ grant_id: grantId, nonce: req.nonce, user_id: req.user_id, scope: req.scope ?? null, key_name: keyName, status: 'active', updated_at: now() });
    return { status: 200, body: { ok: true, key: keyName } };
  }

  // ---- Web Request/Response helpers (SvelteKit, Next route handlers, Hono, Bun.serve) ----

  /** 303 to logicsrc, or to `errorPath?logicsrc=<code>` on a refusal. */
  async function startResponse({ userId, keys, next, scope, errorPath = '/' }) {
    try {
      return new Response(null, { status: 303, headers: { location: await start({ userId, keys, next, scope }) } });
    } catch (e) {
      if (!(e instanceof KeyGrantError)) throw e;
      const u = new URL(safeNext(errorPath, '/'), origin);
      u.searchParams.set('logicsrc', e.code);
      return new Response(null, { status: 303, headers: { location: `${u.pathname}${u.search}` } });
    }
  }

  async function manifestResponse(nonce) {
    const m = await manifest(nonce);
    return Response.json(m ?? { error: 'unknown or expired request' }, { status: m ? 200 : 404, headers: { 'cache-control': 'no-store' } });
  }

  async function webhookResponse(request) {
    const raw = await request.text();
    const r = await webhook(request.headers, raw);
    return Response.json(r.body, { status: r.status });
  }

  return { start, manifest, webhook, startResponse, manifestResponse, webhookResponse, origin, logicsrcUrl, webhookPath };
}

export { sqlStore, memoryStore } from './stores.js';
