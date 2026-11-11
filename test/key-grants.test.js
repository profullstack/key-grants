import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { createSealer } from '@profullstack/sealed-secrets';
import { createKeyGrants, memoryStore, openGrantedValue, parseKeyNames, sqlStore, verifyWebhook, KeyGrantError } from '../src/index.js';

const sealer = createSealer({ app: 'demo', scope: 'workflow_secrets' });
const sign = (secret, body, ts = Math.floor(Date.now() / 1000), id = 'msg_1') => ({
  'webhook-id': id,
  'webhook-timestamp': String(ts),
  'webhook-signature': `v1,${createHmac('sha256', Buffer.from(secret)).update(`${id}.${ts}.${body}`).digest('base64')}`,
});

async function setup({ withVault = true } = {}) {
  const made = await sealer.createSeal('correct horse battery staple', 'u1');
  const stored = new Map();
  const store = memoryStore();
  const kg = createKeyGrants({
    appName: 'Demo',
    origin: 'https://demo.example/',
    store,
    recipientFor: async (uid) => (withVault && uid === 'u1' ? { app: 'demo', scope: 'workflow_secrets', user_id: 'u1', inbox_public_key: made.seal.inbox_public_key } : null),
    onKey: async (e) => stored.set(`${e.scope}:${e.keyName}`, e.sealed),
    onRevoke: async (e) => stored.delete(`${e.scope}:${e.keyName}`),
  });
  return { made, stored, store, kg };
}

test('parseKeyNames', () => {
  assert.deepEqual(parseKeyNames('A, B  A'), ['A', 'B']);
  assert.throws(() => parseKeyNames(''), KeyGrantError);
  assert.throws(() => parseKeyNames('bad name!'), /not a valid/);
  assert.throws(() => parseKeyNames(Array.from({ length: 21 }, (_, i) => `K${i}`)), /At most 20/);
});

test('start needs a vault; startResponse turns refusals into a redirect code', async () => {
  const { kg } = await setup({ withVault: false });
  await assert.rejects(kg.start({ userId: 'u1', keys: 'A' }), { code: 'needs_vault' });
  const r = await kg.startResponse({ userId: 'u1', keys: 'A', errorPath: '/secrets' });
  assert.equal(r.status, 303);
  assert.equal(r.headers.get('location'), '/secrets?logicsrc=needs_vault');
});

test('start -> manifest -> signed delivery -> rotation -> revoke, with real sealing', async () => {
  const { made, stored, store, kg } = await setup();
  const url = new URL(await kg.start({ userId: 'u1', keys: 'API_KEY', next: '/settings', scope: 'proj-1' }));
  assert.equal(url.origin + url.pathname, 'https://app.logicsrc.com/grant');
  assert.equal(url.searchParams.get('origin'), 'https://demo.example');
  const nonce = url.searchParams.get('nonce');

  const m = await kg.manifest(nonce);
  assert.equal(m.app_name, 'Demo');
  assert.equal(m.webhook_url, 'https://demo.example/api/v1/logicsrc/webhook');
  assert.equal(m.return_url, 'https://demo.example/settings?logicsrc=granted');
  assert.deepEqual(m.recipient, { format: 'sealed-secrets/inbox-v2', app: 'demo', scope: 'workflow_secrets', user_id: 'u1', inbox_public_key: made.seal.inbox_public_key });
  assert.equal(await kg.manifest('nope'), null);
  assert.equal((await kg.manifestResponse('nope')).status, 404);

  // What logicsrc's consent page produces, then what its webhook sends.
  const seal = async (v) => `sealed:v2:${JSON.stringify(await sealer.sealToInbox(m.recipient.inbox_public_key, { API_KEY: v }, 'u1'))}`;
  const body = JSON.stringify({ type: 'grant.delivered', grant_id: 'g1', key_name: 'API_KEY', recipient_user_id: 'u1', sealed: await seal('first') });
  assert.equal((await kg.webhook(sign('x'.repeat(40), body), body)).status, 401);
  assert.equal((await kg.webhook(sign(m.webhook_secret, body, Math.floor(Date.now() / 1000) - 600), body)).status, 401);
  const ok = await kg.webhookResponse(new Request('https://demo.example/api/v1/logicsrc/webhook', { method: 'POST', headers: sign(m.webhook_secret, body), body }));
  assert.equal(ok.status, 200);
  const open = async () => (await sealer.openInbox(made.dek, made.seal, [JSON.parse(stored.get('proj-1:API_KEY').slice('sealed:v2:'.length))], 'u1')).patch;
  assert.deepEqual(await open(), { API_KEY: 'first' });

  const extra = JSON.stringify({ type: 'grant.delivered', grant_id: 'g2', key_name: 'OTHER', recipient_user_id: 'u1', sealed: await seal('x') });
  assert.equal((await kg.webhook(sign(m.webhook_secret, extra), extra)).status, 400);

  const upd = JSON.stringify({ type: 'grant.updated', grant_id: 'g1', key_name: 'API_KEY', sealed: await seal('rotated') });
  assert.equal((await kg.webhook(sign(m.webhook_secret, upd), upd)).status, 200);
  assert.deepEqual(await open(), { API_KEY: 'rotated' });

  const rev = JSON.stringify({ type: 'grant.revoked', grant_id: 'g1', key_name: 'API_KEY' });
  assert.equal((await kg.webhook(sign(m.webhook_secret, rev), rev)).status, 200);
  assert.equal(stored.has('proj-1:API_KEY'), false);
  assert.equal(store.grants.get('g1').status, 'revoked');
});

test('expired requests have no manifest', async () => {
  let t = 1_000_000;
  const { made } = await setup();
  const kg = createKeyGrants({
    appName: 'D',
    origin: 'https://d.example',
    store: memoryStore(),
    now: () => t,
    recipientFor: async () => ({ app: 'demo', scope: 's', user_id: 'u1', inbox_public_key: made.seal.inbox_public_key }),
    onKey: async () => {},
  });
  const nonce = new URL(await kg.start({ userId: 'u1', keys: 'K' })).searchParams.get('nonce');
  assert.ok(await kg.manifest(nonce));
  t += 31 * 60_000;
  assert.equal(await kg.manifest(nonce), null);
});

test('verifyWebhook: whsec_ secrets, Headers objects and multi-signature lists', () => {
  const raw = 'k'.repeat(32);
  const ts = Math.floor(Date.now() / 1000);
  const sig = `v1,${createHmac('sha256', Buffer.from(raw)).update(`m.${ts}.b`).digest('base64')}`;
  const headers = new Headers({ 'Webhook-Id': 'm', 'Webhook-Timestamp': String(ts), 'Webhook-Signature': `v1,AAAA ${sig}` });
  assert.equal(verifyWebhook(`whsec_${Buffer.from(raw).toString('base64')}`, headers, 'b'), true);
  assert.equal(verifyWebhook(raw, { 'webhook-id': 'm', 'webhook-timestamp': String(ts), 'webhook-signature': sig }, 'b2'), false);
});

test('sqlStore: $n placeholders, prefix, upsert', async () => {
  const calls = [];
  const client = { query: async (sql, params) => (calls.push({ sql, params }), []) };
  const s = sqlStore(client, { placeholder: '$', prefix: 'kg_' });
  await s.saveRequest({ nonce: 'n', user_id: 'u', scope: null, keys: '[]', webhook_secret: 's', next_path: '/', created_at: 1, expires_at: 2 });
  await s.saveGrant({ grant_id: 'g', nonce: 'n', user_id: 'u', scope: null, key_name: 'K', status: 'active', updated_at: 3 });
  assert.match(calls[0].sql, /create table if not exists kg_grant_requests/);
  const ins = calls.find((c) => /insert into kg_grant_requests/.test(c.sql));
  assert.match(ins.sql, /values \(\$1, \$2, \$3, \$4, \$5, \$6, \$7, \$8\)/);
  assert.match(calls.at(-1).sql, /on conflict \(grant_id\) do update/);
  assert.throws(() => sqlStore(client, { prefix: 'bad;drop' }), /plain identifier/);
});

test('openGrantedValue returns only the granted field', async () => {
  const made = await sealer.createSeal('correct horse battery staple', 'u1');
  const entry = await sealer.sealToInbox(made.seal.inbox_public_key, { API_KEY: 'k', EVM_PRIVATE_KEY: 'smuggled' }, 'u1');
  const sealed = `sealed:v2:${JSON.stringify(entry)}`;
  assert.equal(await openGrantedValue(sealer, made.dek, made.seal, 'u1', sealed, 'API_KEY'), 'k');
  assert.equal(await openGrantedValue(sealer, made.dek, made.seal, 'u1', sealed, 'OTHER'), null);
  await assert.rejects(openGrantedValue(sealer, made.dek, made.seal, 'u1', 'plain', 'API_KEY'), { code: 'bad_sealed' });
});
