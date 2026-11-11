# @profullstack/key-grants

Stop asking people to paste API keys. Your app asks [logicsrc](https://logicsrc.com) for keys **by name**, the person approves on logicsrc, and the key arrives sealed to *their* key vault in your app. When they rotate it in logicsrc, your app gets the new value on its own. When they revoke it, your app deletes it.

No server in the chain can read the key: logicsrc decrypts it only in the person's browser and seals it with [`@profullstack/sealed-secrets`](https://www.npmjs.com/package/@profullstack/sealed-secrets) to the inbox key of their vault in your app. Your app stores the sealed text and opens it only while they have unlocked their vault (unlock-on-use).

```
your app                         logicsrc (app.logicsrc.com)
  start() ── 303 ──────────────▶ /grant?origin=<you>&nonce=<n>
  GET /.well-known/logicsrc-grant/<n> ◀── fetched over TLS: proves it is you
                                  person approves, browser seals the value
  POST /api/v1/logicsrc/webhook ◀── grant.delivered / .updated / .revoked (signed)
```

## Install

```sh
npm i @profullstack/key-grants
```

You need a per-user vault built with `@profullstack/sealed-secrets` (its seal record has `inbox_public_key`).

## Use

```js
import { createKeyGrants, sqlStore } from '@profullstack/key-grants';

export const keyGrants = createKeyGrants({
  appName: 'MeshHook',
  origin: process.env.ORIGIN,                       // https://meshhook.com
  store: sqlStore({ query: (sql, params) => db.query(sql, params) }, { placeholder: '$' }),
  // The person's vault inbox, or null when they have no vault yet.
  recipientFor: async (userId) => {
    const vault = await getVault(userId);
    return vault && { app: 'meshhook', scope: 'workflow_secrets', user_id: userId, inbox_public_key: vault.seal.inbox_public_key };
  },
  // `sealed` is the same `sealed:v2:` text your own secrets page stores.
  onKey: ({ userId, scope, keyName, sealed }) => saveSecret(userId, scope, keyName, sealed),
  onRevoke: ({ userId, scope, keyName }) => deleteSecret(userId, scope, keyName),
});
```

`app` and `scope` must be the ones your vault's sealer was created with (`createSealer({ app, scope })`), and `user_id` the id you seal with: they are bound into the seal.

Three routes (any framework that speaks `Request`/`Response`):

```js
// GET /api/v1/logicsrc/grant/start?keys=COINPAY_API_KEY,SMSHUB_API_KEY&next=/settings
export const GET = ({ url, locals }) =>
  keyGrants.startResponse({ userId: locals.user?.id, keys: url.searchParams.get('keys'), next: url.searchParams.get('next'), errorPath: '/settings' });

// GET /.well-known/logicsrc-grant/[nonce]
export const GET = ({ params }) => keyGrants.manifestResponse(params.nonce);

// POST /api/v1/logicsrc/webhook  (no session, no CSRF: it is signed per request)
export const POST = ({ request }) => keyGrants.webhookResponse(request);
```

A button anywhere: `<a href="/api/v1/logicsrc/grant/start?keys=COINPAY_API_KEY&next=/settings">Get from logicsrc</a>`. On return the URL carries `?logicsrc=granted`, or `?logicsrc=<code>` on a refusal (`needs_vault`, `no_keys`, `bad_key`, `too_many`, `signed_out`).

Express or anything else: call `start()`, `manifest()` and `webhook(headers, rawBody)` directly; the webhook needs the **raw** body.

### Storage

`sqlStore(client, { placeholder: '?' | '$', prefix: 'logicsrc_' })` creates two tables on first use (`logicsrc_grant_requests`, `logicsrc_grants`) and works with any client exposing `query(sql, params) => rows`. `memoryStore()` is for tests. Or implement the five methods of `KeyGrantStore` yourself (see `index.d.ts`), e.g. over Supabase.

The tables hold nonces, per-request webhook secrets and grant ids. Never a key.

## Security notes

- **Apply only the granted key.** Your server cannot see inside a delivery. When you open it (after the person unlocks), take only the field for the key that grant was for; never merge every field of the opened patch. `openGrantedValue(sealer, dek, seal, userId, sealed, keyName)` does exactly that.

- logicsrc shows the person the origin it fetched your manifest from, not a name you claimed, and refuses webhooks off your origin.
- Each request has its own webhook secret; deliveries are Standard Webhooks signed and checked within 5 minutes.
- A grant arrives for a key your request named, or it is refused.
- logicsrc never grants signing keys (wallet keys, seeds, SSH keys) to apps.
- Revoking cannot make your app forget a key it already opened; rotate it in logicsrc too.

## License

MIT
