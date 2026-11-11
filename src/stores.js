/**
 * Where an app keeps grant requests and grants. Two tables, no values: a
 * request holds a nonce and the per-request webhook secret; a grant maps a
 * logicsrc grant id to the request and key name. Bring your own by
 * implementing these five methods.
 *
 * @typedef {object} KeyGrantStore
 * @property {(row: object) => Promise<void>} saveRequest
 * @property {(nonce: string) => Promise<object|null>} getRequest
 * @property {(userId: string, limit: number) => Promise<object[]>} requestsForUser   newest first
 * @property {(grantId: string) => Promise<object|null>} getGrant
 * @property {(row: object) => Promise<void>} saveGrant                               upsert by grant_id
 */

/** In-memory store, for tests and single-process demos. */
export function memoryStore() {
  const requests = new Map();
  const grants = new Map();
  return {
    requests,
    grants,
    async saveRequest(row) {
      requests.set(row.nonce, { ...row });
    },
    async getRequest(nonce) {
      return requests.get(nonce) ?? null;
    },
    async requestsForUser(userId, limit) {
      return [...requests.values()].filter((r) => r.user_id === userId).sort((a, b) => b.created_at - a.created_at).slice(0, limit);
    },
    async getGrant(id) {
      return grants.get(id) ?? null;
    },
    async saveGrant(row) {
      grants.set(row.grant_id, { ...row });
    },
  };
}

/**
 * SQL store over any client with `query(sql, params) => Promise<rows[]>`.
 * Tables are created on first use. `placeholder: '$'` for pg / postgres-style
 * `$1, $2`; `'?'` (default) for libsql, sqlite and @profullstack/libsql-pg.
 *
 * @param {{ query: (sql: string, params: unknown[]) => Promise<object[]> }} client
 * @param {{ placeholder?: '?' | '$', prefix?: string }} [opts]  prefix: table name prefix (default "logicsrc_")
 */
export function sqlStore(client, { placeholder = '?', prefix = 'logicsrc_' } = {}) {
  if (typeof client?.query !== 'function') throw new TypeError('sqlStore needs a client with query(sql, params)');
  if (!/^[a-z_][a-z0-9_]*$/.test(prefix)) throw new TypeError('sqlStore: prefix must be a plain identifier');
  const R = `${prefix}grant_requests`;
  const G = `${prefix}grants`;
  const p = (sql) => {
    if (placeholder !== '$') return sql;
    let i = 0;
    return sql.replace(/\?/g, () => `$${++i}`);
  };
  const q = (sql, params = []) => client.query(p(sql), params);
  let ready = null;
  const ensure = () =>
    (ready ??= (async () => {
      await q(`create table if not exists ${R} (
        nonce text primary key, user_id text not null, scope text, keys text not null,
        webhook_secret text not null, next_path text not null, created_at bigint not null, expires_at bigint not null)`);
      await q(`create index if not exists ${R}_user on ${R} (user_id, created_at)`);
      await q(`create table if not exists ${G} (
        grant_id text primary key, nonce text not null, user_id text not null, scope text,
        key_name text not null, status text not null, updated_at bigint not null)`);
    })().catch((e) => {
      ready = null;
      throw e;
    }));
  const one = async (sql, params) => (await q(sql, params))[0] ?? null;
  return {
    ensure,
    async saveRequest(r) {
      await ensure();
      await q(`insert into ${R} (nonce, user_id, scope, keys, webhook_secret, next_path, created_at, expires_at) values (?, ?, ?, ?, ?, ?, ?, ?)`, [
        r.nonce, r.user_id, r.scope, r.keys, r.webhook_secret, r.next_path, r.created_at, r.expires_at,
      ]);
    },
    async getRequest(nonce) {
      await ensure();
      return one(`select * from ${R} where nonce = ?`, [nonce]);
    },
    async requestsForUser(userId, limit) {
      await ensure();
      return q(`select * from ${R} where user_id = ? order by created_at desc limit ${Math.max(1, Number(limit) | 0)}`, [userId]);
    },
    async getGrant(id) {
      await ensure();
      return one(`select * from ${G} where grant_id = ?`, [id]);
    },
    async saveGrant(g) {
      await ensure();
      await q(
        `insert into ${G} (grant_id, nonce, user_id, scope, key_name, status, updated_at) values (?, ?, ?, ?, ?, ?, ?)
         on conflict (grant_id) do update set status = excluded.status, updated_at = excluded.updated_at`,
        [g.grant_id, g.nonce, g.user_id, g.scope, g.key_name, g.status, g.updated_at],
      );
    },
  };
}
